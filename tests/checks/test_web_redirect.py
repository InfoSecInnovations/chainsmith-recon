"""Tests for RedirectChainCheck — redirect chain analysis."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.redirect_chain import RedirectChainCheck
from app.lib.http import HttpResponse


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
    )


@pytest.fixture
def https_service():
    return Service(
        url="https://target.com:443",
        host="target.com",
        port=443,
        scheme="https",
        service_type="http",
    )


def resp(status_code=200, body="", headers=None, error=None, url="http://target.com:80"):
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client_multi(response_map=None, default=None):
    """Mock client that returns different responses based on URL/method."""
    if default is None:
        default = resp(404)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()

    def _lookup(method, url):
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return response
        return default

    async def dispatch_get(url, **kwargs):
        return _lookup("GET", url)

    async def dispatch_post(url, **kwargs):
        return _lookup("POST", url)

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=lambda m, url, **kw: _lookup(m, url))

    return mock


# ═══════════════════════════════════════════════════════════════════════════════
# RedirectChainCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestRedirectChainCheck:
    def test_init(self):
        check = RedirectChainCheck()
        assert check.name == "redirect_chain"
        assert "redirect_info" in check.produces

    @pytest.mark.asyncio
    async def test_no_https_redirect(self, service):
        """HTTP service with no HTTPS redirect is flagged."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200, body="<html>Hello</html>"),
            ),
        ):
            result = await check.check_service(service, {})

        no_https = [f for f in result.findings if "no-https-redirect" in (f.id or "")]
        assert len(no_https) == 1
        assert no_https[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_https_redirect_present(self, service):
        """HTTP -> HTTPS redirect is correctly detected."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "http://target.com:80"): resp(
                        301, headers={"location": "https://target.com/"}
                    ),
                },
                default=resp(200),
            ),
        ):
            result = await check.check_service(service, {})

        ok = [f for f in result.findings if "https-redirect-ok" in (f.id or "")]
        assert len(ok) == 1
        assert ok[0].severity == "info"

    @pytest.mark.asyncio
    async def test_skip_https_service(self, https_service):
        """HTTPS service skips the HTTP->HTTPS check."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200),
            ),
        ):
            result = await check.check_service(https_service, {})

        no_https = [f for f in result.findings if "no-https-redirect" in (f.id or "")]
        assert len(no_https) == 0

    @pytest.mark.asyncio
    async def test_long_chain_detected(self, service):
        """Chain with >3 hops is flagged."""
        check = RedirectChainCheck()
        call_count = 0

        async def redirect_chain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 4:
                return resp(302, headers={"location": f"http://target.com:80/step{call_count}"})
            return resp(200, body="final")

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=redirect_chain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.redirect_chain.AsyncHttpClient", return_value=mock):
            result = await check.check_service(service, {})

        long_chain = [f for f in result.findings if "long-chain" in (f.id or "")]
        assert len(long_chain) == 1

    @pytest.mark.asyncio
    async def test_open_redirect_detected(self, service):
        """Open redirect via URL parameter is flagged."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "redirect?url="): resp(
                        302, headers={"location": "https://evil.example.com"}
                    ),
                },
                default=resp(200, body="<html>OK</html>"),
            ),
        ):
            result = await check.check_service(service, {})

        open_redir = [f for f in result.findings if "open-redirect" in (f.id or "")]
        assert len(open_redir) >= 1
        assert open_redir[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_cross_domain_redirect(self, service):
        """Cross-domain redirect is reported."""
        check = RedirectChainCheck()
        call_count = 0

        async def cross_domain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call: HTTPS redirect check
                return resp(200, body="<html>OK</html>")
            if call_count == 2:
                # Second call: chain follow - root
                return resp(302, headers={"location": "http://other-domain.com/"})
            return resp(200, body="final")

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=cross_domain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.redirect_chain.AsyncHttpClient", return_value=mock):
            result = await check.check_service(service, {})

        cross = [f for f in result.findings if "cross-domain" in (f.id or "")]
        assert len(cross) == 1

    @pytest.mark.asyncio
    async def test_no_open_redirect(self, service):
        """No open redirect when redirect params are not accepted."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        open_redir = [f for f in result.findings if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 0

    @pytest.mark.asyncio
    async def test_connection_error(self, service):
        """Connection errors are handled gracefully."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
