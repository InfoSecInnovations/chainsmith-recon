"""Tests for web_redirect_chain."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_redirect_chain import RedirectChainCheck
from app.lib.http import HttpResponse


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
        # The real client stamps the requested URL onto the response, and a
        # migrated check records that URL on the exchange its grader reads.
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return replace(response, url=url)
        return replace(default, url=url)

    async def dispatch_get(url, **kwargs):
        return _lookup("GET", url)

    async def dispatch_post(url, **kwargs):
        return _lookup("POST", url)

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=lambda m, url, **kw: _lookup(m, url))

    return mock


async def probe_and_grade(check, service, context=None):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `check_service()`
    now returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.check_service(service, context or {})
    return await grade_result(check, result, context or {})


class TestRedirectChainCheck:
    def test_init(self):
        check = RedirectChainCheck()
        assert check.name == "web_redirect_chain"
        assert "redirect_info" in check.produces

    @pytest.mark.asyncio
    async def test_no_https_redirect(self, service):
        """HTTP service with no HTTPS redirect is flagged."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200, body="<html>Hello</html>"),
            ),
        ):
            result = await probe_and_grade(check, service)

        no_https = [f for f in result.observations if "no-https-redirect" in (f.id or "")]
        assert len(no_https) == 1
        assert no_https[0].severity == "medium"
        assert "No HTTP to HTTPS redirect" in no_https[0].title
        assert "target.com" in no_https[0].title
        assert "no redirect to HTTPS" in no_https[0].evidence

    @pytest.mark.asyncio
    async def test_https_redirect_present(self, service):
        """HTTP -> HTTPS redirect is correctly detected."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "http://target.com:80"): resp(
                        301, headers={"location": "https://target.com/"}
                    ),
                },
                default=resp(200, body="<html>Welcome</html>"),
            ),
        ):
            result = await probe_and_grade(check, service)

        ok = [f for f in result.observations if "https-redirect-ok" in (f.id or "")]
        assert len(ok) == 1
        assert ok[0].severity == "info"
        assert "HTTP to HTTPS redirect present" in ok[0].title
        assert "301" in ok[0].evidence
        assert result.outputs["redirect_info"]["https_redirect"] is True

    @pytest.mark.asyncio
    async def test_skip_https_service(self, https_service):
        """HTTPS service skips the HTTP->HTTPS check."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200, body="<html>Secure</html>"),
            ),
        ):
            result = await probe_and_grade(check, https_service)

        no_https = [f for f in result.observations if "no-https-redirect" in (f.id or "")]
        assert len(no_https) == 0
        https_ok = [f for f in result.observations if "https-redirect-ok" in (f.id or "")]
        assert len(https_ok) == 0

    @pytest.mark.asyncio
    async def test_long_chain_detected(self, service):
        """Chain with >3 hops is flagged as low severity."""
        check = RedirectChainCheck()
        call_count = 0

        async def redirect_chain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 4:
                return replace(
                    resp(302, headers={"location": f"http://target.com:80/step{call_count}"}),
                    url=url,
                )
            return replace(resp(200, body="<html>Final destination</html>"), url=url)

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=redirect_chain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.web_redirect_chain.check.AsyncHttpClient", return_value=mock):
            result = await probe_and_grade(check, service)

        long_chain = [f for f in result.observations if "long-chain" in (f.id or "")]
        assert len(long_chain) == 1
        assert long_chain[0].severity == "low"
        assert "hops" in long_chain[0].title
        assert "Chain:" in long_chain[0].evidence
        assert result.outputs["redirect_info"]["chain_length"] > 3

    @pytest.mark.asyncio
    async def test_short_chain_not_flagged(self, service):
        """Chain with <=3 hops is not flagged as long."""
        check = RedirectChainCheck()
        call_count = 0

        async def short_chain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            # The root redirects once; everything else is a destination. Keyed on
            # the URL rather than the call count, because the probe no longer
            # fetches the root twice.
            if url == "http://target.com:80":
                return replace(
                    resp(302, headers={"location": "http://target.com:80/final"}), url=url
                )
            return replace(resp(200, body="<html>Final</html>"), url=url)

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=short_chain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.web_redirect_chain.check.AsyncHttpClient", return_value=mock):
            result = await probe_and_grade(check, service)

        long_chain = [f for f in result.observations if "long-chain" in (f.id or "")]
        assert len(long_chain) == 0

    @pytest.mark.asyncio
    async def test_open_redirect_detected(self, service):
        """Open redirect via URL parameter is flagged as medium severity."""
        check = RedirectChainCheck()

        # Mock: the /redirect endpoint 302s to whatever the url param says,
        # while other paths return normal pages (not redirects)
        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "redirect?url="): resp(
                        302,
                        headers={"location": "https://evil.example.com"},
                        body="",
                    ),
                },
                default=resp(200, body="<html><body>Normal page</body></html>"),
            ),
        ):
            result = await probe_and_grade(check, service)

        open_redir = [f for f in result.observations if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 1
        assert open_redir[0].severity == "medium"
        assert "Open redirect" in open_redir[0].title
        assert "evil.example.com" in open_redir[0].evidence
        assert result.outputs["redirect_info"]["open_redirects"]

    @pytest.mark.asyncio
    async def test_no_open_redirect_when_not_redirecting(self, service):
        """No open redirect when redirect params return normal pages."""
        check = RedirectChainCheck()

        # Redirect param paths return 200 (not a redirect), so no open redirect
        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200, body="<html><body>Page not found</body></html>"),
            ),
        ):
            result = await probe_and_grade(check, service)

        open_redir = [f for f in result.observations if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 0
        assert "open_redirects" not in result.outputs.get("redirect_info", {})

    @pytest.mark.asyncio
    async def test_no_open_redirect_when_404(self, service):
        """No open redirect when redirect params are not accepted (404)."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body="Not Found"),
            ),
        ):
            result = await probe_and_grade(check, service)

        open_redir = [f for f in result.observations if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 0

    @pytest.mark.asyncio
    async def test_redirect_to_safe_location_not_flagged(self, service):
        """Redirect that goes to a safe (non-evil) location is not an open redirect."""
        check = RedirectChainCheck()

        # The endpoint redirects, but to the same domain, not to the attacker URL
        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "redirect?url="): resp(
                        302,
                        headers={"location": "http://target.com:80/home"},
                        body="",
                    ),
                },
                default=resp(200, body="<html><body>Home</body></html>"),
            ),
        ):
            result = await probe_and_grade(check, service)

        open_redir = [f for f in result.observations if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 0

    @pytest.mark.asyncio
    async def test_cross_domain_redirect(self, service):
        """Cross-domain redirect is reported as info severity."""
        check = RedirectChainCheck()
        call_count = 0

        async def cross_domain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            # The root redirects off to a CDN host; everything else answers 200.
            # Keyed on the URL rather than the call count, because the probe no
            # longer fetches the root twice.
            if url == "http://target.com:80":
                return replace(
                    resp(302, headers={"location": "http://cdn.target-assets.com/"}), url=url
                )
            return replace(resp(200, body="<html>CDN content</html>"), url=url)

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=cross_domain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.web_redirect_chain.check.AsyncHttpClient", return_value=mock):
            result = await probe_and_grade(check, service)

        cross = [f for f in result.observations if "cross-domain" in (f.id or "")]
        assert len(cross) == 1
        assert cross[0].severity == "info"
        assert "Cross-domain redirect" in cross[0].title
        assert "cdn.target-assets.com" in cross[0].evidence

    @pytest.mark.asyncio
    async def test_connection_error(self, service):
        """Connection errors are handled gracefully, no observations produced."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.web_redirect_chain.check.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await probe_and_grade(check, service)

        assert result.success
        # Connection errors should not produce redirect/open-redirect observations
        open_redir = [f for f in result.observations if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 0
        long_chain = [f for f in result.observations if "long-chain" in (f.id or "")]
        assert len(long_chain) == 0

    @pytest.mark.asyncio
    async def test_exception_during_check(self, service):
        """Unhandled exception in HTTP client is caught and recorded."""
        check = RedirectChainCheck()

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.get = AsyncMock(side_effect=OSError("Network unreachable"))

        with patch("app.checks.web.web_redirect_chain.check.AsyncHttpClient", return_value=mock):
            result = await probe_and_grade(check, service)

        assert len(result.errors) >= 1
        assert "Redirect chain error" in result.errors[0]
