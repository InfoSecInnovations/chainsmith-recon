"""Tests for web_http2_detection."""

import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_http2_detection import HTTP2DetectionCheck
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


def _mock_alpn_socket(selected_protocol):
    """Create mock SSL context and socket that return the given ALPN protocol.

    Patches at the ssl.SSLContext / socket.create_connection level instead of
    patching the private _check_alpn method directly.
    """
    mock_tls_sock = MagicMock()
    mock_tls_sock.selected_alpn_protocol.return_value = selected_protocol
    mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
    mock_tls_sock.__exit__ = MagicMock(return_value=False)

    mock_ctx = MagicMock(spec=ssl.SSLContext)
    mock_ctx.wrap_socket.return_value = mock_tls_sock

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
    mock_raw_sock.__exit__ = MagicMock(return_value=False)

    return mock_ctx, mock_raw_sock


class TestHTTP2DetectionCheck:
    def test_init(self):
        check = HTTP2DetectionCheck()
        assert check.name == "web_http2_detection"
        assert "http_protocols" in check.produces

    @pytest.mark.asyncio
    async def test_h2_via_alpn(self, https_service):
        """HTTP/2 detected via TLS ALPN negotiation."""
        mock_ctx, mock_raw_sock = _mock_alpn_socket("h2")

        client = mock_client_multi(
            default=resp(200, headers={}),
        )
        with (
            patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client),
            patch("app.checks.web.web_http2_detection.check.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.web_http2_detection.check.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, https_service)

        assert result.success
        assert result.outputs["http_protocols"]["h2"] is True
        h2_obs = [f for f in result.observations if "HTTP/2 supported" in f.title]
        assert len(h2_obs) == 1
        assert h2_obs[0].severity == "info"
        assert "h2" in h2_obs[0].evidence.lower()

    @pytest.mark.asyncio
    async def test_h3_via_alt_svc(self, https_service):
        """HTTP/3 detected via Alt-Svc header."""
        mock_ctx, mock_raw_sock = _mock_alpn_socket(None)

        client = mock_client_multi(
            default=resp(200, headers={"alt-svc": 'h3=":443"; ma=86400'}),
        )
        with (
            patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client),
            patch("app.checks.web.web_http2_detection.check.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.web_http2_detection.check.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, https_service)

        assert result.success
        assert result.outputs["http_protocols"]["h3"] is True
        assert result.outputs["http_protocols"]["h2"] is False
        h3_obs = [f for f in result.observations if "HTTP/3" in f.title]
        assert len(h3_obs) == 1
        assert h3_obs[0].severity == "info"
        assert "Alt-Svc" in h3_obs[0].evidence

    @pytest.mark.asyncio
    async def test_h2_and_h3(self, https_service):
        """Both HTTP/2 and HTTP/3 detected."""
        mock_ctx, mock_raw_sock = _mock_alpn_socket("h2")

        client = mock_client_multi(
            default=resp(200, headers={"alt-svc": 'h3=":443"'}),
        )
        with (
            patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client),
            patch("app.checks.web.web_http2_detection.check.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.web_http2_detection.check.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, https_service)

        assert result.outputs["http_protocols"]["h2"] is True
        assert result.outputs["http_protocols"]["h3"] is True
        combined_obs = [f for f in result.observations if "HTTP/2 and HTTP/3" in f.title]
        assert len(combined_obs) == 1
        assert combined_obs[0].severity == "info"

    @pytest.mark.asyncio
    async def test_http1_only(self, service):
        """HTTP/1.1 only when no h2/h3 detected (HTTP service, no ALPN check)."""
        client = mock_client_multi(default=resp(200, headers={}))
        with patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["http_protocols"]["h2"] is False
        assert result.outputs["http_protocols"]["h3"] is False
        h1_obs = [f for f in result.observations if "HTTP/1.1 only" in f.title]
        assert len(h1_obs) == 1
        assert h1_obs[0].severity == "info"

    @pytest.mark.asyncio
    async def test_h2c_upgrade(self, service):
        """HTTP/2 cleartext detected via Upgrade header."""
        client = mock_client_multi(
            default=resp(200, headers={"upgrade": "h2c"}),
        )
        with patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["http_protocols"]["h2"] is True
        assert "h2c" in result.outputs["http_protocols"]["protocols"]
        h2_obs = [f for f in result.observations if "HTTP/2 supported" in f.title]
        assert len(h2_obs) == 1

    @pytest.mark.asyncio
    async def test_no_h2_or_h3_for_https(self, https_service):
        """HTTPS service with no ALPN h2 and no Alt-Svc reports HTTP/1.1 only."""
        mock_ctx, mock_raw_sock = _mock_alpn_socket(None)

        client = mock_client_multi(default=resp(200, headers={}))
        with (
            patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client),
            patch("app.checks.web.web_http2_detection.check.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.web_http2_detection.check.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, https_service)

        assert result.outputs["http_protocols"]["h2"] is False
        assert result.outputs["http_protocols"]["h3"] is False
        h1_obs = [f for f in result.observations if "HTTP/1.1 only" in f.title]
        assert len(h1_obs) == 1

    @pytest.mark.asyncio
    async def test_alpn_failure_graceful(self, https_service):
        """ALPN check failure (TLS error) doesn't crash the check."""
        client = mock_client_multi(default=resp(200, headers={}))
        with (
            patch("app.checks.web.web_http2_detection.check.AsyncHttpClient", return_value=client),
            patch(
                "app.checks.web.web_http2_detection.check.socket.create_connection",
                side_effect=ssl.SSLError("TLS handshake failed"),
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await probe_and_grade(check, https_service)

        assert result.success
        # Should fall back to HTTP/1.1 only
        assert result.outputs["http_protocols"]["h2"] is False
