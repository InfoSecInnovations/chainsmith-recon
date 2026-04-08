"""Tests for FaviconCheck and HTTP2DetectionCheck."""

import hashlib
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.favicon import FaviconCheck
from app.checks.web.http2_detection import HTTP2DetectionCheck
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


# ═══════════════════════════════════════════════════════════════════════════════
# FaviconCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestFaviconCheck:
    def test_init(self):
        check = FaviconCheck()
        assert check.name == "favicon"
        assert "favicon_info" in check.produces

    @pytest.mark.asyncio
    async def test_known_favicon_detected(self, service):
        """Known favicon hash is matched to framework."""
        # Create a body whose MD5 matches a known hash
        test_body = "fake-favicon-content-for-jenkins"
        test_hash = hashlib.md5(test_body.encode("latin-1")).hexdigest()

        with patch.dict(
            "app.checks.web.favicon.FAVICON_HASHES",
            {test_hash: ("TestFramework", "Test framework detected")},
        ):
            client = mock_client_multi(
                response_map={
                    ("GET", "favicon.ico"): resp(200, body=test_body),
                },
                default=resp(200, body="<html><body>Hello</body></html>"),
            )
            with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
                check = FaviconCheck()
                result = await check.check_service(service, {})

        assert result.success
        framework_observations = [f for f in result.observations if "TestFramework" in f.title]
        assert len(framework_observations) == 1
        assert framework_observations[0].severity == "info"
        assert "Framework identified via favicon" in framework_observations[0].title
        assert test_hash in framework_observations[0].evidence
        assert (
            result.outputs["favicon_info"]["identified"]["TestFramework"]
            == "Test framework detected"
        )

    @pytest.mark.asyncio
    async def test_no_favicon(self, service):
        """No favicon returns info observation with specific title."""
        client = mock_client_multi(default=resp(404))
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        no_fav = [f for f in result.observations if "No favicon" in f.title]
        assert len(no_fav) == 1
        assert no_fav[0].severity == "info"
        assert "target.com" in no_fav[0].title
        assert result.outputs["favicon_info"]["identified"] == {}

    @pytest.mark.asyncio
    async def test_unknown_favicon_hash(self, service):
        """Unknown favicon hash is recorded but no framework observation."""
        unknown_body = "unknown-favicon-bytes-xyz123"
        expected_hash = hashlib.md5(unknown_body.encode("latin-1")).hexdigest()

        client = mock_client_multi(
            response_map={
                ("GET", "favicon.ico"): resp(200, body=unknown_body),
            },
            default=resp(200, body="<html></html>"),
        )
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        # Should have unknown hash recorded, no framework match observation
        assert result.outputs["favicon_info"]["identified"]["unknown"] == expected_hash
        assert not any("Framework identified" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_favicon_from_html_link(self, service):
        """Favicon URL extracted from HTML <link> tag."""
        test_body = "custom-icon-content"
        test_hash = hashlib.md5(test_body.encode("latin-1")).hexdigest()

        html_page = '<html><head><link rel="icon" href="/static/my-icon.png"></head></html>'

        with patch.dict(
            "app.checks.web.favicon.FAVICON_HASHES", {test_hash: ("CustomApp", "Custom app")}
        ):
            # Order matters: more specific patterns first
            client = mock_client_multi(
                response_map={
                    ("GET", "my-icon.png"): resp(200, body=test_body),
                    ("GET", "favicon.ico"): resp(404),
                },
                default=resp(200, body=html_page),
            )
            with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
                check = FaviconCheck()
                result = await check.check_service(service, {})

        assert result.success
        custom_obs = [f for f in result.observations if "CustomApp" in f.title]
        assert len(custom_obs) == 1
        assert custom_obs[0].severity == "info"
        assert "my-icon.png" in custom_obs[0].evidence
        assert "CustomApp" in result.outputs["favicon_info"]["identified"]

    @pytest.mark.asyncio
    async def test_favicon_empty_body_skipped(self, service):
        """Favicon response with empty body is skipped."""
        client = mock_client_multi(
            response_map={
                ("GET", "favicon.ico"): resp(200, body=""),
            },
            default=resp(200, body="<html></html>"),
        )
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        # No framework identified, should get "No favicon" observation
        assert any("No favicon" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_error_handling_server_error(self, service):
        """Check handles HTTP 500 errors gracefully, reports no favicon."""
        client = mock_client_multi(default=resp(500, error="Server Error"))
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        # With errors on all requests, should get "No favicon" observation
        no_fav = [f for f in result.observations if "No favicon" in f.title]
        assert len(no_fav) == 1
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_exception_in_client(self, service):
        """Unhandled exception in HTTP client is caught and recorded."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.get = AsyncMock(side_effect=OSError("Network unreachable"))

        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=mock):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert len(result.errors) >= 1
        assert "Favicon check error" in result.errors[0]


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP2DetectionCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestHTTP2DetectionCheck:
    def test_init(self):
        check = HTTP2DetectionCheck()
        assert check.name == "http2_detection"
        assert "http_protocols" in check.produces

    @pytest.mark.asyncio
    async def test_h2_via_alpn(self, https_service):
        """HTTP/2 detected via TLS ALPN negotiation."""
        mock_ctx, mock_raw_sock = _mock_alpn_socket("h2")

        client = mock_client_multi(
            default=resp(200, headers={}),
        )
        with (
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch("app.checks.web.http2_detection.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.http2_detection.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

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
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch("app.checks.web.http2_detection.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.http2_detection.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

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
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch("app.checks.web.http2_detection.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.http2_detection.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.outputs["http_protocols"]["h2"] is True
        assert result.outputs["http_protocols"]["h3"] is True
        combined_obs = [f for f in result.observations if "HTTP/2 and HTTP/3" in f.title]
        assert len(combined_obs) == 1
        assert combined_obs[0].severity == "info"

    @pytest.mark.asyncio
    async def test_http1_only(self, service):
        """HTTP/1.1 only when no h2/h3 detected (HTTP service, no ALPN check)."""
        client = mock_client_multi(default=resp(200, headers={}))
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client):
            check = HTTP2DetectionCheck()
            result = await check.check_service(service, {})

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
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client):
            check = HTTP2DetectionCheck()
            result = await check.check_service(service, {})

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
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch("app.checks.web.http2_detection.ssl.SSLContext", return_value=mock_ctx),
            patch(
                "app.checks.web.http2_detection.socket.create_connection",
                return_value=mock_raw_sock,
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.outputs["http_protocols"]["h2"] is False
        assert result.outputs["http_protocols"]["h3"] is False
        h1_obs = [f for f in result.observations if "HTTP/1.1 only" in f.title]
        assert len(h1_obs) == 1

    @pytest.mark.asyncio
    async def test_alpn_failure_graceful(self, https_service):
        """ALPN check failure (TLS error) doesn't crash the check."""
        client = mock_client_multi(default=resp(200, headers={}))
        with (
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch(
                "app.checks.web.http2_detection.socket.create_connection",
                side_effect=ssl.SSLError("TLS handshake failed"),
            ),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        # Should fall back to HTTP/1.1 only
        assert result.outputs["http_protocols"]["h2"] is False
