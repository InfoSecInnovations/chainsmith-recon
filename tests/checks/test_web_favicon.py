"""Tests for FaviconCheck and HTTP2DetectionCheck."""

from unittest.mock import AsyncMock, patch

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
        import hashlib

        # Create a body whose MD5 matches a known hash
        # We'll inject a test hash into the lookup
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
        assert (
            result.outputs["favicon_info"]["identified"]["TestFramework"]
            == "Test framework detected"
        )

    @pytest.mark.asyncio
    async def test_no_favicon(self, service):
        """No favicon returns info observation."""
        client = mock_client_multi(default=resp(404))
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        assert any("No favicon" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_unknown_favicon_hash(self, service):
        """Unknown favicon hash is recorded but no framework observation."""
        client = mock_client_multi(
            response_map={
                ("GET", "favicon.ico"): resp(200, body="unknown-favicon-bytes"),
            },
            default=resp(200, body="<html></html>"),
        )
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        # Should have unknown hash recorded, no framework match observation
        assert "unknown" in result.outputs["favicon_info"]["identified"]
        assert not any("Framework identified" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_favicon_from_html_link(self, service):
        """Favicon URL extracted from HTML <link> tag."""
        import hashlib

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
        assert any("CustomApp" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_error_handling(self, service):
        """Check handles HTTP errors gracefully."""
        client = mock_client_multi(default=resp(500, error="Server Error"))
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success  # Graceful degradation


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
        client = mock_client_multi(
            default=resp(200, headers={}),
        )
        with (
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch.object(HTTP2DetectionCheck, "_check_alpn", return_value="h2"),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        assert result.outputs["http_protocols"]["h2"] is True
        assert any("HTTP/2 supported" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_h3_via_alt_svc(self, https_service):
        """HTTP/3 detected via Alt-Svc header."""
        client = mock_client_multi(
            default=resp(200, headers={"alt-svc": 'h3=":443"; ma=86400'}),
        )
        with (
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch.object(HTTP2DetectionCheck, "_check_alpn", return_value=None),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        assert result.outputs["http_protocols"]["h3"] is True
        assert any("HTTP/3" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_h2_and_h3(self, https_service):
        """Both HTTP/2 and HTTP/3 detected."""
        client = mock_client_multi(
            default=resp(200, headers={"alt-svc": 'h3=":443"'}),
        )
        with (
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch.object(HTTP2DetectionCheck, "_check_alpn", return_value="h2"),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.outputs["http_protocols"]["h2"] is True
        assert result.outputs["http_protocols"]["h3"] is True
        assert any("HTTP/2 and HTTP/3" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_http1_only(self, service):
        """HTTP/1.1 only when no h2/h3 detected."""
        client = mock_client_multi(default=resp(200, headers={}))
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client):
            check = HTTP2DetectionCheck()
            result = await check.check_service(service, {})

        assert result.outputs["http_protocols"]["h2"] is False
        assert result.outputs["http_protocols"]["h3"] is False
        assert any("HTTP/1.1 only" in f.title for f in result.observations)

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

    @pytest.mark.asyncio
    async def test_alpn_failure_graceful(self, https_service):
        """ALPN check failure doesn't crash the check."""
        client = mock_client_multi(default=resp(200, headers={}))
        with (
            patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client),
            patch.object(HTTP2DetectionCheck, "_check_alpn", side_effect=Exception("TLS error")),
        ):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success
