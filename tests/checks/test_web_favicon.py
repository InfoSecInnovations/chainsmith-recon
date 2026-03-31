"""
Tests for Phase 6d additional protocol & analysis checks.

Covers:
- FaviconCheck (check 15)
- HTTP2DetectionCheck (check 16)
- HSTSPreloadCheck (check 17)
- SRICheck (check 18)
- MassAssignmentCheck (check 19)

All HTTP calls are mocked to avoid actual network traffic.
"""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from app.checks.base import Service
from app.checks.web.favicon import FaviconCheck, FAVICON_HASHES
from app.checks.web.http2_detection import HTTP2DetectionCheck
from app.checks.web.hsts_preload import HSTSPreloadCheck
from app.checks.web.sri_check import SRICheck
from app.checks.web.mass_assignment import MassAssignmentCheck
from app.lib.http import HttpResponse


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http")


@pytest.fixture
def https_service():
    return Service(url="https://target.com:443", host="target.com", port=443, scheme="https", service_type="http")


def resp(status_code=200, body="", headers=None, error=None, url="http://target.com:80"):
    return HttpResponse(url=url, status_code=status_code, headers=headers or {}, body=body, elapsed_ms=50.0, error=error)


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

        with patch.dict("app.checks.web.favicon.FAVICON_HASHES",
                        {test_hash: ("TestFramework", "Test framework detected")}):
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
        framework_findings = [f for f in result.findings if "TestFramework" in f.title]
        assert len(framework_findings) == 1
        assert framework_findings[0].severity == "info"
        assert result.outputs["favicon_info"]["identified"]["TestFramework"] == "Test framework detected"

    @pytest.mark.asyncio
    async def test_no_favicon(self, service):
        """No favicon returns info finding."""
        client = mock_client_multi(default=resp(404))
        with patch("app.checks.web.favicon.AsyncHttpClient", return_value=client):
            check = FaviconCheck()
            result = await check.check_service(service, {})

        assert result.success
        assert any("No favicon" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_unknown_favicon_hash(self, service):
        """Unknown favicon hash is recorded but no framework finding."""
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
        # Should have unknown hash recorded, no framework match finding
        assert "unknown" in result.outputs["favicon_info"]["identified"]
        assert not any("Framework identified" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_favicon_from_html_link(self, service):
        """Favicon URL extracted from HTML <link> tag."""
        import hashlib
        test_body = "custom-icon-content"
        test_hash = hashlib.md5(test_body.encode("latin-1")).hexdigest()

        html_page = '<html><head><link rel="icon" href="/static/my-icon.png"></head></html>'

        with patch.dict("app.checks.web.favicon.FAVICON_HASHES",
                        {test_hash: ("CustomApp", "Custom app")}):
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
        assert any("CustomApp" in f.title for f in result.findings)

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
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client), \
             patch.object(HTTP2DetectionCheck, "_check_alpn", return_value="h2"):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        assert result.outputs["http_protocols"]["h2"] is True
        assert any("HTTP/2 supported" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_h3_via_alt_svc(self, https_service):
        """HTTP/3 detected via Alt-Svc header."""
        client = mock_client_multi(
            default=resp(200, headers={"alt-svc": 'h3=":443"; ma=86400'}),
        )
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client), \
             patch.object(HTTP2DetectionCheck, "_check_alpn", return_value=None):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        assert result.outputs["http_protocols"]["h3"] is True
        assert any("HTTP/3" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_h2_and_h3(self, https_service):
        """Both HTTP/2 and HTTP/3 detected."""
        client = mock_client_multi(
            default=resp(200, headers={"alt-svc": 'h3=":443"'}),
        )
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client), \
             patch.object(HTTP2DetectionCheck, "_check_alpn", return_value="h2"):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.outputs["http_protocols"]["h2"] is True
        assert result.outputs["http_protocols"]["h3"] is True
        assert any("HTTP/2 and HTTP/3" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_http1_only(self, service):
        """HTTP/1.1 only when no h2/h3 detected."""
        client = mock_client_multi(default=resp(200, headers={}))
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client):
            check = HTTP2DetectionCheck()
            result = await check.check_service(service, {})

        assert result.outputs["http_protocols"]["h2"] is False
        assert result.outputs["http_protocols"]["h3"] is False
        assert any("HTTP/1.1 only" in f.title for f in result.findings)

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
        with patch("app.checks.web.http2_detection.AsyncHttpClient", return_value=client), \
             patch.object(HTTP2DetectionCheck, "_check_alpn", side_effect=Exception("TLS error")):
            check = HTTP2DetectionCheck()
            result = await check.check_service(https_service, {})

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# HSTSPreloadCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestHSTSPreloadCheck:
    def test_init(self):
        check = HSTSPreloadCheck()
        assert check.name == "hsts_preload"
        assert "hsts_preload_info" in check.produces

    @pytest.mark.asyncio
    async def test_preloaded_domain(self, https_service):
        """Domain found on preload list."""
        api_response = json.dumps({"status": "preloaded", "domain": "target.com"})
        hsts_header = "max-age=31536000; includeSubDomains; preload"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(200, headers={"strict-transport-security": hsts_header}),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        assert result.outputs["hsts_preload_info"]["preloaded"] is True
        assert any("HSTS preloaded" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_not_preloaded_with_hsts(self, https_service):
        """HSTS header present but domain not preloaded."""
        api_response = json.dumps({"status": "unknown", "domain": "target.com"})
        hsts_header = "max-age=31536000; includeSubDomains"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(200, headers={"strict-transport-security": hsts_header}),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert result.outputs["hsts_preload_info"]["preloaded"] is False
        not_preloaded = [f for f in result.findings if "not preloaded" in f.title]
        assert len(not_preloaded) == 1
        assert not_preloaded[0].severity == "low"

    @pytest.mark.asyncio
    async def test_preload_directive_pending(self, https_service):
        """Has preload directive but not yet on the list."""
        api_response = json.dumps({"status": "pending", "domain": "target.com"})
        hsts_header = "max-age=31536000; includeSubDomains; preload"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(200, headers={"strict-transport-security": hsts_header}),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert any("not yet preloaded" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_no_hsts_header_http(self, service):
        """HTTP service with no HSTS — check not applicable."""
        client = mock_client_multi(default=resp(200, headers={}))
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(service, {})

        assert any("No HSTS" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_hsts_from_context(self, https_service):
        """HSTS header read from header_analysis context output."""
        api_response = json.dumps({"status": "preloaded"})
        context = {
            "header_info": {
                "headers": {"strict-transport-security": "max-age=63072000; includeSubDomains; preload"},
            },
        }

        client = mock_client_multi(
            response_map={("GET", "hstspreload.org"): resp(200, body=api_response)},
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, context)

        assert result.outputs["hsts_preload_info"]["preloaded"] is True

    @pytest.mark.asyncio
    async def test_short_max_age_noted(self, https_service):
        """Short max-age is mentioned in not-preloaded finding."""
        api_response = json.dumps({"status": "unknown"})
        hsts_header = "max-age=86400"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(200, headers={"strict-transport-security": hsts_header}),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        not_preloaded = [f for f in result.findings if "not preloaded" in f.title]
        assert len(not_preloaded) == 1
        assert "max-age too short" in not_preloaded[0].description

    @pytest.mark.asyncio
    async def test_api_unreachable(self, https_service):
        """Graceful handling when hstspreload.org API is down."""
        hsts_header = "max-age=31536000; includeSubDomains; preload"
        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(500, error="Server Error"),
                ("GET", "target.com"): resp(200, headers={"strict-transport-security": hsts_header}),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# SRICheck
# ═══════════════════════════════════════════════════════════════════════════════


HTML_WITH_EXTERNAL_NO_SRI = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.css">
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="/static/local.js"></script>
</head>
<body>Hello</body>
</html>"""

HTML_WITH_SRI = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.css"
          integrity="sha384-abc123" crossorigin="anonymous">
    <script src="https://cdn.example.com/app.js"
            integrity="sha384-def456" crossorigin="anonymous"></script>
</head>
<body>Hello</body>
</html>"""

HTML_NO_EXTERNAL = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/app.js"></script>
</head>
<body>Hello</body>
</html>"""

HTML_MIXED_SRI = """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.example.com/jquery.js"
            integrity="sha384-xyz789" crossorigin="anonymous"></script>
    <script src="https://cdn.example.com/app.js"></script>
</head>
<body>Hello</body>
</html>"""


class TestSRICheck:
    def test_init(self):
        check = SRICheck()
        assert check.name == "sri_check"
        assert "sri_info" in check.produces

    @pytest.mark.asyncio
    async def test_external_without_sri(self, service):
        """External resources without SRI are flagged."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body=HTML_WITH_EXTERNAL_NO_SRI,
                                                headers={"content-type": "text/html"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.success
        # Should find 3 external resources without SRI (2 scripts + 1 stylesheet)
        assert result.outputs["sri_info"]["without_sri"] == 3
        assert result.outputs["sri_info"]["with_sri"] == 0
        # Summary finding
        summary = [f for f in result.findings if "external resource(s) without SRI" in f.title]
        assert len(summary) == 1

    @pytest.mark.asyncio
    async def test_all_sri_present(self, service):
        """All external resources have SRI — good finding."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body=HTML_WITH_SRI,
                                                headers={"content-type": "text/html"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["with_sri"] == 2
        assert result.outputs["sri_info"]["without_sri"] == 0
        assert any("All external resources use SRI" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_no_external_resources(self, service):
        """No external resources — info finding."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body=HTML_NO_EXTERNAL,
                                                headers={"content-type": "text/html"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["total_external"] == 0
        assert any("No external resources" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_mixed_sri(self, service):
        """Mix of SRI and non-SRI external resources."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body=HTML_MIXED_SRI,
                                                headers={"content-type": "text/html"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["with_sri"] == 1
        assert result.outputs["sri_info"]["without_sri"] == 1

    @pytest.mark.asyncio
    async def test_severity_scales_with_count(self, service):
        """Medium severity when 3+ external resources lack SRI."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body=HTML_WITH_EXTERNAL_NO_SRI,
                                                headers={"content-type": "text/html"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        summary = [f for f in result.findings if "external resource(s) without SRI" in f.title]
        assert summary[0].severity == "medium"  # 3 resources = medium

    @pytest.mark.asyncio
    async def test_protocol_relative_url(self, service):
        """Protocol-relative URLs (//cdn.example.com) are treated as external."""
        html = '<html><head><script src="//cdn.example.com/lib.js"></script></head></html>'
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body=html, headers={"content-type": "text/html"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["without_sri"] == 1

    @pytest.mark.asyncio
    async def test_non_html_response_skipped(self, service):
        """Non-HTML responses are not analyzed."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(200, body='{"api": true}',
                                                headers={"content-type": "application/json"}),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["total_external"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# MassAssignmentCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestMassAssignmentCheck:
    def test_init(self):
        check = MassAssignmentCheck()
        assert check.name == "mass_assignment"
        assert "mass_assignment_info" in check.produces

    @pytest.mark.asyncio
    async def test_privilege_field_reflected(self, service):
        """Privilege field reflected in response = critical."""
        response_body = json.dumps({"name": "test", "email": "test@example.com", "is_admin": True})
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("is_admin" in f.title for f in critical)
        assert result.outputs["mass_assignment_info"]["tested"] > 0

    @pytest.mark.asyncio
    async def test_billing_field_reflected(self, service):
        """Billing field reflected in response = high severity."""
        # Use OpenAPI spec with privilege fields already in schema so they're skipped,
        # allowing billing fields (balance, credits, etc.) to be tested
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/billing": {
                        "put": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["name"],
                                            "properties": {
                                                "name": {"type": "string"},
                                                # These are in schema, so won't be injected
                                                "is_admin": {"type": "boolean"},
                                                "admin": {"type": "boolean"},
                                                "role": {"type": "string"},
                                                "permissions": {"type": "array"},
                                                "is_superuser": {"type": "boolean"},
                                                "is_staff": {"type": "boolean"},
                                                "is_verified": {"type": "boolean"},
                                                "is_active": {"type": "boolean"},
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
        response_body = json.dumps({"name": "test", "balance": 999999})
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, context)

        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) >= 1

    @pytest.mark.asyncio
    async def test_extra_fields_accepted_not_reflected(self, service):
        """Fields accepted (200) but not reflected = medium blind assignment."""
        response_body = json.dumps({"name": "test", "email": "test@example.com"})
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        blind = [f for f in result.findings if "blind mass assignment" in f.description]
        # At least some fields should be classified as blind (accepted but not reflected)
        assert len(blind) >= 1

    @pytest.mark.asyncio
    async def test_all_fields_rejected(self, service):
        """All extra fields rejected (422) = not vulnerable."""
        error_body = json.dumps({"detail": "Unexpected field"})
        client = mock_client_multi(
            default=resp(422, body=error_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        not_vuln = [f for f in result.findings if "not detected" in f.title]
        assert len(not_vuln) >= 1

    @pytest.mark.asyncio
    async def test_openapi_endpoints_used(self, service):
        """Endpoints from OpenAPI spec are used for testing."""
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/users": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["name"],
                                            "properties": {
                                                "name": {"type": "string"},
                                                "email": {"type": "string"},
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
        response_body = json.dumps({"name": "test", "is_admin": True})
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, context)

        # Should use /api/users from OpenAPI
        api_findings = [f for f in result.findings if "/api/users" in (f.evidence or "")]
        assert len(api_findings) >= 1

    @pytest.mark.asyncio
    async def test_schema_fields_excluded_from_injection(self, service):
        """Fields already in the schema are not injected."""
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/profile": {
                        "put": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "role": {"type": "string"},  # Already in schema
                                                "name": {"type": "string"},
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
        response_body = json.dumps({"name": "test"})
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, context)

        # "role" should NOT be tested since it's a known schema field
        role_findings = [f for f in result.findings if "'role' accepted and reflected" in f.title]
        assert len(role_findings) == 0

    @pytest.mark.asyncio
    async def test_validation_error_reveals_schema(self, service):
        """Validation error that reveals accepted fields = low finding."""
        error_body = json.dumps({
            "detail": [
                {"loc": ["body", "is_admin"], "msg": "extra fields not allowed",
                 "type": "value_error.extra", "ctx": {"expected": ["name", "email"]}}
            ]
        })
        client = mock_client_multi(
            default=resp(422, body=error_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        schema_leak = [f for f in result.findings if "schema" in f.title.lower()]
        assert len(schema_leak) >= 1

    @pytest.mark.asyncio
    async def test_no_api_endpoints(self, service):
        """No testable endpoints found = info finding."""
        # Override _gather_endpoints to return empty
        client = mock_client_multi(default=resp(404, error="Not Found"))
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client), \
             patch.object(MassAssignmentCheck, "_gather_endpoints", return_value=[]):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert any("No testable API endpoints" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_nested_field_reflection(self, service):
        """Field reflected in nested response object is still detected."""
        response_body = json.dumps({
            "data": {"user": {"name": "test", "is_admin": True}},
            "status": "ok",
        })
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        critical = [f for f in result.findings if f.severity == "critical" and "is_admin" in f.title]
        assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_error_handling(self, service):
        """Check handles HTTP errors gracefully."""
        client = mock_client_multi(default=resp(500, error="Server Error"))
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
