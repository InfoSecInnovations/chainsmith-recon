"""
Tests for app/checks/web/ suite

Covers:
- HeaderAnalysisCheck
  - Missing security headers detection
  - CORS wildcard detection
  - Server version disclosure
- RobotsTxtCheck
  - Robots.txt parsing
  - Sensitive path detection
  - Sitemap extraction
- PathProbeCheck
  - Common path probing
  - Severity classification
  - Redirect and forbidden detection
- OpenAPICheck
  - OpenAPI/Swagger discovery
  - Endpoint extraction
  - Sensitive endpoint detection
- CorsCheck
  - CORS misconfiguration testing
  - Origin reflection
  - Null origin handling

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.headers import HeaderAnalysisCheck
from app.checks.web.robots import RobotsTxtCheck
from app.checks.web.paths import PathProbeCheck
from app.checks.web.openapi import OpenAPICheck
from app.checks.web.cors import CorsCheck
from app.lib.http import HttpResponse


# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_service():
    """Sample HTTP service."""
    return Service(
        url="http://example.com:8080",
        host="example.com",
        port=8080,
        scheme="http",
        service_type="http",
    )


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client(responses: list[HttpResponse] | HttpResponse):
    """Create a mock AsyncHttpClient context."""
    if not isinstance(responses, list):
        responses = [responses]

    response_iter = iter(responses)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()

    async def get_response(*args, **kwargs):
        try:
            return next(response_iter)
        except StopIteration:
            return responses[-1]  # Repeat last response

    mock.get = AsyncMock(side_effect=get_response)
    mock.options = AsyncMock(side_effect=get_response)
    mock.head = AsyncMock(side_effect=get_response)

    return mock


# ═══════════════════════════════════════════════════════════════════════════════
# HeaderAnalysisCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderAnalysisCheckInit:
    """Tests for HeaderAnalysisCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = HeaderAnalysisCheck()

        assert check.name == "header_analysis"
        assert len(check.conditions) == 1
        assert "http" in check.service_types
        assert "ai" in check.service_types

    def test_security_headers_defined(self):
        """Security headers to check are defined."""
        check = HeaderAnalysisCheck()

        assert "strict-transport-security" in check.SECURITY_HEADERS
        assert "content-security-policy" in check.SECURITY_HEADERS


class TestHeaderAnalysisCheckService:
    """Tests for HeaderAnalysisCheck.check_service."""

    async def test_missing_security_headers(self, sample_service):
        """Missing security headers create finding."""
        check = HeaderAnalysisCheck()
        response = make_response(headers={"content-type": "text/html"})

        with patch("app.checks.web.headers.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        missing_findings = [f for f in result.findings if "Missing security" in f.title]
        assert len(missing_findings) == 1
        assert missing_findings[0].severity == "low"

    async def test_all_security_headers_present(self, sample_service):
        """No missing headers finding when all present."""
        check = HeaderAnalysisCheck()
        response = make_response(headers={
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-xss-protection": "1; mode=block",
            "referrer-policy": "no-referrer",
        })

        with patch("app.checks.web.headers.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        missing_findings = [f for f in result.findings if "Missing security" in f.title]
        assert len(missing_findings) == 0

    async def test_cors_wildcard_detection(self, sample_service):
        """CORS wildcard creates finding."""
        check = HeaderAnalysisCheck()
        response = make_response(headers={
            "content-type": "text/html",
            "access-control-allow-origin": "*",
        })

        with patch("app.checks.web.headers.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        cors_findings = [f for f in result.findings if "CORS" in f.title]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == "medium"

    async def test_cors_wildcard_with_credentials_high_severity(self, sample_service):
        """CORS wildcard with credentials is high severity."""
        check = HeaderAnalysisCheck()
        response = make_response(headers={
            "content-type": "text/html",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })

        with patch("app.checks.web.headers.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        cors_findings = [f for f in result.findings if "CORS" in f.title]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == "high"

    async def test_server_version_disclosure(self, sample_service):
        """Server version disclosure creates finding."""
        check = HeaderAnalysisCheck()
        response = make_response(headers={
            "content-type": "text/html",
            "server": "nginx/1.21.3",
        })

        with patch("app.checks.web.headers.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        server_findings = [f for f in result.findings if "Server version" in f.title]
        assert len(server_findings) == 1

    async def test_error_handling(self, sample_service):
        """HTTP errors are captured."""
        check = HeaderAnalysisCheck()
        response = make_response(error="Connection refused")

        with patch("app.checks.web.headers.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.errors) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# RobotsTxtCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRobotsTxtCheckInit:
    """Tests for RobotsTxtCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = RobotsTxtCheck()

        assert check.name == "robots_txt"
        assert len(check.INTERESTING_PATTERNS) > 0


class TestRobotsTxtCheckService:
    """Tests for RobotsTxtCheck.check_service."""

    async def test_robots_not_found(self, sample_service):
        """No finding when robots.txt missing."""
        check = RobotsTxtCheck()
        response = make_response(status_code=404)

        with patch("app.checks.web.robots.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 0

    async def test_parses_disallow_paths(self, sample_service):
        """Disallow paths are extracted."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /private/
Disallow: /admin/
Disallow: /public/
"""
        response = make_response(body=robots_content)

        with patch("app.checks.web.robots.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        # /admin/ matches "admin" pattern
        sensitive_findings = [f for f in result.findings if "Sensitive paths" in f.title]
        assert len(sensitive_findings) == 1

    async def test_detects_sensitive_paths(self, sample_service):
        """Sensitive patterns are flagged."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /api/internal/
Disallow: /.git/
Disallow: /model/weights/
"""
        response = make_response(body=robots_content)

        with patch("app.checks.web.robots.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) > 0
        finding = result.findings[0]
        assert "Sensitive" in finding.title

    async def test_extracts_sitemaps(self, sample_service):
        """Sitemap URLs are extracted."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
"""
        response = make_response(body=robots_content)

        with patch("app.checks.web.robots.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        sitemap_findings = [f for f in result.findings if "Sitemaps" in f.title]
        assert len(sitemap_findings) == 1
        assert sitemap_findings[0].severity == "info"

    async def test_sets_outputs(self, sample_service):
        """Outputs contain parsed data."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
"""
        response = make_response(body=robots_content)

        with patch("app.checks.web.robots.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        key = f"robots_{sample_service.port}"
        assert key in result.outputs
        assert "/admin/" in result.outputs[key]["disallowed"]


# ═══════════════════════════════════════════════════════════════════════════════
# PathProbeCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPathProbeCheckInit:
    """Tests for PathProbeCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = PathProbeCheck()

        assert check.name == "path_probe"
        assert len(check.COMMON_PATHS) > 0
        assert "/admin" in check.COMMON_PATHS

    def test_severity_patterns_defined(self):
        """Severity patterns are defined."""
        check = PathProbeCheck()

        assert len(check.HIGH_SEVERITY_PATTERNS) > 0
        assert len(check.MEDIUM_SEVERITY_PATTERNS) > 0


class TestPathProbeCheckService:
    """Tests for PathProbeCheck.check_service."""

    async def test_accessible_path_creates_finding(self, sample_service):
        """HTTP 200 creates accessible path finding."""
        check = PathProbeCheck()
        check.COMMON_PATHS = ["/test"]  # Simplify for test

        response = make_response(
            status_code=200,
            headers={"content-type": "text/html"},
        )

        with patch("app.checks.web.paths.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        accessible_findings = [f for f in result.findings if "Accessible" in f.title]
        assert len(accessible_findings) == 1

    async def test_high_severity_paths(self, sample_service):
        """Sensitive paths get high severity."""
        check = PathProbeCheck()
        check.COMMON_PATHS = ["/.env"]

        response = make_response(
            status_code=200,
            headers={"content-type": "text/plain"},
        )

        with patch("app.checks.web.paths.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    async def test_medium_severity_paths(self, sample_service):
        """Admin paths get medium severity."""
        check = PathProbeCheck()
        check.COMMON_PATHS = ["/admin"]

        response = make_response(
            status_code=200,
            headers={"content-type": "text/html"},
        )

        with patch("app.checks.web.paths.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "medium"

    async def test_forbidden_path_finding(self, sample_service):
        """HTTP 403 on sensitive paths creates finding."""
        check = PathProbeCheck()
        check.COMMON_PATHS = ["/admin"]

        response = make_response(status_code=403)

        with patch("app.checks.web.paths.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        forbidden_findings = [f for f in result.findings if "Protected" in f.title]
        assert len(forbidden_findings) == 1

    async def test_redirect_creates_finding(self, sample_service):
        """Redirects create findings."""
        check = PathProbeCheck()
        check.COMMON_PATHS = ["/admin"]

        response = make_response(
            status_code=302,
            headers={"location": "/login"},
        )

        with patch("app.checks.web.paths.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        redirect_findings = [f for f in result.findings if "Redirect" in f.title]
        assert len(redirect_findings) == 1

    async def test_sets_outputs(self, sample_service):
        """Outputs contain discovered paths."""
        check = PathProbeCheck()
        check.COMMON_PATHS = ["/found", "/forbidden"]

        responses = [
            make_response(status_code=200),
            make_response(status_code=403),
        ]

        with patch("app.checks.web.paths.AsyncHttpClient") as mock_cls:
            m = AsyncMock()
            m.__aenter__ = AsyncMock(return_value=m)
            m.__aexit__ = AsyncMock()
            response_iter = iter(responses)
            m.get = AsyncMock(side_effect=lambda *a, **k: next(response_iter, responses[-1]))
            mock_cls.return_value = m

            result = await check.check_service(sample_service, {})

        key = f"paths_{sample_service.port}"
        assert key in result.outputs


# ═══════════════════════════════════════════════════════════════════════════════
# OpenAPICheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpenAPICheckInit:
    """Tests for OpenAPICheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = OpenAPICheck()

        assert check.name == "openapi_discovery"
        assert "/openapi.json" in check.OPENAPI_PATHS
        assert "/swagger.json" in check.OPENAPI_PATHS


class TestOpenAPICheckService:
    """Tests for OpenAPICheck.check_service."""

    async def test_openapi_json_discovery(self, sample_service):
        """OpenAPI JSON spec is detected."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {"get": {}},
                "/api/items": {"get": {}, "post": {}},
            },
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=str(spec).replace("'", '"'),
        )

        with patch("app.checks.web.openapi.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        spec_findings = [f for f in result.findings if "OpenAPI" in f.title]
        assert len(spec_findings) == 1

    async def test_swagger_json_discovery(self, sample_service):
        """Swagger JSON spec is detected."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/swagger.json"]

        spec = {
            "swagger": "2.0",
            "paths": {
                "/api/v1/data": {"get": {}},
            },
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=str(spec).replace("'", '"'),
        )

        with patch("app.checks.web.openapi.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1

    async def test_sensitive_endpoints_high_severity(self, sample_service):
        """Sensitive endpoints increase severity."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/admin/users": {"get": {}},
                "/api/internal/config": {"get": {}},
            },
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=str(spec).replace("'", '"'),
        )

        with patch("app.checks.web.openapi.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    async def test_swagger_ui_detection(self, sample_service):
        """Swagger UI HTML is detected."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/swagger"]

        response = make_response(
            headers={"content-type": "text/html"},
            body="<html><title>Swagger UI</title></html>",
        )

        with patch("app.checks.web.openapi.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        ui_findings = [f for f in result.findings if "UI" in f.title]
        assert len(ui_findings) == 1

    async def test_sets_outputs_on_discovery(self, sample_service):
        """Outputs contain spec data."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        spec = {
            "openapi": "3.0.0",
            "paths": {"/api/test": {"get": {}}},
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=str(spec).replace("'", '"'),
        )

        with patch("app.checks.web.openapi.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        key = f"openapi_{sample_service.port}"
        assert key in result.outputs


# ═══════════════════════════════════════════════════════════════════════════════
# CorsCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCorsCheckInit:
    """Tests for CorsCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = CorsCheck()

        assert check.name == "cors_check"
        assert "https://evil.attacker.com" in check.TEST_ORIGINS
        assert "null" in check.TEST_ORIGINS


class TestCorsCheckService:
    """Tests for CorsCheck.check_service."""

    async def test_cors_wildcard_detection(self, sample_service):
        """CORS wildcard origin creates finding."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.com"]

        response = make_response(headers={
            "access-control-allow-origin": "*",
        })

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        wildcard_findings = [f for f in result.findings if "wildcard" in f.title.lower()]
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0].severity == "medium"

    async def test_cors_wildcard_with_credentials(self, sample_service):
        """Wildcard with credentials is high severity."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.com"]

        response = make_response(headers={
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    async def test_cors_origin_reflection(self, sample_service):
        """Reflected origin creates finding."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.attacker.com"]

        response = make_response(headers={
            "access-control-allow-origin": "https://evil.attacker.com",
        })

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        reflect_findings = [f for f in result.findings if "reflects" in f.title.lower()]
        assert len(reflect_findings) == 1

    async def test_cors_null_origin(self, sample_service):
        """Null origin creates finding."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["null"]

        response = make_response(headers={
            "access-control-allow-origin": "null",
        })

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        null_findings = [f for f in result.findings if "null" in f.title.lower()]
        assert len(null_findings) == 1
        assert null_findings[0].severity == "medium"

    async def test_no_cors_headers(self, sample_service):
        """No CORS headers means no finding."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.com"]

        response = make_response(headers={})

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 0

    async def test_error_handling(self, sample_service):
        """HTTP errors are captured."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.com"]

        response = make_response(error="Connection refused")

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.errors) > 0
