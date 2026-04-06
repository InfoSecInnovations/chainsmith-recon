"""Tests for OpenAPI discovery and CORS misconfiguration checks."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.cors import CorsCheck
from app.checks.web.openapi import OpenAPICheck
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

        response = make_response(
            headers={
                "access-control-allow-origin": "*",
            }
        )

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        wildcard_findings = [f for f in result.findings if "wildcard" in f.title.lower()]
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0].severity == "medium"

    async def test_cors_wildcard_with_credentials(self, sample_service):
        """Wildcard with credentials is high severity."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.com"]

        response = make_response(
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"

    async def test_cors_origin_reflection(self, sample_service):
        """Reflected origin creates finding."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["https://evil.attacker.com"]

        response = make_response(
            headers={
                "access-control-allow-origin": "https://evil.attacker.com",
            }
        )

        with patch("app.checks.web.cors.AsyncHttpClient", return_value=mock_client(response)):
            result = await check.check_service(sample_service, {})

        reflect_findings = [f for f in result.findings if "reflects" in f.title.lower()]
        assert len(reflect_findings) == 1

    async def test_cors_null_origin(self, sample_service):
        """Null origin creates finding."""
        check = CorsCheck()
        check.TEST_ORIGINS = ["null"]

        response = make_response(
            headers={
                "access-control-allow-origin": "null",
            }
        )

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
