"""Tests for web_openapi_discovery."""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_openapi_discovery import OpenAPICheck
from app.lib.http import HttpResponse


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

    async def get_response(url=None, *args, **kwargs):
        try:
            response = next(response_iter)
        except StopIteration:
            response = responses[-1]  # Repeat last response
        # The real client stamps the requested URL onto the response, and a
        # migrated check records that URL on the exchange its grader reads.
        return replace(response, url=url) if url else response

    mock.get = AsyncMock(side_effect=get_response)
    mock.options = AsyncMock(side_effect=get_response)
    mock.head = AsyncMock(side_effect=get_response)

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


class TestOpenAPICheckInit:
    """Tests for OpenAPICheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = OpenAPICheck()

        assert check.name == "web_openapi_discovery"
        assert "/openapi.json" in check.OPENAPI_PATHS
        assert "/swagger.json" in check.OPENAPI_PATHS


class TestOpenAPICheckService:
    """Tests for OpenAPICheck.check_service."""

    async def test_openapi_json_discovery(self, sample_service):
        """OpenAPI JSON spec is detected with correct title, severity, and evidence."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Example API", "version": "1.0.0"},
            "paths": {
                "/api/products": {"get": {"summary": "List products"}},
                "/api/orders": {
                    "get": {"summary": "List orders"},
                    "post": {"summary": "Create order"},
                },
            },
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=json.dumps(spec),
        )

        with patch(
            "app.checks.web.web_openapi_discovery.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        spec_observations = [f for f in result.observations if "OpenAPI" in f.title]
        assert len(spec_observations) == 1
        obs = spec_observations[0]
        assert "2 endpoints" in obs.title
        assert obs.severity == "medium"
        assert "/openapi.json" in obs.evidence

    async def test_swagger_json_discovery(self, sample_service):
        """Swagger 2.0 JSON spec is detected with correct title and severity."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/swagger.json"]

        spec = {
            "swagger": "2.0",
            "info": {"title": "Legacy API", "version": "1.0"},
            "paths": {
                "/api/v1/data": {"get": {"summary": "Fetch data"}},
            },
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=json.dumps(spec),
        )

        with patch(
            "app.checks.web.web_openapi_discovery.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "OpenAPI documentation exposed" in obs.title
        assert "1 endpoints" in obs.title
        assert obs.severity == "medium"

    async def test_sensitive_endpoints_high_severity(self, sample_service):
        """Sensitive endpoints increase severity to high."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Internal API", "version": "2.0.0"},
            "paths": {
                "/api/admin/users": {"get": {"summary": "List admin users"}},
                "/api/internal/config": {"get": {"summary": "Get runtime config"}},
                "/api/public/health": {"get": {"summary": "Health check"}},
            },
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=json.dumps(spec),
        )

        with patch(
            "app.checks.web.web_openapi_discovery.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.severity == "high"
        assert "3 endpoints" in obs.title
        assert "OpenAPI documentation exposed" in obs.title

    async def test_swagger_ui_detection(self, sample_service):
        """Swagger UI HTML page is detected with correct title and severity."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/swagger"]

        # Realistic Swagger UI page with the keyword embedded in a full HTML document
        html_body = (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '  <meta charset="UTF-8">\n'
            "  <title>API Reference - Developer Portal</title>\n"
            '  <link rel="stylesheet" href="/static/css/swagger-ui.css">\n'
            "</head>\n"
            "<body>\n"
            '  <div id="swagger-ui-container"></div>\n'
            '  <script src="/static/js/swagger-ui-bundle.js"></script>\n'
            "  <script>\n"
            "    SwaggerUIBundle({\n"
            '      url: "/openapi.json",\n'
            '      dom_id: "#swagger-ui-container"\n'
            "    });\n"
            "  </script>\n"
            "</body>\n"
            "</html>"
        )
        response = make_response(
            headers={"content-type": "text/html"},
            body=html_body,
        )

        with patch(
            "app.checks.web.web_openapi_discovery.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        ui_observations = [f for f in result.observations if "UI" in f.title]
        assert len(ui_observations) == 1
        obs = ui_observations[0]
        assert "API documentation UI" in obs.title
        assert obs.severity == "low"
        assert "/swagger" in obs.evidence

    async def test_non_openapi_json_no_observation(self, sample_service):
        """JSON at /openapi.json that is not an OpenAPI spec produces no observation."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        # A generic JSON response with no openapi/swagger/paths keys
        non_spec_body = json.dumps(
            {
                "status": "ok",
                "version": "1.2.3",
                "features": ["search", "export"],
            }
        )
        response = make_response(
            headers={"content-type": "application/json"},
            body=non_spec_body,
        )

        with patch(
            "app.checks.web.web_openapi_discovery.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 0

    async def test_sets_outputs_on_discovery(self, sample_service):
        """Outputs contain spec data."""
        check = OpenAPICheck()
        check.OPENAPI_PATHS = ["/openapi.json"]

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "0.1.0"},
            "paths": {"/api/test": {"get": {"summary": "Test endpoint"}}},
        }
        response = make_response(
            headers={"content-type": "application/json"},
            body=json.dumps(spec),
        )

        with patch(
            "app.checks.web.web_openapi_discovery.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        key = f"openapi_{sample_service.port}"
        assert key in result.outputs
