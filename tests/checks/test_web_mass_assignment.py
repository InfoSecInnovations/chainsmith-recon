"""Tests for MassAssignmentCheck."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.mass_assignment import MassAssignmentCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
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
        critical = [f for f in result.observations if f.severity == "critical"]
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

        high_observations = [f for f in result.observations if f.severity == "high"]
        assert len(high_observations) >= 1

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

        blind = [f for f in result.observations if "blind mass assignment" in f.description]
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

        not_vuln = [f for f in result.observations if "not detected" in f.title]
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
        api_observations = [f for f in result.observations if "/api/users" in (f.evidence or "")]
        assert len(api_observations) >= 1

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
        role_observations = [
            f for f in result.observations if "'role' accepted and reflected" in f.title
        ]
        assert len(role_observations) == 0

    @pytest.mark.asyncio
    async def test_validation_error_reveals_schema(self, service):
        """Validation error that reveals accepted fields = low observation."""
        error_body = json.dumps(
            {
                "detail": [
                    {
                        "loc": ["body", "is_admin"],
                        "msg": "extra fields not allowed",
                        "type": "value_error.extra",
                        "ctx": {"expected": ["name", "email"]},
                    }
                ]
            }
        )
        client = mock_client_multi(
            default=resp(422, body=error_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        schema_leak = [f for f in result.observations if "schema" in f.title.lower()]
        assert len(schema_leak) >= 1

    @pytest.mark.asyncio
    async def test_no_api_endpoints(self, service):
        """No testable endpoints found = info observation."""
        # Override _gather_endpoints to return empty
        client = mock_client_multi(default=resp(404, error="Not Found"))
        with (
            patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client),
            patch.object(MassAssignmentCheck, "_gather_endpoints", return_value=[]),
        ):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert any("No testable API endpoints" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_nested_field_reflection(self, service):
        """Field reflected in nested response object is still detected."""
        response_body = json.dumps(
            {
                "data": {"user": {"name": "test", "is_admin": True}},
                "status": "ok",
            }
        )
        client = mock_client_multi(
            default=resp(200, body=response_body),
        )
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        critical = [
            f for f in result.observations if f.severity == "critical" and "is_admin" in f.title
        ]
        assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_error_handling(self, service):
        """Check handles HTTP errors gracefully."""
        client = mock_client_multi(default=resp(500, error="Server Error"))
        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
