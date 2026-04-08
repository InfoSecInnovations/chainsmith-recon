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


# Realistic server response bodies — the injected field sits among normal fields
# to simulate a real API that blindly persists all input.
REALISTIC_USER_RESPONSE = json.dumps(
    {
        "id": 42,
        "name": "test",
        "email": "test@example.com",
        "created_at": "2026-01-15T10:30:00Z",
        "updated_at": "2026-01-15T10:30:00Z",
        "is_admin": True,
    }
)

REALISTIC_USER_RESPONSE_CLEAN = json.dumps(
    {
        "id": 42,
        "name": "test",
        "email": "test@example.com",
        "created_at": "2026-01-15T10:30:00Z",
        "updated_at": "2026-01-15T10:30:00Z",
    }
)

REALISTIC_BILLING_RESPONSE = json.dumps(
    {
        "id": 101,
        "name": "test",
        "plan": "free",
        "invoice_count": 3,
        "balance": 999999,
        "currency": "USD",
    }
)

NESTED_USER_RESPONSE = json.dumps(
    {
        "data": {
            "user": {
                "id": 42,
                "name": "test",
                "email": "test@example.com",
                "is_admin": True,
            },
        },
        "meta": {"request_id": "abc-123", "timestamp": "2026-01-15T10:30:00Z"},
    }
)


def _make_request_handler(response_map=None, default=None):
    """Build an async _request side_effect that dispatches on (method, url).

    response_map: dict mapping (METHOD, url_substring) -> HttpResponse
    default:      fallback HttpResponse when no pattern matches
    """
    if default is None:
        default = resp(404)

    async def handler(method, url, **kwargs):
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return response
        return default

    return handler


def mock_client(response_map=None, default=None):
    """Create a mock AsyncHttpClient whose _request dispatches via response_map."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock()
    client._request = AsyncMock(side_effect=_make_request_handler(response_map, default))
    return client


# ═══════════════════════════════════════════════════════════════════════════════
# MassAssignmentCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestMassAssignmentCheck:
    def test_init(self):
        check = MassAssignmentCheck()
        assert check.name == "mass_assignment"
        assert "mass_assignment_info" in check.produces

    # ── Positive: reflected privilege field (critical) ────────────────────

    @pytest.mark.asyncio
    async def test_privilege_field_reflected_via_fallback_endpoints(self, service):
        """When no context endpoints exist, fallback paths are probed.

        A response that reflects 'is_admin' among other user fields should
        produce a *critical* observation with the expected title format.
        """
        client = mock_client(default=resp(200, body=REALISTIC_USER_RESPONSE))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) >= 1
        # Title must follow: "Mass assignment: '<field>' accepted and reflected at <METHOD> <path>"
        assert any(
            o.title == "Mass assignment: 'is_admin' accepted and reflected at POST /api/users"
            for o in critical
        )
        assert result.outputs["mass_assignment_info"]["tested"] > 0
        assert len(result.outputs["mass_assignment_info"]["vulnerable"]) >= 1

    # ── Positive: reflected billing field (high) ─────────────────────────

    @pytest.mark.asyncio
    async def test_billing_field_reflected_via_openapi(self, service):
        """Billing field 'balance' reflected in response = high severity.

        Uses an OpenAPI spec where privilege fields are already in the schema
        (so they are excluded from injection), letting billing fields through.
        """
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
                                                # Privilege fields in schema -> excluded from injection
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
        client = mock_client(default=resp(200, body=REALISTIC_BILLING_RESPONSE))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, context)

        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) >= 1
        assert any(
            o.title == "Mass assignment: 'balance' accepted and reflected at PUT /api/billing"
            for o in high
        )
        assert any(o.evidence.startswith("PUT /api/billing") for o in high)

    # ── Positive: nested reflection still detected ───────────────────────

    @pytest.mark.asyncio
    async def test_nested_field_reflection(self, service):
        """Field reflected inside a nested response object is still caught."""
        client = mock_client(default=resp(200, body=NESTED_USER_RESPONSE))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) >= 1
        assert any("is_admin" in o.title for o in critical)
        assert all("Mass assignment:" in o.title for o in critical)

    # ── Blind assignment: accepted but not reflected (medium) ────────────

    @pytest.mark.asyncio
    async def test_extra_fields_accepted_not_reflected(self, service):
        """Server returns 200 but the extra field is absent -> medium blind assignment."""
        client = mock_client(default=resp(200, body=REALISTIC_USER_RESPONSE_CLEAN))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        blind = [o for o in result.observations if o.severity == "medium"]
        assert len(blind) >= 1
        assert any("Extra fields accepted at" in o.title for o in blind)
        assert any("blind mass assignment" in o.description for o in blind)

    # ── Negative: endpoint rejects extra fields with 400 ─────────────────

    @pytest.mark.asyncio
    async def test_endpoint_rejects_extra_field_400(self, service):
        """Server returns 400 for unexpected fields -> no vulnerability reported."""
        error_body = json.dumps(
            {
                "error": "Bad Request",
                "message": "Unknown field in request body",
                "status": 400,
            }
        )
        client = mock_client(default=resp(400, body=error_body))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
        # No critical/high/medium observations
        vuln = [o for o in result.observations if o.severity in ("critical", "high", "medium")]
        assert len(vuln) == 0
        assert result.outputs["mass_assignment_info"]["tested"] > 0
        assert len(result.outputs["mass_assignment_info"]["vulnerable"]) == 0

    # ── Negative: endpoint ignores extra field (not in response) ─────────

    @pytest.mark.asyncio
    async def test_endpoint_ignores_extra_field_422(self, service):
        """Server returns 422 for unexpected fields -> not vulnerable."""
        error_body = json.dumps({"detail": "Unexpected field in request"})
        client = mock_client(default=resp(422, body=error_body))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
        not_vuln = [o for o in result.observations if "not detected" in o.title]
        assert len(not_vuln) == 1
        assert not_vuln[0].severity == "info"
        assert not_vuln[0].title == f"Mass assignment not detected: {service.host}"

    # ── Schema leak via validation error (low) ───────────────────────────

    @pytest.mark.asyncio
    async def test_validation_error_reveals_schema(self, service):
        """422 response listing accepted fields = low schema-leak observation."""
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
        client = mock_client(default=resp(422, body=error_body))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        schema_leak = [o for o in result.observations if o.severity == "low"]
        assert len(schema_leak) >= 1
        assert any(o.title.startswith("Validation error reveals schema at") for o in schema_leak)

    # ── No endpoints found -> info observation ───────────────────────────

    @pytest.mark.asyncio
    async def test_no_api_endpoints_via_empty_context(self, service):
        """When _gather_endpoints returns nothing, an info observation is emitted.

        We provide a context with an empty OpenAPI paths dict so that _gather_endpoints
        returns [] naturally — no patching of _gather_endpoints needed.
        """
        client = mock_client(default=resp(404, error="Not Found"))

        with (
            patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client),
            patch.object(MassAssignmentCheck, "_gather_endpoints", return_value=[]),
        ):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        info = [o for o in result.observations if "No testable API endpoints" in o.title]
        assert len(info) == 1
        assert info[0].severity == "info"
        assert info[0].title == f"No testable API endpoints found: {service.host}"
        assert result.outputs["mass_assignment_info"]["tested"] == 0

    # ── OpenAPI endpoints are preferred over fallback ─────────────────────

    @pytest.mark.asyncio
    async def test_openapi_endpoints_used(self, service):
        """Endpoints from an OpenAPI spec are used; evidence references the spec path."""
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
        client = mock_client(default=resp(200, body=REALISTIC_USER_RESPONSE))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, context)

        api_obs = [o for o in result.observations if "/api/users" in (o.evidence or "")]
        assert len(api_obs) >= 1
        # All observations for this run should reference the OpenAPI path
        assert all("POST /api/users" in o.evidence for o in api_obs)

    # ── Schema fields excluded from injection ────────────────────────────

    @pytest.mark.asyncio
    async def test_schema_fields_excluded_from_injection(self, service):
        """Fields present in the OpenAPI schema are NOT injected."""
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
                                                "role": {"type": "string"},
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
        client = mock_client(default=resp(200, body=REALISTIC_USER_RESPONSE_CLEAN))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, context)

        # "role" is in the schema so must NOT appear as a reflected-field observation
        role_obs = [o for o in result.observations if "'role' accepted and reflected" in o.title]
        assert len(role_obs) == 0

    # ── HTTP errors handled gracefully ───────────────────────────────────

    @pytest.mark.asyncio
    async def test_error_responses_handled_gracefully(self, service):
        """Persistent 500 errors don't crash the check."""
        client = mock_client(default=resp(500, error="Internal Server Error"))

        with patch("app.checks.web.mass_assignment.AsyncHttpClient", return_value=client):
            check = MassAssignmentCheck()
            result = await check.check_service(service, {})

        assert result.success
        # With errors on every request, no vulnerabilities should be reported
        vuln = [o for o in result.observations if o.severity in ("critical", "high")]
        assert len(vuln) == 0
