"""
app/checks/web/mass_assignment.py - Mass Assignment Detection

Tests REST API endpoints for mass assignment vulnerabilities by sending
extra/unexpected fields in POST/PUT/PATCH requests and observing whether
they are accepted and reflected in the response.

This targets standard REST data models — distinct from AI-specific
API parameter injection checks.
"""

import json
import logging
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

logger = logging.getLogger(__name__)

# Fields to inject, grouped by risk category
PRIVILEGE_FIELDS = [
    "is_admin",
    "admin",
    "role",
    "permissions",
    "is_superuser",
    "is_staff",
    "is_verified",
    "is_active",
]

BILLING_FIELDS = [
    "balance",
    "credits",
    "price",
    "plan",
    "subscription_tier",
]

IDENTITY_FIELDS = [
    "user_id",
    "org_id",
    "tenant_id",
    "owner_id",
    "created_by",
]

INTERNAL_FIELDS = [
    "internal",
    "debug",
    "_private",
    "metadata",
]

# Test values for injected fields
FIELD_VALUES: dict[str, Any] = {
    "is_admin": True,
    "admin": True,
    "role": "admin",
    "permissions": ["admin", "write", "delete"],
    "is_superuser": True,
    "is_staff": True,
    "is_verified": True,
    "is_active": True,
    "balance": 999999,
    "credits": 999999,
    "price": 0,
    "plan": "enterprise",
    "subscription_tier": "unlimited",
    "user_id": "injected-user-id",
    "org_id": "injected-org-id",
    "tenant_id": "injected-tenant-id",
    "owner_id": "injected-owner-id",
    "created_by": "injected-user",
    "internal": True,
    "debug": True,
    "_private": "injected",
    "metadata": {"injected": True},
}

# Risk levels for field categories
FIELD_RISK: dict[str, str] = {}
for f in PRIVILEGE_FIELDS:
    FIELD_RISK[f] = "privilege"
for f in BILLING_FIELDS:
    FIELD_RISK[f] = "billing"
for f in IDENTITY_FIELDS:
    FIELD_RISK[f] = "identity"
for f in INTERNAL_FIELDS:
    FIELD_RISK[f] = "internal"


class MassAssignmentCheck(ServiceIteratingCheck):
    """Detect mass assignment vulnerabilities in REST API endpoints."""

    name = "mass_assignment"
    description = "Test REST APIs for mass assignment by sending extra fields in requests"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["mass_assignment_info"]
    service_types = ["http", "api", "ai"]

    timeout_seconds = 90.0
    delay_between_targets = 0.3

    reason = "REST APIs that bind request bodies without field whitelisting allow privilege escalation and data manipulation"
    references = ["OWASP API8:2023", "CWE-915"]
    techniques = ["mass assignment testing", "API parameter tampering"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        vulnerable_endpoints: list[dict[str, Any]] = []
        tested_count = 0

        # Collect API endpoints to test
        endpoints = self._gather_endpoints(service, context)
        if not endpoints:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"No testable API endpoints found: {service.host}",
                    description="No POST/PUT/PATCH endpoints discovered for mass assignment testing",
                    severity="info",
                    evidence="No OpenAPI spec or API paths with writable methods detected",
                    host=service.host,
                    discriminator="no-endpoints",
                    target=service,
                )
            )
            result.outputs["mass_assignment_info"] = {"tested": 0, "vulnerable": []}
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in endpoints[:5]:  # Cap at 5 endpoints
                    path = endpoint["path"]
                    method = endpoint.get("method", "POST")
                    base_body = endpoint.get("base_body", {})
                    schema_fields = endpoint.get("schema_fields", set())

                    # Test a selection of injection fields
                    injection_fields = self._select_injection_fields(schema_fields)

                    for field_name in injection_fields[:6]:  # Cap per endpoint
                        await self._rate_limit()
                        tested_count += 1

                        test_body = dict(base_body)
                        test_body[field_name] = FIELD_VALUES.get(field_name, "injected")

                        resp = await client._request(
                            method,
                            service.with_path(path),
                            headers={"Content-Type": "application/json"},
                            data=json.dumps(test_body),
                        )

                        if resp.error:
                            continue

                        reflected = self._check_reflection(resp, field_name)
                        accepted = resp.status_code in (200, 201, 204)
                        validation_error = resp.status_code in (400, 422)

                        if reflected:
                            risk_cat = FIELD_RISK.get(field_name, "unknown")
                            severity = (
                                "critical"
                                if risk_cat == "privilege"
                                else "high"
                                if risk_cat in ("billing", "identity")
                                else "medium"
                            )

                            vuln_info = {
                                "path": path,
                                "method": method,
                                "field": field_name,
                                "risk_category": risk_cat,
                                "reflected": True,
                                "status_code": resp.status_code,
                            }
                            vulnerable_endpoints.append(vuln_info)

                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Mass assignment: '{field_name}' accepted and reflected at {method} {path}",
                                    description=f"The {risk_cat} field '{field_name}' was accepted in a {method} request "
                                    f"and reflected in the response, indicating the endpoint does not "
                                    f"filter request body fields",
                                    severity=severity,
                                    evidence=f"{method} {path} with extra field '{field_name}' -> "
                                    f"HTTP {resp.status_code}, field present in response",
                                    host=service.host,
                                    discriminator=f"mass-assign-{path.replace('/', '-').strip('-')}-{field_name}",
                                    target=service,
                                    target_url=service.with_path(path),
                                    references=["CWE-915", "OWASP API8:2023"],
                                )
                            )

                        elif accepted and not validation_error:
                            # Accepted but not reflected — possible blind mass assignment
                            vuln_info = {
                                "path": path,
                                "method": method,
                                "field": field_name,
                                "risk_category": FIELD_RISK.get(field_name, "unknown"),
                                "reflected": False,
                                "status_code": resp.status_code,
                            }
                            vulnerable_endpoints.append(vuln_info)

                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Extra fields accepted at {method} {path}",
                                    description=f"Endpoint accepted request with extra field '{field_name}' "
                                    f"(HTTP {resp.status_code}) but did not reflect it — "
                                    f"potential blind mass assignment",
                                    severity="medium",
                                    evidence=f"{method} {path} with '{field_name}' -> HTTP {resp.status_code} "
                                    f"(field not in response but request succeeded)",
                                    host=service.host,
                                    discriminator=f"blind-mass-assign-{path.replace('/', '-').strip('-')}-{field_name}",
                                    target=service,
                                    target_url=service.with_path(path),
                                    references=["CWE-915"],
                                )
                            )

                        elif validation_error:
                            # Check if the validation error reveals schema info
                            if resp.body and self._reveals_schema(resp.body, field_name):
                                result.observations.append(
                                    build_observation(
                                        check_name=self.name,
                                        title=f"Validation error reveals schema at {method} {path}",
                                        description=f"422/400 response reveals accepted field names when "
                                        f"extra field '{field_name}' was submitted",
                                        severity="low",
                                        evidence=f"{method} {path} -> HTTP {resp.status_code}, "
                                        f"response lists valid fields",
                                        host=service.host,
                                        discriminator=f"schema-leak-{path.replace('/', '-').strip('-')}",
                                        target=service,
                                        target_url=service.with_path(path),
                                        references=["CWE-209"],
                                    )
                                )

        except Exception as e:
            result.errors.append(f"Mass assignment check error: {e}")

        if tested_count > 0 and not vulnerable_endpoints:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Mass assignment not detected: {service.host}",
                    description=f"Tested {tested_count} field injections across {min(len(endpoints), 5)} "
                    f"endpoints — extra fields were rejected",
                    severity="info",
                    evidence=f"{tested_count} injection attempts, all extra fields rejected",
                    host=service.host,
                    discriminator="not-vulnerable",
                    target=service,
                )
            )

        result.outputs["mass_assignment_info"] = {
            "tested": tested_count,
            "vulnerable": vulnerable_endpoints,
        }
        return result

    def _gather_endpoints(self, service: Service, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect API endpoints that accept POST/PUT/PATCH from context."""
        endpoints: list[dict[str, Any]] = []

        # 1. From OpenAPI spec
        openapi_spec = context.get("openapi_spec")
        if isinstance(openapi_spec, dict):
            paths = openapi_spec.get("paths", {})
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method in ("post", "put", "patch"):
                    operation = path_item.get(method)
                    if not isinstance(operation, dict):
                        continue

                    base_body, schema_fields = self._extract_schema_body(operation)
                    endpoints.append(
                        {
                            "path": path,
                            "method": method.upper(),
                            "base_body": base_body,
                            "schema_fields": schema_fields,
                            "source": "openapi",
                        }
                    )

        # 2. From discovered API paths (probe common ones)
        if not endpoints:
            api_endpoints = context.get("api_endpoints", [])
            if isinstance(api_endpoints, list):
                for ep in api_endpoints:
                    if isinstance(ep, dict) and ep.get("path"):
                        endpoints.append(
                            {
                                "path": ep["path"],
                                "method": "POST",
                                "base_body": {},
                                "schema_fields": set(),
                                "source": "discovered",
                            }
                        )

        # 3. Fallback: common API paths
        if not endpoints:
            for path in [
                "/api/users",
                "/api/profile",
                "/api/account",
                "/api/settings",
                "/api/v1/users",
            ]:
                endpoints.append(
                    {
                        "path": path,
                        "method": "POST",
                        "base_body": {"name": "test", "email": "test@example.com"},
                        "schema_fields": set(),
                        "source": "fallback",
                    }
                )

        return endpoints

    def _extract_schema_body(self, operation: dict) -> tuple[dict, set[str]]:
        """Extract a minimal valid body and known fields from an OpenAPI operation."""
        base_body: dict[str, Any] = {}
        schema_fields: set[str] = set()

        req_body = operation.get("requestBody", {})
        if not isinstance(req_body, dict):
            return base_body, schema_fields

        content = req_body.get("content", {})
        for media_type in ("application/json", "application/x-www-form-urlencoded"):
            media_obj = content.get(media_type, {})
            if not isinstance(media_obj, dict):
                continue

            schema = media_obj.get("schema", {})
            if not isinstance(schema, dict):
                continue

            props = schema.get("properties", {})
            required = set(schema.get("required", []))

            for prop_name, prop_schema in props.items():
                schema_fields.add(prop_name)
                if not isinstance(prop_schema, dict):
                    continue

                # Build minimal body from required fields
                if prop_name in required:
                    prop_type = prop_schema.get("type", "string")
                    if prop_type == "string":
                        base_body[prop_name] = "test"
                    elif prop_type == "integer":
                        base_body[prop_name] = 1
                    elif prop_type == "boolean":
                        base_body[prop_name] = True
                    elif prop_type == "array":
                        base_body[prop_name] = []
                    elif prop_type == "object":
                        base_body[prop_name] = {}

            if props:
                break  # Found a schema, stop looking

        return base_body, schema_fields

    def _select_injection_fields(self, schema_fields: set[str]) -> list[str]:
        """Select injection fields that are NOT in the known schema."""
        all_injection = PRIVILEGE_FIELDS + BILLING_FIELDS + IDENTITY_FIELDS + INTERNAL_FIELDS
        if schema_fields:
            return [f for f in all_injection if f not in schema_fields]
        return all_injection

    def _check_reflection(self, resp: Any, field_name: str) -> bool:
        """Check if the injected field appears in the response body."""
        if not resp.body:
            return False
        try:
            data = json.loads(resp.body)
            return self._field_in_dict(data, field_name)
        except (json.JSONDecodeError, ValueError):
            return False

    def _field_in_dict(self, data: Any, field_name: str) -> bool:
        """Recursively check if field_name appears as a key in the response."""
        if isinstance(data, dict):
            if field_name in data:
                return True
            for v in data.values():
                if self._field_in_dict(v, field_name):
                    return True
        elif isinstance(data, list):
            for item in data[:5]:  # Cap recursion
                if self._field_in_dict(item, field_name):
                    return True
        return False

    def _reveals_schema(self, body: str, injected_field: str) -> bool:
        """Check if a validation error response reveals accepted field names."""
        try:
            data = json.loads(body)
            body_str = json.dumps(data).lower()
            # Look for common patterns in validation errors
            schema_hints = [
                "allowed",
                "valid",
                "expected",
                "properties",
                "accepted",
                "fields",
                "schema",
            ]
            return any(hint in body_str for hint in schema_hints)
        except (json.JSONDecodeError, ValueError):
            return False
