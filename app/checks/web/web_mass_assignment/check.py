"""
app/checks/web/mass_assignment.py - Mass Assignment Detection

Tests REST API endpoints for mass assignment vulnerabilities by sending
extra/unexpected fields in POST/PUT/PATCH requests and observing whether
they are accepted and reflected in the response.

This targets standard REST data models — distinct from AI-specific
API parameter injection checks.

**Probe/grade.** `check_service()` gathers the writable
endpoints from context, sends each field-injection request and records it — the
name of the injected field stamped into a request header so the grader can tell
it from the base body — and judges nothing; `grade()` re-reads each recorded
response and decides what happened.

The injection requests are side effects and stay in the probe. One candidate for
the service carries them all; `grade()` returns one verdict per attempt, plus
the summary judgements (`not-vulnerable`, `no-endpoints`) it derives from the
attempts and the context.

**Every judgement here is graded on how much the response actually shows, and
the two that over-claimed now say so:**

- `mass-assign` — a privilege/billing/identity field *reflected* in the response
  — carries 0.7, not certainty: an endpoint that echoes its input reflects any
  field whether or not it was ever bound to a record. Reflection is evidence the
  field was accepted, not proof it was persisted or acted on.
- `blind-mass-assign` — accepted (2xx) but *not* reflected — is the weakest, at
  0.35: servers routinely ignore unknown fields and still return 200, so "did
  not reject" is barely evidence at all. The severity was already only `medium`.

`schema-leak` (0.5) and `not-vulnerable` (0.6, an absence over capped tests) are
graded likewise; `no-endpoints` is categorical (0.9). No severity changed.
"""

import json
import logging
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

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

#: The request header the probe stamps the injected field name into, so the
#: grader can tell it from the base-body fields on the same request.
INJECTED_FIELD_HEADER = "x-chainsmith-injected-field"


class MassAssignmentCheck(ServiceIteratingCheck):
    """Detect mass assignment vulnerabilities in REST API endpoints."""

    name = "web_mass_assignment"
    description = "Test REST APIs for mass assignment by sending extra fields in requests"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["mass_assignment_info"]
    service_types = ["http", "api", "ai"]

    reason = "REST APIs that bind request bodies without field whitelisting allow privilege escalation and data manipulation"
    references = ["OWASP API8:2023", "CWE-915"]
    techniques = ["mass assignment testing", "API parameter tampering"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Inject fields, record each attempt. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate for the service: every attempt is a judgement over the
        # same subject, so the candidate stays undiscriminated and `grade()`
        # names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        endpoints = self._gather_endpoints(service, context)
        if not endpoints:
            # No exchanges to hand over; `grade()` re-gathers from the context
            # and emits the `no-endpoints` verdict.
            result.candidates.append(candidate)
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

                        test_body = dict(base_body)
                        test_body[field_name] = FIELD_VALUES.get(field_name, "injected")
                        body_json = json.dumps(test_body)

                        resp = await client._request(
                            method,
                            service.with_path(path),
                            headers={"Content-Type": "application/json"},
                            data=body_json,
                        )

                        candidate.attach(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=service.host,
                                method=method,
                                request_headers={
                                    "Content-Type": "application/json",
                                    INJECTED_FIELD_HEADER: field_name,
                                },
                                request_body=body_json,
                            )
                        )

        except Exception as e:
            result.errors.append(f"Mass assignment check error: {e}")

        result.candidates.append(candidate)
        result.outputs["mass_assignment_info"] = _reading(candidate.exchanges)
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded injection attempts. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one service's mass-assignment attempts."""
        attempts = [
            e
            for e in evidence
            if INJECTED_FIELD_HEADER in {k.lower() for k in (e.request_headers or {})}
        ]

        if not attempts:
            # Nothing was tested. Distinguish "no endpoints" (the probe found
            # nothing to test) from a run where every request errored.
            endpoints = (
                self._gather_endpoints(ctx.target, ctx.context) if ctx.target is not None else []
            )
            if not endpoints:
                return [
                    Verdict(
                        severity="info",
                        # Categorical: there was nothing with a writable method
                        # to test. Short of 1.0 only because discovery is bounded
                        # by what upstream checks surfaced.
                        confidence=0.9,
                        discriminator="no-endpoints",
                        title=f"No testable API endpoints found: {ctx.host}",
                        description=(
                            "No POST/PUT/PATCH endpoints discovered for mass assignment testing"
                        ),
                        evidence=("No OpenAPI spec or API paths with writable methods detected"),
                        reasoning=(
                            "no OpenAPI spec, discovered API path or fallback endpoint "
                            "offered a writable method to test"
                        ),
                        signals={"endpoints": 0},
                        evidence_ids=evidence.ids(),
                    )
                ]
            return []

        verdicts: list[Verdict] = []
        vulnerable = False

        for exchange in attempts:
            field_name = _injected_field(exchange)
            if not field_name or exchange.error is not None:
                continue

            path = _path_of(exchange)
            method = (exchange.request_method or "POST").upper()
            status = exchange.response_status
            slug = path.replace("/", "-").strip("-")

            reflected = _check_reflection(exchange, field_name)
            accepted = status in (200, 201, 204)
            validation_error = status in (400, 422)

            if reflected:
                vulnerable = True
                risk_cat = FIELD_RISK.get(field_name, "unknown")
                severity = (
                    "critical"
                    if risk_cat == "privilege"
                    else "high"
                    if risk_cat in ("billing", "identity")
                    else "medium"
                )
                verdicts.append(
                    Verdict(
                        severity=severity,
                        # The field came back in the response, so it was
                        # accepted — but an endpoint that echoes its input
                        # reflects any field whether or not it was ever bound to
                        # a record, and that is the classic false positive here.
                        confidence=0.7,
                        discriminator=f"mass-assign-{slug}-{field_name}",
                        title=(
                            f"Mass assignment: '{field_name}' accepted and reflected at "
                            f"{method} {path}"
                        ),
                        description=(
                            f"The {risk_cat} field '{field_name}' was accepted in a "
                            f"{method} request and reflected in the response, indicating "
                            "the endpoint does not filter request body fields"
                        ),
                        evidence=(
                            f"{method} {path} with extra field '{field_name}' -> "
                            f"HTTP {status}, field present in response"
                        ),
                        reasoning=(
                            "the injected field was echoed in the response; reflection "
                            "shows acceptance, not that the field was persisted or acted on"
                        ),
                        signals={
                            "path": path,
                            "method": method,
                            "field": field_name,
                            "risk_category": risk_cat,
                            "reflected": True,
                            "status_code": status,
                        },
                        references=["CWE-915", "OWASP API8:2023"],
                        evidence_ids=[exchange.id],
                    )
                )

            elif accepted and not validation_error:
                vulnerable = True
                verdicts.append(
                    Verdict(
                        severity="medium",
                        # The weakest signal in the check: a 2xx to a request
                        # carrying an extra field. Servers routinely ignore
                        # unknown fields and still succeed, so "did not reject"
                        # is barely evidence of mass assignment.
                        confidence=0.35,
                        discriminator=f"blind-mass-assign-{slug}-{field_name}",
                        title=f"Extra fields accepted at {method} {path}",
                        description=(
                            f"Endpoint accepted request with extra field '{field_name}' "
                            f"(HTTP {status}) but did not reflect it — potential blind "
                            "mass assignment"
                        ),
                        evidence=(
                            f"{method} {path} with '{field_name}' -> HTTP {status} "
                            "(field not in response but request succeeded)"
                        ),
                        reasoning=(
                            "the request succeeded but the field was not reflected; a "
                            "server that silently drops unknown fields is indistinguishable "
                            "from one that bound it"
                        ),
                        signals={
                            "path": path,
                            "method": method,
                            "field": field_name,
                            "risk_category": FIELD_RISK.get(field_name, "unknown"),
                            "reflected": False,
                            "status_code": status,
                        },
                        references=["CWE-915"],
                        evidence_ids=[exchange.id],
                    )
                )

            elif validation_error and _reveals_schema(exchange.response_body or ""):
                verdicts.append(
                    Verdict(
                        severity="low",
                        # A validation body containing words like "allowed" or
                        # "properties" is a heuristic for a schema leak; plenty
                        # of terse 422s contain them without listing fields.
                        confidence=0.5,
                        discriminator=f"schema-leak-{slug}",
                        title=f"Validation error reveals schema at {method} {path}",
                        description=(
                            f"422/400 response reveals accepted field names when extra "
                            f"field '{field_name}' was submitted"
                        ),
                        evidence=(f"{method} {path} -> HTTP {status}, response lists valid fields"),
                        reasoning=(
                            "the validation body contains schema-hint words; whether it "
                            "actually enumerates fields is not certain"
                        ),
                        signals={"path": path, "method": method, "status_code": status},
                        references=["CWE-209"],
                        evidence_ids=[exchange.id],
                    )
                )

        tested = _tested_count(attempts)
        if tested > 0 and not vulnerable:
            verdicts.append(
                Verdict(
                    severity="info",
                    # An absence over a capped test (≤5 endpoints, ≤6 fields
                    # each), so it means "not found here", not "not present".
                    confidence=0.6,
                    discriminator="not-vulnerable",
                    title=f"Mass assignment not detected: {ctx.host}",
                    description=(f"Tested {tested} field injections — extra fields were rejected"),
                    evidence=f"{tested} injection attempts, all extra fields rejected",
                    reasoning=(
                        f"{tested} injection(s) were rejected; the test is capped at 5 "
                        "endpoints and 6 fields each, so this is a floor"
                    ),
                    signals={"tested": tested},
                    evidence_ids=[e.id for e in attempts],
                )
            )

        return verdicts

    def _gather_endpoints(self, service: Service, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect API endpoints that accept POST/PUT/PATCH from context."""
        context = context or {}
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


# ── The one reader, called by both halves ────────────────────────────


def _injected_field(exchange: Exchange) -> str | None:
    """The field this attempt injected, read back off its request header."""
    for key, value in (exchange.request_headers or {}).items():
        if key.lower() == INJECTED_FIELD_HEADER:
            return value
    return None


def _path_of(exchange: Exchange) -> str:
    """The path this attempt targeted, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"


def _tested_count(attempts: list[Exchange]) -> int:
    """How many injections were made — the original's `tested_count`.

    Counts every attempt, errored ones included, because the probe incremented
    before sending; the recorded exchange exists either way.
    """
    return len(attempts)


def _check_reflection(exchange: Exchange, field_name: str) -> bool:
    """Check if the injected field appears in the recorded response body."""
    body = exchange.response_body
    if not body:
        return False
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    return _field_in_dict(data, field_name)


def _field_in_dict(data: Any, field_name: str) -> bool:
    """Recursively check if field_name appears as a key in the response."""
    if isinstance(data, dict):
        if field_name in data:
            return True
        for v in data.values():
            if _field_in_dict(v, field_name):
                return True
    elif isinstance(data, list):
        for item in data[:5]:  # Cap recursion
            if _field_in_dict(item, field_name):
                return True
    return False


def _reveals_schema(body: str) -> bool:
    """Check if a validation error response reveals accepted field names."""
    if not body:
        return False
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    body_str = json.dumps(data).lower()
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


def _reading(exchanges: list[Exchange]) -> dict[str, Any]:
    """Read `mass_assignment_info` out of the recorded attempts.

    `tested` and `vulnerable` match the pre-57.4 output: every reflected field
    and every accepted-but-not-reflected field is a vulnerable entry, in the
    order the attempts were made.
    """
    attempts = [e for e in exchanges if _injected_field(e) is not None]
    vulnerable: list[dict[str, Any]] = []

    for exchange in attempts:
        if exchange.error is not None:
            continue
        field_name = _injected_field(exchange)
        status = exchange.response_status
        reflected = _check_reflection(exchange, field_name)
        accepted = status in (200, 201, 204)
        validation_error = status in (400, 422)

        if reflected:
            vulnerable.append(
                {
                    "path": _path_of(exchange),
                    "method": (exchange.request_method or "POST").upper(),
                    "field": field_name,
                    "risk_category": FIELD_RISK.get(field_name, "unknown"),
                    "reflected": True,
                    "status_code": status,
                }
            )
        elif accepted and not validation_error:
            vulnerable.append(
                {
                    "path": _path_of(exchange),
                    "method": (exchange.request_method or "POST").upper(),
                    "field": field_name,
                    "risk_category": FIELD_RISK.get(field_name, "unknown"),
                    "reflected": False,
                    "status_code": status,
                }
            )

    return {"tested": _tested_count(attempts), "vulnerable": vulnerable}
