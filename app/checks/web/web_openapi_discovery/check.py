"""
app/checks/web/openapi.py - OpenAPI/Swagger Discovery

Find and analyze exposed API documentation.

**Probe/grade.** `check_service()` walks the candidate paths,
records each that answered 200, and stops at the first real spec; `grade()`
re-reads the recorded bodies and decides what was found.

The probe still stops early — the original's "first spec found wins" — and it
decides that by reading the exchange it just recorded rather than the response
object (§6.2). `_kind()` is the one parser both halves call, so "this is a spec"
cannot mean one thing to the probe and another to the grader.

Two confidences here are doing real work:

- The spec trigger accepts a JSON object carrying *any* of `openapi`, `swagger`
  or `paths`. The first two are version declarations and settle the question;
  `paths` alone is any JSON document that happens to have that key.
- `severity` escalates to `high` when an endpoint name contains one of six
  keywords, and two of them — `user` and `auth` — are in almost every REST API
  ever written. The escalation is preserved and the verdict now says how much
  it rests on.
"""

from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict, extract_paths_from_openapi, safe_json

#: Markers of an actual documentation bundle, as opposed to a page that merely
#: says the word. Grading input only — the trigger is unchanged.
UI_BUNDLE_MARKERS = ("swagger-ui", "swaggerui", "redoc.standalone", "redoc-standalone")


class OpenAPICheck(ServiceIteratingCheck):
    """Discover and analyze OpenAPI/Swagger documentation."""

    name = "web_openapi_discovery"
    description = "Find exposed API documentation and extract endpoint information"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["api_endpoints", "openapi_specs"]
    service_types = ["http", "api", "ai"]

    reason = "OpenAPI docs reveal all API endpoints, parameters, auth mechanisms, and data models"
    references = ["OWASP API Security Top 10", "OWASP API1:2023", "OpenAPI Specification"]
    techniques = ["API enumeration", "documentation discovery"]

    OPENAPI_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/v1/openapi.json",
        "/docs/openapi.json",
        "/api-docs",
        "/swagger",
        "/docs",
        "/redoc",
        "/api/docs",
        "/api/v1/docs",
        "/swagger-ui.html",
    ]

    SENSITIVE_PATH_KEYWORDS = ["admin", "internal", "debug", "config", "user", "auth"]

    #: The keywords that name an administrative surface rather than appearing in
    #: every CRUD API. Grading input only; `SENSITIVE_PATH_KEYWORDS` still
    #: decides the severity.
    STRONG_PATH_KEYWORDS = frozenset({"admin", "internal", "debug", "config"})

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record, stop at the first spec. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # One candidate per service: a spec and any number of UI pages are
        # separate judgements over the same subject, so the candidate stays
        # undiscriminated and `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.OPENAPI_PATHS:
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200:
                        continue

                    exchange = exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=context.get("scan_id") or "",
                        host=service.host,
                    )

                    # Only the exchanges that support a judgement are handed
                    # over. The other ten answered 200 with something unrelated,
                    # and a corpus of those is volume without evidence — the
                    # interceptor still stores them when capture is on.
                    kind = _kind(exchange)
                    if kind is None:
                        continue
                    candidate.attach(exchange)

                    if kind == "spec":
                        spec = _spec_of(exchange) or {}
                        result.outputs[f"openapi_{service.port}"] = {
                            "url": url,
                            "endpoints": extract_paths_from_openapi(spec),
                            "spec": spec,
                        }
                        break  # First spec found wins

            if candidate.exchanges:
                result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded documentation. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on the API documentation one service exposed."""
        verdicts: list[Verdict] = []

        for exchange in evidence.completed():
            kind = _kind(exchange)
            path = urlparse(exchange.request_url or "").path or "/"

            if kind == "spec":
                verdicts.append(self._grade_spec(exchange, path))
            elif kind == "ui":
                verdicts.append(self._grade_ui(exchange, path))

        return verdicts

    def _grade_spec(self, exchange: Exchange, path: str) -> Verdict:
        """Grade one recorded OpenAPI/Swagger document."""
        spec = _spec_of(exchange) or {}
        endpoints = extract_paths_from_openapi(spec)

        security_schemes = list(
            spec.get("components", {}).get("securitySchemes", {}).keys()
        ) or list(spec.get("securityDefinitions", {}).keys())

        matched = {
            kw for kw in self.SENSITIVE_PATH_KEYWORDS if any(kw in e.lower() for e in endpoints)
        }
        sensitive = [
            e for e in endpoints if any(kw in e.lower() for kw in self.SENSITIVE_PATH_KEYWORDS)
        ]

        endpoint_preview = ", ".join(endpoints[:5])
        if len(endpoints) > 5:
            endpoint_preview += "..."

        # A document declaring `openapi:` or `swagger:` is a spec by its own
        # word. One accepted on `paths` alone is any JSON with that key.
        declared = "openapi" in spec or "swagger" in spec
        strong = matched & self.STRONG_PATH_KEYWORDS

        if sensitive:
            severity = "high"
            if strong:
                confidence = 0.9 if declared else 0.7
                why = f"endpoint name(s) match {', '.join(sorted(strong))}"
            else:
                # The whole escalation rests on `user` or `auth` appearing in an
                # endpoint name, which nearly every REST API satisfies.
                confidence = 0.6
                why = (
                    f"escalated only on {', '.join(sorted(matched))}, which most "
                    "ordinary APIs contain"
                )
        else:
            severity = "medium"
            confidence = 0.95 if declared else 0.7
            why = (
                "document declares its OpenAPI/Swagger version"
                if declared
                else "document was accepted on a `paths` key alone, with no version declared"
            )

        return Verdict(
            severity=severity,
            confidence=confidence,
            discriminator="spec-exposed",
            title=f"OpenAPI documentation exposed ({len(endpoints)} endpoints)",
            description="API documentation reveals endpoint structure and attack surface",
            evidence=f"Spec at {path} | Endpoints include: {endpoint_preview}",
            reasoning=f"{len(endpoints)} endpoint(s) read from the recorded spec; {why}",
            signals={
                "endpoints": len(endpoints),
                "sensitive_endpoints": sensitive,
                "keywords_matched": sorted(matched),
                "version_declared": declared,
                "security_schemes": security_schemes,
            },
            raw_data={
                "endpoints": endpoints,
                "sensitive_endpoints": sensitive,
                "security_schemes": security_schemes,
                "spec_path": path,
            },
            references=["OWASP API1:2023"],
            evidence_ids=[exchange.id],
        )

    def _grade_ui(self, exchange: Exchange, path: str) -> Verdict:
        """Grade one recorded documentation UI page."""
        body_lower = (exchange.response_body or "").lower()
        bundled = any(marker in body_lower for marker in UI_BUNDLE_MARKERS)

        return Verdict(
            severity="low",
            # The trigger is a keyword anywhere in an HTML document, which a
            # page that merely links to the docs also satisfies. A loaded
            # Swagger-UI or ReDoc bundle is the real thing.
            confidence=0.9 if bundled else 0.75,
            discriminator=f"ui-{path.strip('/').replace('/', '-')}",
            title=f"API documentation UI at {path}",
            description="Interactive API documentation is accessible",
            evidence=f"Swagger/OpenAPI UI found at {path}",
            reasoning=(
                "page loads a Swagger-UI or ReDoc bundle"
                if bundled
                else "page mentions swagger/openapi/redoc but loads no documentation bundle"
            ),
            signals={"path": path, "bundle_detected": bundled},
            evidence_ids=[exchange.id],
        )


# ── The one parser, called by both halves ────────────────────────────


def _spec_of(exchange: Exchange) -> dict | None:
    """The recorded body as an OpenAPI/Swagger document, or `None`.

    The original trigger, unchanged: JSON content type, a JSON object, and at
    least one of `openapi`, `swagger` or `paths`.
    """
    content_type = extract_headers_dict(exchange.response_headers or {}).get("content-type", "")
    if "json" not in content_type:
        return None

    spec = safe_json(exchange.response_body or "")
    if not spec or not isinstance(spec, dict):
        return None
    if "openapi" in spec or "swagger" in spec or "paths" in spec:
        return spec
    return None


def _kind(exchange: Exchange) -> str | None:
    """`"spec"`, `"ui"`, or `None` for a 200 that was neither.

    The probe reads this to decide whether to keep looking; the grader reads it
    to decide what to say. One reading, so the two cannot drift.
    """
    if _spec_of(exchange) is not None:
        return "spec"

    content_type = extract_headers_dict(exchange.response_headers or {}).get("content-type", "")
    if "html" in content_type:
        body_lower = (exchange.response_body or "").lower()
        if any(kw in body_lower for kw in ("swagger", "openapi", "redoc")):
            return "ui"
    return None
