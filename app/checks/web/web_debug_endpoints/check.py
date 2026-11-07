"""
app/checks/web/debug_endpoints.py - Exposed Debug Endpoint Analysis

When path_probe finds debug endpoints (/debug, /actuator, /server-status, etc.)
returning 200, this check fetches and analyzes their content for sensitive data.

**Probe/grade.** `check_service()` fetches each debug path,
keeps the 200s, enumerates the Spring Boot Actuator sub-endpoints when it finds
the actuator root, and judges nothing; `grade()` re-reads each recorded body and
places the severity.

One candidate per probed path — each observation named its own `target_url`, so
the subject is the path. The actuator root's candidate carries the sub-endpoint
probes as well: it is the one place the check makes several requests to answer a
single question, and they are handed over together so the grader counts the same
200s the probe saw.

**What the confidence separates.** Two of this check's judgements are structural
matches — a framework debug page or the Werkzeug debugger name — and are as
certain as a signature match gets. The other two rest on *content patterns over
a body of unknown format*, and both over-fire:

- `sensitive-data` escalates to `critical` when a `password|secret|key` pattern
  matches, but `/actuator/env` legitimately lists the *names* of those
  properties with the values masked as `******`, which the pattern still hits.
  So a hit whose match is a masked value carries 0.5, not 0.9.
- `verbose-health` fires on any health endpoint returning more than 100 bytes,
  which a perfectly ordinary JSON health document exceeds. It carries 0.4.

No severity changed.
"""

import re
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig

#: Values a masked config dump prints instead of the secret. A `password=…`
#: pattern that matched one of these has found a property name, not a secret.
MASK_TOKENS = ("******", "*****", "[PROTECTED]", "<redacted>", "REDACTED")

HEALTH_PATHS = ("/health", "/healthcheck", "/.well-known/health")


class DebugEndpointCheck(ServiceIteratingCheck):
    """Analyze accessible debug endpoints for sensitive information disclosure."""

    name = "web_debug_endpoints"
    description = "Analyze exposed debug/actuator/status endpoints for sensitive data"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["debug_observations"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Debug endpoints frequently expose environment variables, connection strings, and internal IPs"
    references = ["OWASP WSTG-CONF-05", "CWE-215"]
    techniques = ["debug endpoint analysis", "information disclosure"]

    # Debug paths to probe (may overlap with path_probe but this check analyzes content)
    DEBUG_PATHS = [
        "/debug",
        "/__debug__/",
        "/actuator",
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/beans",
        "/server-status",
        "/server-info",
        "/.well-known/health",
        "/health",
        "/healthcheck",
        "/elmah.axd",
        "/phpinfo.php",
        "/_profiler",
        "/trace",
    ]

    # Spring Boot Actuator sub-endpoints
    ACTUATOR_ENDPOINTS = [
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/info",
        "/actuator/metrics",
        "/actuator/loggers",
        "/actuator/threaddump",
    ]

    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        (
            "environment_variables",
            re.compile(r"(?:password|secret|key|token|credential|api_key)\s*[=:]\s*\S+", re.I),
        ),
        (
            "connection_string",
            re.compile(
                r"(?:DATABASE_URL|MONGO_URI|REDIS_URL|jdbc:|mongodb://|postgres://|mysql://)", re.I
            ),
        ),
        (
            "internal_ip",
            re.compile(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
            ),
        ),
        (
            "stack_trace",
            re.compile(r"(?:Traceback|at\s+\w+\.\w+\(|Exception in|Error:.*at\s+line)", re.I),
        ),
    ]

    # Framework-specific debug signatures
    FRAMEWORK_SIGNATURES = {
        "django_debug": re.compile(
            r"You're seeing this error because you have DEBUG\s*=\s*True", re.I
        ),
        "werkzeug_debugger": re.compile(
            r"Werkzeug\s+Debug(?:ger)?|The debugger caught an exception", re.I
        ),
        "spring_whitelabel": re.compile(r"Whitelabel Error Page", re.I),
        "express_error": re.compile(r"Cannot GET /|at Layer\.handle", re.I),
        "laravel_ignition": re.compile(r"Ignition|laravel.*exception", re.I),
        "aspnet_error": re.compile(r"Server Error in '/' Application", re.I),
    }

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record, enumerate the actuator. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # Combine our probe paths with those found by path_probe
        paths_to_check = list(self.DEBUG_PATHS)
        accessible = self._get_accessible_paths(service, context)
        for p in accessible:
            p_lower = p.lower()
            if (
                any(
                    kw in p_lower
                    for kw in [
                        "debug",
                        "actuator",
                        "status",
                        "health",
                        "phpinfo",
                        "profiler",
                        "trace",
                    ]
                )
                and p not in paths_to_check
            ):
                paths_to_check.append(p)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:

                def make_exchange(resp) -> Exchange:
                    return exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host
                    )

                actuator_found = False

                for path in paths_to_check:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    # One candidate per path; the primary exchange goes first,
                    # so `grade()` can take exchanges[0] as the body it judges.
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"path-{_slug(path)}",
                        target=service,
                        target_url=url,
                    )
                    candidate.attach(make_exchange(resp))

                    # The actuator root is the one path that answers its question
                    # with several requests. They ride on its candidate so the
                    # grader counts the same 200s.
                    if path == "/actuator" and not actuator_found:
                        actuator_found = True
                        for sub in self.ACTUATOR_ENDPOINTS:
                            sub_resp = await client.get(service.with_path(sub))
                            candidate.attach(make_exchange(sub_resp))

                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read one recorded debug endpoint. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one probed debug path. At most one verdict."""
        exchanges = list(evidence)
        if not exchanges:
            return []

        primary = exchanges[0]
        if not _served(primary):
            return []

        path = _path_of(primary)
        url = primary.request_url or ""
        body = primary.response_body or ""

        # ── Spring Boot Actuator root ─────────────────────
        if path == "/actuator" and len(exchanges) > 1:
            actuator_endpoints = [_path_of(e) for e in exchanges[1:] if _served(e)]
            if not actuator_endpoints:
                return []
            return [
                Verdict(
                    severity="high",
                    # Each named actuator endpoint returned 200 in the record;
                    # short of certain only because a 200 does not prove the
                    # body is the sensitive one (some deployments shim these).
                    confidence=0.9,
                    discriminator="actuator-exposed",
                    title=f"Spring Boot Actuator exposed: {ctx.host}",
                    description=f"{len(actuator_endpoints)} actuator endpoints accessible",
                    evidence=f"Accessible endpoints: {', '.join(actuator_endpoints[:10])}",
                    reasoning=(
                        f"{len(actuator_endpoints)} of {len(self.ACTUATOR_ENDPOINTS)} "
                        "actuator sub-endpoints returned 200"
                    ),
                    signals={"endpoints": actuator_endpoints},
                    raw_data={"endpoints": actuator_endpoints},
                    evidence_ids=[e.id for e in exchanges],
                )
            ]

        evidence_ids = [primary.id]
        framework = self._detect_framework_debug(body)
        sensitive = self._find_sensitive_data(body)

        if framework == "werkzeug_debugger":
            return [
                Verdict(
                    severity="critical",
                    # The Werkzeug debugger names itself, and its presence is the
                    # RCE — not an inference from the name.
                    confidence=0.95,
                    discriminator=f"werkzeug-debugger-{_slug(path)}",
                    title=f"Werkzeug debugger exposed: {ctx.host}{path}",
                    description=("Interactive debugger detected — potential remote code execution"),
                    evidence=fmt_status_evidence(url, 200, body[:200]),
                    reasoning="the body matches the Werkzeug interactive debugger signature",
                    signals={"path": path, "framework": framework},
                    evidence_ids=evidence_ids,
                )
            ]

        if framework == "django_debug":
            return [
                Verdict(
                    severity="high",
                    confidence=0.95,
                    discriminator="django-debug",
                    title=f"Django DEBUG=True: {ctx.host}",
                    description=(
                        "Django debug mode enabled — detailed error pages with source code"
                    ),
                    evidence=fmt_status_evidence(url, 200, body[:200]),
                    reasoning="the body matches Django's DEBUG=True error-page text",
                    signals={"path": path, "framework": framework},
                    evidence_ids=evidence_ids,
                )
            ]

        if sensitive:
            categories = list({s[0] for s in sensitive})
            has_env = "environment_variables" in categories
            # A masked config dump (`password: ******`) trips the env-var
            # pattern without disclosing anything. If every env-var hit is a
            # masked value, the escalation to `critical` rests on a false match.
            masked = has_env and _all_masked(sensitive)
            severity = "critical" if has_env else "high"
            return [
                Verdict(
                    severity=severity,
                    confidence=0.5 if masked else 0.9,
                    discriminator=f"sensitive-{_slug(path)}",
                    title=f"Debug endpoint leaks sensitive data: {ctx.host}{path}",
                    description=f"Sensitive data categories: {', '.join(categories)}",
                    evidence=(f"GET {url} -> 200 | Sensitive patterns: {', '.join(categories)}"),
                    reasoning=(
                        "the secret-name pattern matched only masked values (e.g. "
                        "`password: ******`), which discloses names, not secrets"
                        if masked
                        else f"matched sensitive pattern(s): {', '.join(categories)}"
                    ),
                    signals={"categories": categories, "path": path, "masked": masked},
                    raw_data={"categories": categories, "path": path},
                    evidence_ids=evidence_ids,
                )
            ]

        if framework:
            return [
                Verdict(
                    severity="low",
                    # A framework signature match, but the ones that reach this
                    # branch (`express_error`'s `Cannot GET /`, `laravel_ignition`)
                    # are looser than the debug-mode ones above.
                    confidence=0.75,
                    discriminator=f"framework-{framework}",
                    title=(
                        f"Framework identified from debug page: {framework} at {ctx.host}{path}"
                    ),
                    description=f"Debug/error page reveals framework: {framework}",
                    evidence=fmt_status_evidence(url, 200, body[:200]),
                    reasoning=f"the body matched the {framework} signature",
                    signals={"path": path, "framework": framework},
                    evidence_ids=evidence_ids,
                )
            ]

        if path in HEALTH_PATHS and len(body) > 100:
            return [
                Verdict(
                    severity="medium",
                    # The whole test is "a health endpoint returned more than
                    # 100 bytes", which an ordinary JSON health document does.
                    confidence=0.4,
                    discriminator=f"verbose-health-{_slug(path)}",
                    title=f"Verbose health endpoint: {ctx.host}{path}",
                    description=f"Health endpoint returns detailed info ({len(body)} bytes)",
                    evidence=fmt_status_evidence(url, 200, body[:200]),
                    reasoning=(
                        f"the health endpoint returned {len(body)} bytes; length alone is a "
                        "weak proxy for a verbose or leaky response"
                    ),
                    signals={"path": path, "bytes": len(body)},
                    evidence_ids=evidence_ids,
                )
            ]

        return []

    def _detect_framework_debug(self, body: str) -> str | None:
        """Detect framework-specific debug signatures."""
        for name, pattern in self.FRAMEWORK_SIGNATURES.items():
            if pattern.search(body):
                return name
        return None

    def _find_sensitive_data(self, body: str) -> list[tuple[str, str]]:
        """Find sensitive data patterns in response body."""
        found = []
        for name, pattern in self.SENSITIVE_PATTERNS:
            matches = pattern.findall(body)
            if matches:
                found.append((name, str(matches[0])[:50]))
        return found

    @staticmethod
    def _get_accessible_paths(service: Service, context: dict) -> list[str]:
        """Get accessible paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            return paths_data[paths_key].get("accessible", [])
        if paths_key in context:
            return context[paths_key].get("accessible", [])
        return []


def _path_of(exchange: Exchange) -> str:
    """The path this endpoint was fetched from, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"


def _served(exchange: Exchange) -> bool:
    """True when the endpoint returned 200 with a body."""
    return (
        exchange.error is None and exchange.response_status == 200 and bool(exchange.response_body)
    )


def _all_masked(sensitive: list[tuple[str, str]]) -> bool:
    """True when every environment-variable hit matched a masked value.

    `SENSITIVE_PATTERNS` records the first match per category; this reads it
    back to tell a real leaked secret from a config dump that prints property
    names beside `******`.
    """
    env_hits = [value for name, value in sensitive if name == "environment_variables"]
    if not env_hits:
        return False
    return all(any(mask in value for mask in MASK_TOKENS) for value in env_hits)


def _slug(path: str) -> str:
    """The per-path discriminator suffix, unchanged from the original."""
    return path.replace("/", "-").strip("-")
