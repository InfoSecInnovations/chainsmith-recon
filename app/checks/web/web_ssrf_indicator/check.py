"""
app/checks/web/ssrf_indicator.py - SSRF Indicator Detection

Identifies endpoints that accept URL parameters — classic SSRF candidates,
especially common in AI services that process documents, images, or fetch
external content.

This check identifies candidates only. It does NOT attempt actual SSRF
exploitation (no callback, no internal IP probing).

**Probe/grade.** Only the third of this check's three
sources touches the network: `check_service()` probes the known SSRF-prone paths
and records each. The other two sources — the OpenAPI spec and the paths
discovered upstream — are read out of the scan context, which the grader also
holds (`GradeContext.context`), so no exchange stands behind them.

The check therefore emits **one candidate for the service** carrying the probe
GETs, and `grade()` re-derives all three sources — OpenAPI and discovered from
`ctx.context`, probe from the recorded exchanges — and returns one verdict per
unique candidate path. `_collect()` is the one function both halves call, so
`ssrf_candidates` (the output) and the verdicts cannot drift.

**The confidence is doing something this check needs said out loud: none of
these findings is an SSRF, and the severities never claimed one.** They are the
strength of the evidence that a parameter *takes a URL*:

- **OpenAPI** (0.8) — the spec declares the parameter, sometimes with a `uri`
  format. Strong for "takes a URL", but a declared parameter may be validated,
  allow-listed, or unreachable.
- **discovered** (0.7) — a URL-named parameter seen in a real query string.
- **probe** (0.5) — the weakest: an endpoint answered and its body *mentions* a
  URL field, or a `400/422` came back. A generic validation error naming "url"
  matches whether or not the endpoint is fetch-like.

Every verdict's `reasoning` says the finding is a candidate, not a confirmed
vulnerability.
"""

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

# Parameter names that commonly accept URLs
URL_PARAM_NAMES = [
    "url",
    "uri",
    "link",
    "src",
    "source",
    "href",
    "image",
    "img",
    "image_url",
    "img_url",
    "document",
    "doc",
    "doc_url",
    "document_url",
    "fetch",
    "load",
    "download",
    "proxy",
    "forward",
    "target",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return_url",
    "return_to",
    "callback",
    "callback_url",
    "webhook",
    "webhook_url",
    "file",
    "file_url",
    "path",
    "resource",
    "endpoint",
    "api_url",
    "base_url",
    "feed",
    "feed_url",
    "rss",
]

# OpenAPI parameter formats/patterns that suggest URL input
OPENAPI_URL_INDICATORS = {"uri", "url", "iri", "iri-reference", "uri-reference"}

# Paths commonly associated with SSRF-vulnerable functionality
SSRF_PRONE_PATHS = [
    "/api/fetch",
    "/api/proxy",
    "/api/scrape",
    "/api/crawl",
    "/api/summarize",
    "/api/analyze",
    "/api/extract",
    "/api/import",
    "/api/webhook",
    "/api/callback",
    "/api/preview",
    "/api/embed",
    "/api/render",
    "/proxy",
    "/fetch",
    "/load",
    "/download",
]

#: Params whose very name is an action verb — a stronger SSRF tell, and the ones
#: the original raised to `medium` regardless of source.
ACTION_PARAMS = ("proxy", "forward", "fetch", "download")

PROBE_ACCEPT_CODES = (200, 400, 405, 422)


class SSRFIndicatorCheck(ServiceIteratingCheck):
    """Identify endpoints with URL-accepting parameters (SSRF candidates)."""

    name = "web_ssrf_indicator"
    description = "Detect parameters that accept URLs — potential SSRF vectors"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["ssrf_candidates"]
    service_types = ["http", "html", "api", "ai"]

    reason = (
        "AI services frequently accept URLs for document processing, creating classic SSRF vectors"
    )
    references = ["OWASP WSTG-INPV-19", "CWE-918"]
    techniques = ["SSRF candidate identification", "parameter analysis"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Probe the SSRF-prone paths, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate for the service: the three sources are collapsed by path
        # and each yields its own verdict, so the candidate stays undiscriminated
        # and `grade()` names each.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in SSRF_PRONE_PATHS:
                    await self._rate_limit()
                    resp = await client.get(service.with_path(path))
                    if resp.error:
                        continue
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )
        except Exception as e:
            result.errors.append(f"SSRF probe error: {e}")

        result.candidates.append(candidate)
        result.outputs["ssrf_candidates"] = _collect(context, candidate.exchanges)
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded probes and the scan context. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on each SSRF candidate. One verdict per unique path."""
        exchanges = list(evidence)
        candidates = _collect(ctx.context, exchanges)
        ids = [e.id for e in exchanges]
        verdicts: list[Verdict] = []

        for candidate in candidates:
            path = candidate["path"]
            param = candidate.get("param", "unknown")
            source = candidate.get("source", "unknown")

            if param in ACTION_PARAMS:
                severity = "medium"
                title = f"SSRF candidate: {ctx.host}{path} accepts '{param}' parameter"
            elif source == "openapi":
                severity = "medium"
                title = (
                    f"SSRF candidate: {ctx.host}{path} accepts URL parameter '{param}' "
                    "(from OpenAPI spec)"
                )
            else:
                severity = "low"
                title = f"URL parameter detected: {ctx.host}{path} (potential SSRF)"

            confidence, why = _source_confidence(source, param)
            # Match the probe exchange for this path, so the verdict binds to the
            # bytes it came from; context-sourced candidates bind to all probes.
            match = next((e for e in exchanges if _path_of(e) == path), None)

            verdicts.append(
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator=f"ssrf-{path.replace('/', '-').strip('-')}-{param}",
                    title=title,
                    description=(
                        f"Endpoint at {path} accepts URL-like parameter '{param}', which "
                        "may be vulnerable to SSRF"
                    ),
                    evidence=candidate.get("evidence", f"Parameter '{param}' at {path}"),
                    reasoning=f"{why}; a candidate only — no SSRF request was attempted",
                    signals={"path": path, "param": param, "source": source},
                    references=["CWE-918", "OWASP WSTG-INPV-19"],
                    evidence_ids=[match.id] if match is not None else ids,
                )
            )

        return verdicts


# ── The one collector, called by both halves ─────────────────────────


def _collect(context: dict[str, Any], exchanges: list[Exchange]) -> list[dict]:
    """Every SSRF candidate from all three sources, deduplicated by path.

    The single parser behind §6.2's two reads: `check_service()` calls it to
    populate `ssrf_candidates`, and `grade()` calls it to place the verdicts.
    Source order (openapi, discovered, probe) and first-path-wins match the
    original, because that determines which source is attributed to a path.
    """
    context = context or {}
    candidates: list[dict] = []
    candidates.extend(_openapi_candidates(context))
    candidates.extend(_discovered_candidates(context))
    candidates.extend(_probe_candidates(exchanges))

    seen_paths: set[str] = set()
    unique: list[dict] = []
    for c in candidates:
        if c["path"] not in seen_paths:
            seen_paths.add(c["path"])
            unique.append(c)
    return unique


def _openapi_candidates(context: dict[str, Any]) -> list[dict]:
    """Check OpenAPI spec for URL-accepting parameters."""
    candidates = []
    openapi_spec = context.get("openapi_spec")
    if not openapi_spec or not isinstance(openapi_spec, dict):
        return candidates

    paths = openapi_spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.startswith("x-") or not isinstance(operation, dict):
                continue

            # Check parameters
            params = operation.get("parameters", [])
            for param in params:
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "").lower()
                fmt = (
                    param.get("schema", {}).get("format", "").lower()
                    if isinstance(param.get("schema"), dict)
                    else ""
                )

                if name in URL_PARAM_NAMES or fmt in OPENAPI_URL_INDICATORS:
                    candidates.append(
                        {
                            "path": path,
                            "param": param.get("name", name),
                            "source": "openapi",
                            "method": method.upper(),
                            "evidence": (
                                f"OpenAPI spec: {method.upper()} {path} parameter "
                                f"'{param.get('name', name)}' (format: {fmt or 'string'})"
                            ),
                        }
                    )

            # Check request body schema for URL fields
            req_body = operation.get("requestBody", {})
            if isinstance(req_body, dict):
                content = req_body.get("content", {})
                for _media_type, media_obj in content.items():
                    if not isinstance(media_obj, dict):
                        continue
                    schema = media_obj.get("schema", {})
                    if isinstance(schema, dict):
                        props = schema.get("properties", {})
                        for prop_name, prop_schema in props.items():
                            if not isinstance(prop_schema, dict):
                                continue
                            name_lower = prop_name.lower()
                            fmt = prop_schema.get("format", "").lower()
                            if name_lower in URL_PARAM_NAMES or fmt in OPENAPI_URL_INDICATORS:
                                candidates.append(
                                    {
                                        "path": path,
                                        "param": prop_name,
                                        "source": "openapi",
                                        "method": method.upper(),
                                        "evidence": (
                                            f"OpenAPI spec: {method.upper()} {path} body "
                                            f"field '{prop_name}' (format: {fmt or 'string'})"
                                        ),
                                    }
                                )

    return candidates


def _discovered_candidates(context: dict[str, Any]) -> list[dict]:
    """Check paths from path_probe or sitemap for URL query parameters."""
    candidates = []

    for key in ("discovered_paths", "sitemap_paths"):
        data = context.get(key, {})
        if isinstance(data, dict):
            all_paths = data.get("all_paths", [])
        elif isinstance(data, list):
            all_paths = data
        else:
            continue

        for path in all_paths:
            parsed = urlparse(path)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params:
                    if param_name.lower() in URL_PARAM_NAMES:
                        candidates.append(
                            {
                                "path": parsed.path,
                                "param": param_name,
                                "source": "discovered",
                                "evidence": (
                                    f"URL parameter '{param_name}' found in discovered path: {path}"
                                ),
                            }
                        )

    return candidates


def _probe_candidates(exchanges: list[Exchange]) -> list[dict]:
    """Read SSRF candidates out of the recorded probes of the prone paths."""
    candidates = []
    for exchange in exchanges:
        if exchange.error is not None or exchange.response_status not in PROBE_ACCEPT_CODES:
            continue
        body = (exchange.response_body or "").lower()
        if _body_suggests_url_param(body, exchange.response_status):
            path = _path_of(exchange)
            param_hint = _extract_param_hint(body)
            candidates.append(
                {
                    "path": path,
                    "param": param_hint or "unknown",
                    "source": "probe",
                    "evidence": f"GET {path} -> HTTP {exchange.response_status}",
                }
            )
    return candidates


def _source_confidence(source: str, param: str) -> tuple[float, str]:
    """How much the evidence establishes that the parameter takes a URL."""
    if source == "openapi":
        return 0.8, (
            f"the OpenAPI spec declares '{param}', so the parameter is real and URL-shaped"
        )
    if source == "discovered":
        return 0.75, (f"'{param}' was seen in a real query string on a discovered path")
    # probe
    return 0.5, (
        "an SSRF-prone path responded and its body mentions a URL field — a heuristic "
        "read that a generic validation error also produces"
    )


def _body_suggests_url_param(body: str, status_code: int) -> bool:
    """Check if response body suggests the endpoint expects a URL parameter."""
    if status_code in (400, 422):
        # Validation error mentioning URL-like parameters
        for param in URL_PARAM_NAMES[:15]:  # Check most common
            if param in body:
                return True
        # Check for "required" + url-like field mentions
        if "required" in body and ("url" in body or "uri" in body):
            return True
    elif status_code == 200:
        # Form with URL input
        if re.search(r'type=["\']url["\']', body):
            return True
        if re.search(r'name=["\']url["\']', body):
            return True
    return False


def _extract_param_hint(body: str) -> str | None:
    """Try to extract the expected parameter name from error response."""
    for param in URL_PARAM_NAMES[:15]:
        if param in body:
            return param
    return None


def _path_of(exchange: Exchange) -> str:
    """The path this probe asked for, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"
