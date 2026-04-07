"""
app/checks/web/ssrf_indicator.py - SSRF Indicator Detection

Identifies endpoints that accept URL parameters — classic SSRF candidates,
especially common in AI services that process documents, images, or fetch
external content.

This check identifies candidates only. It does NOT attempt actual SSRF
exploitation (no callback, no internal IP probing).
"""

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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


class SSRFIndicatorCheck(ServiceIteratingCheck):
    """Identify endpoints with URL-accepting parameters (SSRF candidates)."""

    name = "ssrf_indicator"
    description = "Detect parameters that accept URLs — potential SSRF vectors"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["ssrf_candidates"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 60.0
    delay_between_targets = 0.2

    reason = (
        "AI services frequently accept URLs for document processing, creating classic SSRF vectors"
    )
    references = ["OWASP WSTG-INPV-19", "CWE-918"]
    techniques = ["SSRF candidate identification", "parameter analysis"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        candidates: list[dict[str, Any]] = []

        # 1. Check OpenAPI spec for URL-accepting parameters
        openapi_candidates = self._check_openapi(service, context)
        candidates.extend(openapi_candidates)

        # 2. Check discovered paths for URL parameters in query strings
        path_candidates = self._check_discovered_paths(service, context)
        candidates.extend(path_candidates)

        # 3. Probe known SSRF-prone paths
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in SSRF_PRONE_PATHS:
                    await self._rate_limit()
                    resp = await client.get(service.with_path(path))
                    if resp.error:
                        continue

                    # A 200 or 400/422 (validation error) suggests the endpoint exists
                    if resp.status_code in (200, 400, 405, 422):
                        # Check if response hints at URL parameter expectation
                        body = (resp.body or "").lower()
                        if self._body_suggests_url_param(body, resp.status_code):
                            param_hint = self._extract_param_hint(body)
                            candidates.append(
                                {
                                    "path": path,
                                    "param": param_hint or "unknown",
                                    "source": "probe",
                                    "evidence": f"GET {path} -> HTTP {resp.status_code}",
                                }
                            )
        except Exception as e:
            result.errors.append(f"SSRF probe error: {e}")

        # Deduplicate by path
        seen_paths = set()
        unique_candidates = []
        for c in candidates:
            if c["path"] not in seen_paths:
                seen_paths.add(c["path"])
                unique_candidates.append(c)
        candidates = unique_candidates

        # Generate observations
        for candidate in candidates:
            path = candidate["path"]
            param = candidate.get("param", "unknown")
            source = candidate.get("source", "unknown")

            if param in ("proxy", "forward", "fetch", "download"):
                severity = "medium"
                title = f"SSRF candidate: {service.host}{path} accepts '{param}' parameter"
            elif source == "openapi":
                severity = "medium"
                title = f"SSRF candidate: {service.host}{path} accepts URL parameter '{param}' (from OpenAPI spec)"
            else:
                severity = "low"
                title = f"URL parameter detected: {service.host}{path} (potential SSRF)"

            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=title,
                    description=f"Endpoint at {path} accepts URL-like parameter '{param}', which may be vulnerable to SSRF",
                    severity=severity,
                    evidence=candidate.get("evidence", f"Parameter '{param}' at {path}"),
                    host=service.host,
                    discriminator=f"ssrf-{path.replace('/', '-').strip('-')}-{param}",
                    target=service,
                    target_url=service.with_path(path),
                    references=["CWE-918", "OWASP WSTG-INPV-19"],
                )
            )

        result.outputs["ssrf_candidates"] = candidates
        return result

    def _check_openapi(self, service: Service, context: dict[str, Any]) -> list[dict]:
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
                                "evidence": f"OpenAPI spec: {method.upper()} {path} parameter '{param.get('name', name)}' (format: {fmt or 'string'})",
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
                                            "evidence": f"OpenAPI spec: {method.upper()} {path} body field '{prop_name}' (format: {fmt or 'string'})",
                                        }
                                    )

        return candidates

    def _check_discovered_paths(self, service: Service, context: dict[str, Any]) -> list[dict]:
        """Check paths from path_probe or sitemap for URL query parameters."""
        candidates = []

        # Check various path sources
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
                                    "evidence": f"URL parameter '{param_name}' found in discovered path: {path}",
                                }
                            )

        return candidates

    def _body_suggests_url_param(self, body: str, status_code: int) -> bool:
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

    def _extract_param_hint(self, body: str) -> str | None:
        """Try to extract the expected parameter name from error response."""
        for param in URL_PARAM_NAMES[:15]:
            if param in body:
                return param
        return None
