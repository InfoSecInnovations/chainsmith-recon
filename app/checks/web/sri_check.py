"""
app/checks/web/sri_check.py - Subresource Integrity Check

Parses HTML responses for <script> and <link> tags that load external
resources, and checks whether they have integrity= attributes (SRI
hashes). External resources without SRI are vulnerable to CDN
compromise or supply-chain attacks.
"""

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

# Match <script src="..."> tags
SCRIPT_TAG_PATTERN = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.I,
)

# Match <link rel="stylesheet" href="..."> tags
LINK_TAG_PATTERN = re.compile(
    r"<link\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.I,
)

# Match integrity attribute in a tag
INTEGRITY_ATTR_PATTERN = re.compile(
    r"\bintegrity\s*=\s*[\"']([^\"']+)[\"']",
    re.I,
)

# Match crossorigin attribute
CROSSORIGIN_PATTERN = re.compile(
    r"\bcrossorigin\b",
    re.I,
)

# Paths to check for HTML content
HTML_PATHS = ["/", "/index.html", "/login", "/app"]


class SRICheck(ServiceIteratingCheck):
    """Check external scripts and stylesheets for Subresource Integrity."""

    name = "sri_check"
    description = "Verify external resources use Subresource Integrity (SRI) hashes"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["sri_info"]
    service_types = ["http", "html"]

    timeout_seconds = 30.0
    delay_between_targets = 0.2

    reason = (
        "External scripts without SRI are vulnerable to CDN compromise and supply-chain attacks"
    )
    references = ["W3C Subresource Integrity", "CWE-353"]
    techniques = ["SRI verification", "supply chain analysis"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        external_without_sri: list[dict[str, str]] = []
        external_with_sri: list[dict[str, str]] = []
        total_external = 0

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                pages_checked = 0
                seen_bodies = set()
                for path in HTML_PATHS:
                    if pages_checked >= 2:
                        break

                    await self._rate_limit()
                    resp = await client.get(service.with_path(path))
                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    # Only analyze HTML responses
                    content_type = resp.headers.get("content-type", "").lower()
                    if "html" not in content_type and not resp.body.strip().startswith("<"):
                        continue

                    # Deduplicate identical pages (e.g., / and /index.html serve same content)
                    body_hash = hash(resp.body)
                    if body_hash in seen_bodies:
                        continue
                    seen_bodies.add(body_hash)

                    pages_checked += 1
                    self._analyze_html(
                        resp.body,
                        service,
                        path,
                        external_without_sri,
                        external_with_sri,
                    )

                total_external = len(external_without_sri) + len(external_with_sri)

        except Exception as e:
            result.errors.append(f"SRI check error: {e}")

        # Generate findings
        if external_without_sri:
            # Group by host to reduce noise
            hosts_without_sri = set()
            for resource in external_without_sri:
                parsed = urlparse(resource["url"])
                hosts_without_sri.add(parsed.netloc)

            count = len(external_without_sri)
            severity = "medium" if count >= 3 else "low"

            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"{count} external resource(s) without SRI: {service.host}",
                    description=f"{count} external scripts/stylesheets loaded without integrity verification. "
                    f"Sources: {', '.join(sorted(hosts_without_sri)[:5])}",
                    severity=severity,
                    evidence=" | ".join(
                        f"{r['type']}: {r['url']}" for r in external_without_sri[:10]
                    ),
                    host=service.host,
                    discriminator="missing-sri",
                    target=service,
                    references=["CWE-353", "W3C SRI"],
                )
            )

            # Individual findings for the first few
            for resource in external_without_sri[:5]:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title=f"External {resource['type']} without SRI: {resource['url'][:80]}",
                        description=f"External {resource['type']} loaded from {resource['url']} without an integrity attribute",
                        severity="low",
                        evidence=f'<{resource["type"]} src="{resource["url"]}"> on {resource["page"]} — no integrity= attribute',
                        host=service.host,
                        discriminator=f"no-sri-{_url_slug(resource['url'])}",
                        target=service,
                        target_url=service.with_path(resource["page"]),
                        references=["CWE-353"],
                    )
                )
        elif total_external > 0:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"All external resources use SRI: {service.host}",
                    description=f"All {total_external} external resource(s) have integrity attributes",
                    severity="info",
                    evidence=f"{total_external} external resources with SRI hashes verified",
                    host=service.host,
                    discriminator="all-sri",
                    target=service,
                )
            )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"No external resources found: {service.host}",
                    description="No external scripts or stylesheets detected in HTML responses",
                    severity="info",
                    evidence="No <script src> or <link href> tags referencing external origins",
                    host=service.host,
                    discriminator="no-external",
                    target=service,
                )
            )

        result.outputs["sri_info"] = {
            "total_external": total_external,
            "without_sri": len(external_without_sri),
            "with_sri": len(external_with_sri),
            "resources_without_sri": external_without_sri[:20],
        }
        return result

    def _analyze_html(
        self,
        html: str,
        service: Service,
        page_path: str,
        without_sri: list[dict[str, str]],
        with_sri: list[dict[str, str]],
    ) -> None:
        """Parse HTML and categorize external resources by SRI status."""
        service_origin = f"{service.scheme}://{service.host}"

        # Check <script> tags
        for match in SCRIPT_TAG_PATTERN.finditer(html):
            src = match.group(1)
            if not self._is_external(src, service_origin):
                continue

            tag_text = match.group(0)
            has_integrity = bool(INTEGRITY_ATTR_PATTERN.search(tag_text))

            entry = {"url": src, "type": "script", "page": page_path}
            if has_integrity:
                with_sri.append(entry)
            else:
                without_sri.append(entry)

        # Check <link> tags (stylesheets only)
        for match in LINK_TAG_PATTERN.finditer(html):
            href = match.group(1)
            tag_text = match.group(0)

            # Only consider stylesheet links
            if "rel=" not in tag_text.lower() or "stylesheet" not in tag_text.lower():
                continue

            if not self._is_external(href, service_origin):
                continue

            has_integrity = bool(INTEGRITY_ATTR_PATTERN.search(tag_text))

            entry = {"url": href, "type": "stylesheet", "page": page_path}
            if has_integrity:
                with_sri.append(entry)
            else:
                without_sri.append(entry)

    def _is_external(self, url: str, service_origin: str) -> bool:
        """Check if a URL points to an external origin."""
        if url.startswith("//"):
            return True  # Protocol-relative, likely external
        if url.startswith("http"):
            parsed = urlparse(url)
            resource_origin = f"{parsed.scheme}://{parsed.hostname}"
            return resource_origin.lower() != service_origin.lower()
        # Relative URLs are internal
        return False


def _url_slug(url: str) -> str:
    """Create a short slug from a URL for finding discriminators."""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    # Take just the host and first path segment
    path_part = parsed.path.split("/")[1] if "/" in parsed.path.lstrip("/") else ""
    slug = f"{host}-{path_part}".strip("-")
    # Sanitize
    slug = re.sub(r"[^a-zA-Z0-9\-.]", "-", slug)
    return slug[:40]
