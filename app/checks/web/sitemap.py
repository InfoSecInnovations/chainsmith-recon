"""
app/checks/web/sitemap.py - Sitemap Parsing Check

Fetches sitemaps discovered by RobotsTxtCheck (or tries default /sitemap.xml).
Parses XML sitemap format, extracts URLs, identifies interesting paths that
the fixed wordlist in PathProbe would miss.

Handles:
- Standard XML sitemaps (urlset format)
- Sitemap index files (sitemapindex)
- Caps at 500 URLs to avoid overwhelming downstream checks
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

MAX_URLS = 500
MAX_SITEMAPS = 10  # max sub-sitemaps to follow from index

# Paths that suggest sensitive or internal content
SENSITIVE_PATH_PATTERNS = [
    re.compile(r"/(admin|internal|staging|debug|test|dev)/", re.I),
    re.compile(r"/(api|graphql|v\d+)/", re.I),
    re.compile(r"/\.(env|git|svn|config)", re.I),
    re.compile(r"/(dashboard|console|manager|portal)/", re.I),
    re.compile(r"/(backup|dump|export|import)/", re.I),
    re.compile(r"/(model|train|inference|predict)/", re.I),
]


class SitemapCheck(ServiceIteratingCheck):
    """Parse sitemaps to discover additional paths and surface structure."""

    name = "sitemap"
    description = "Parse sitemap.xml to discover paths missed by wordlist probing"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["sitemap_paths"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.2

    reason = "Sitemaps reveal full URL structure including internal tools, API versioning, and AI/ML endpoints"
    references = ["OWASP WSTG-INFO-03"]
    techniques = ["passive reconnaissance", "path discovery"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Get sitemap URLs from robots_txt output
        robots_key = f"robots_{service.port}"
        robots_data = context.get(robots_key, {})
        sitemaps = list(robots_data.get("sitemaps", []))

        # Always try default location if robots didn't find any
        if not sitemaps:
            sitemaps = [service.with_path("/sitemap.xml")]
        else:
            # Normalize: robots may give relative or absolute URLs
            normalized = []
            for s in sitemaps:
                if s.startswith("http://") or s.startswith("https://"):
                    normalized.append(s)
                else:
                    path = s if s.startswith("/") else f"/{s}"
                    normalized.append(service.with_path(path))
            sitemaps = normalized

        all_paths: list[str] = []
        sensitive_paths: list[str] = []
        api_paths: list[str] = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for sitemap_url in sitemaps[:MAX_SITEMAPS]:
                    await self._rate_limit()
                    resp = await client.get(sitemap_url)

                    if resp.error or resp.status_code != 200:
                        continue

                    body = resp.body or ""
                    if not body.strip():
                        continue

                    # Check if this is a sitemap index
                    sub_sitemaps = self._parse_sitemap_index(body)
                    if sub_sitemaps:
                        # Follow sub-sitemaps (limited)
                        for sub_url in sub_sitemaps[:MAX_SITEMAPS]:
                            if not sub_url.startswith("http"):
                                sub_url = service.with_path(
                                    sub_url if sub_url.startswith("/") else f"/{sub_url}"
                                )
                            await self._rate_limit()
                            sub_resp = await client.get(sub_url)
                            if sub_resp.error or sub_resp.status_code != 200:
                                continue
                            paths = self._extract_paths(sub_resp.body or "", service.host)
                            all_paths.extend(paths)
                            if len(all_paths) >= MAX_URLS:
                                break
                    else:
                        paths = self._extract_paths(body, service.host)
                        all_paths.extend(paths)

                    if len(all_paths) >= MAX_URLS:
                        all_paths = all_paths[:MAX_URLS]
                        break

        except Exception as e:
            result.errors.append(f"Sitemap fetch error: {e}")
            return result

        if not all_paths:
            return result

        # Deduplicate
        all_paths = list(dict.fromkeys(all_paths))

        # Classify paths
        for path in all_paths:
            for pattern in SENSITIVE_PATH_PATTERNS:
                if pattern.search(path):
                    sensitive_paths.append(path)
                    break
            if re.search(r"/(api|v\d+)/", path, re.I):
                api_paths.append(path)

        # Base finding: sitemap discovered
        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"Sitemap contains {len(all_paths)} URLs ({len(set(all_paths))} unique paths)",
                description=f"Sitemap parsing discovered {len(all_paths)} URLs from {service.host}",
                severity="info",
                evidence=f"Paths sample: {', '.join(all_paths[:10])}",
                host=service.host,
                discriminator="sitemap-discovered",
                target=service,
            )
        )

        # Sensitive paths finding
        if sensitive_paths:
            severity = (
                "medium"
                if any(
                    re.search(r"/(staging|debug|internal|backup)/", p, re.I)
                    for p in sensitive_paths
                )
                else "low"
            )
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Sitemap reveals sensitive paths ({len(sensitive_paths)})",
                    description="Sitemap contains paths suggesting internal or sensitive resources",
                    severity=severity,
                    evidence=f"Sensitive paths: {', '.join(sensitive_paths[:10])}",
                    host=service.host,
                    discriminator="sensitive-paths",
                    target=service,
                    raw_data={"sensitive_paths": sensitive_paths[:50]},
                )
            )

        # API versioning finding
        api_versions = set()
        for p in api_paths:
            m = re.search(r"/v(\d+)/", p, re.I)
            if m:
                api_versions.add(f"v{m.group(1)}")
        if len(api_versions) > 1:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Sitemap reveals API versioning: {', '.join(sorted(api_versions))}",
                    description="Multiple API versions discovered, older versions may lack security controls",
                    severity="low",
                    evidence=f"API versions: {', '.join(sorted(api_versions))}; sample paths: {', '.join(api_paths[:5])}",
                    host=service.host,
                    discriminator="api-versioning",
                    target=service,
                )
            )

        # Output for downstream checks
        result.outputs["sitemap_paths"] = {
            "all_paths": all_paths,
            "sensitive_paths": sensitive_paths,
            "api_paths": api_paths,
        }

        return result

    def _extract_paths(self, xml_body: str, target_host: str) -> list[str]:
        """Parse sitemap XML and extract paths from <loc> elements."""
        paths = []
        try:
            root = ET.fromstring(xml_body)
            # Handle namespace
            # Try with namespace
            locs = root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
            if not locs:
                # Try without namespace
                locs = root.findall(".//loc")
            for loc in locs:
                if loc.text:
                    parsed = urlparse(loc.text.strip())
                    path = parsed.path or "/"
                    paths.append(path)
        except ET.ParseError:
            logger.debug("Failed to parse sitemap XML")
        return paths

    def _parse_sitemap_index(self, xml_body: str) -> list[str]:
        """Check if XML is a sitemap index and extract sub-sitemap URLs."""
        urls = []
        try:
            root = ET.fromstring(xml_body)
            # Sitemap index has <sitemapindex> root with <sitemap><loc> children
            tag = root.tag.lower()
            if "sitemapindex" not in tag:
                return []
            ns_uri = "http://www.sitemaps.org/schemas/sitemap/0.9"
            locs = root.findall(f".//{{{ns_uri}}}loc")
            if not locs:
                locs = root.findall(".//loc")
            for loc in locs:
                if loc.text:
                    urls.append(loc.text.strip())
        except ET.ParseError:
            pass
        return urls
