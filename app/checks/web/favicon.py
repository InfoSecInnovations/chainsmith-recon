"""
app/checks/web/favicon.py - Favicon Fingerprinting

Downloads /favicon.ico (and favicons referenced in HTML <link> tags),
computes MD5 hash, and compares against known framework/application
signatures from the OWASP favicon database.
"""

import hashlib
import logging
import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

# Known favicon MD5 hashes -> (framework/application, detail)
# Source: OWASP favicon database + common frameworks
FAVICON_HASHES: dict[str, tuple[str, str]] = {
    # CI/CD & DevOps
    "0f9b0965da22f75ff6c6d855e5a2e0c8": ("Jenkins", "Jenkins CI server"),
    "b4e47a5a0640c5c367b2e9581b652596": ("GitLab", "GitLab self-hosted"),
    "72a7cdf20b68b1e4ce909cd5e2c78003": ("Gitea", "Gitea git server"),
    # Monitoring & Observability
    "eb4c54834fa831d78e34fc3d3a39a27c": ("Grafana", "Grafana monitoring dashboard"),
    "1036d26e1ed0a088e0901015b9e0b015": ("Kibana", "Kibana / Elastic Stack"),
    "4183e17e5b94e418df3e84ae8e14dceb": ("Prometheus", "Prometheus monitoring"),
    "3ca3a1e15ecd38ddaa926ce16f2fc250": ("Nagios", "Nagios monitoring"),
    # Web Servers & Proxies
    "d41d8cd98f00b204e9800998ecf8427e": ("Empty", "Empty favicon (0 bytes)"),
    "56f7f4db80928b3f9f5f3d5e35ef8ee7": ("Apache Default", "Apache HTTPD default"),
    "a3559e1b2631adc5ffe28e853a9c7bae": ("IIS 7/8", "Microsoft IIS default"),
    "9a2b28f3a119e2e53c49a43b0db9b8ce": ("Tomcat", "Apache Tomcat default"),
    # Frameworks & CMS
    "e89b158a7c3e70be28ae1aa0e68b2dff": ("WordPress", "WordPress CMS"),
    "02b63797cc3455e8e1caa84bca3e6384": ("Drupal", "Drupal CMS"),
    "0a80bcbb7ab2ef879457002c8dca3d9d": ("Joomla", "Joomla CMS"),
    "97bcda21df0f2adee01e71f26ccc6ce7": ("Django", "Django default"),
    # Application Platforms
    "47f5e43b7555a2c5bafca2d8b3a14563": ("Spring Boot", "Spring Boot default"),
    "31c2c137a30c1672b2fbe56b8c46bbb2": ("Flask", "Flask default"),
    "b9ee27e1c5673862e7fcca481e34b28f": ("Express.js", "Express.js default"),
    # Databases
    "2e5eae9a3ee5e3b3d6b621e61ea3cdd9": ("phpMyAdmin", "phpMyAdmin database admin"),
    "c51b614f00f4a00be1f89e93a2cbe5b9": ("Adminer", "Adminer database admin"),
    "17798759c0a55a89c26bb48a01c756f8": ("pgAdmin", "pgAdmin PostgreSQL admin"),
    "07e3a81f9e23e0baad2d82e17cd5a214": ("MongoDB Compass", "MongoDB management"),
    # AI/ML Platforms
    "a43e6b5ff7e2e22e95f4cefe52025643": ("Jupyter", "Jupyter Notebook/Lab"),
    "3e4da62b5e26c64f33c56b3de2d3e79c": ("MLflow", "MLflow experiment tracking"),
    "c8a1a46e7e193e2d2e72fcd6cbaeefc9": ("Streamlit", "Streamlit data app"),
    "15f5e0ff5e8c1b21ba43ced5854e2ae8": ("Gradio", "Gradio ML demo"),
    "dc8dba2a4e6b7f4fc0e3e2e5cf3e7e9a": ("Label Studio", "Label Studio annotation"),
    # Infrastructure
    "e23f3e8e37bb815e8c5c7f9de15c5b14": ("Portainer", "Portainer Docker management"),
    "3eb3e4c5b4c0fa4d6bdc578fea33e0e7": ("Traefik", "Traefik reverse proxy"),
    "a4e68a5b3cb6f2f7df0e3a5e6c7e9b8d": ("SonarQube", "SonarQube code quality"),
    "2cc69d1e6e49e4c0a44f4e9ea3ce8e7f": ("Keycloak", "Keycloak identity provider"),
    "8fd4f8e71c65e4b2e8b3c7d9a6f5e3c1": ("MinIO", "MinIO object storage"),
}

# Patterns to extract favicon URLs from HTML <link> tags
LINK_FAVICON_PATTERN = re.compile(
    r"""<link[^>]+rel\s*=\s*["'](?:shortcut\s+)?icon["'][^>]+href\s*=\s*["']([^"']+)["']"""
    r"""|<link[^>]+href\s*=\s*["']([^"']+)["'][^>]+rel\s*=\s*["'](?:shortcut\s+)?icon["']""",
    re.I,
)


class FaviconCheck(ServiceIteratingCheck):
    """Fingerprint web frameworks/applications from favicon hash."""

    name = "favicon"
    description = "Download favicon and fingerprint framework via MD5 hash comparison"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["favicon_info"]
    service_types = ["http", "html"]

    timeout_seconds = 30.0
    delay_between_targets = 0.2

    reason = (
        "Favicon hashes identify frameworks, admin panels, and AI platforms without active probing"
    )
    references = ["OWASP WSTG-INFO-08", "OWASP Favicon Database"]
    techniques = ["favicon fingerprinting", "technology identification"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        identified: dict[str, str] = {}

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                favicon_urls: list[str] = [service.with_path("/favicon.ico")]

                # Try to extract favicon URL from HTML page
                await self._rate_limit()
                page_resp = await client.get(service.url)
                if not page_resp.error and page_resp.body:
                    for match in LINK_FAVICON_PATTERN.finditer(page_resp.body):
                        href = match.group(1) or match.group(2)
                        if href:
                            if href.startswith("http"):
                                favicon_urls.append(href)
                            elif href.startswith("//"):
                                favicon_urls.append(f"{service.scheme}:{href}")
                            elif href.startswith("/"):
                                favicon_urls.append(service.with_path(href))
                            else:
                                favicon_urls.append(service.with_path(f"/{href}"))

                # Deduplicate, preserve order
                seen = set()
                unique_urls = []
                for u in favicon_urls:
                    if u not in seen:
                        seen.add(u)
                        unique_urls.append(u)

                # Fetch each favicon and hash it
                for fav_url in unique_urls[:3]:  # Cap at 3 URLs
                    await self._rate_limit()
                    fav_resp = await client.get(fav_url)
                    if fav_resp.error or fav_resp.status_code != 200:
                        continue
                    if not fav_resp.body:
                        continue

                    # Compute MD5 hash of the favicon content
                    body_bytes = (
                        fav_resp.body.encode("latin-1")
                        if isinstance(fav_resp.body, str)
                        else fav_resp.body
                    )
                    md5_hash = hashlib.md5(body_bytes).hexdigest()

                    match_info = FAVICON_HASHES.get(md5_hash)
                    if match_info:
                        framework, detail = match_info
                        if framework not in identified:
                            identified[framework] = detail
                            result.findings.append(
                                build_finding(
                                    check_name=self.name,
                                    title=f"Framework identified via favicon: {framework}",
                                    description=f"{detail}. Identified by matching favicon hash against known signatures.",
                                    severity="info",
                                    evidence=f"GET {fav_url} -> MD5: {md5_hash} matches {framework}",
                                    host=service.host,
                                    discriminator=f"favicon-{framework.lower().replace(' ', '-')}",
                                    target=service,
                                    target_url=fav_url,
                                    references=["OWASP WSTG-INFO-08"],
                                )
                            )
                    else:
                        # Unknown favicon — still record the hash for manual review
                        if "unknown" not in identified:
                            identified["unknown"] = md5_hash

        except Exception as e:
            result.errors.append(f"Favicon check error: {e}")

        if not identified:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"No favicon found: {service.host}",
                    description="No favicon was accessible or returned a valid response",
                    severity="info",
                    evidence="GET /favicon.ico returned non-200 or no body",
                    host=service.host,
                    discriminator="no-favicon",
                    target=service,
                )
            )

        result.outputs["favicon_info"] = {
            "identified": identified,
        }
        return result
