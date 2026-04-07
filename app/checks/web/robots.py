"""
app/checks/web/robots.py - Robots.txt Analysis

Fetch and analyze robots.txt for sensitive path disclosure.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig


class RobotsTxtCheck(ServiceIteratingCheck):
    """Fetch and analyze robots.txt for sensitive path disclosure."""

    name = "robots_txt"
    description = "Retrieve robots.txt and identify potentially sensitive paths"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["robots_paths"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 30.0
    delay_between_targets = 0.2

    reason = "robots.txt often reveals hidden paths that admins want to keep from search engines"
    references = ["OWASP WSTG-INFO-03", "RFC 9309"]
    techniques = ["passive reconnaissance", "path discovery"]

    INTERESTING_PATTERNS = [
        r"admin",
        r"internal",
        r"api",
        r"debug",
        r"config",
        r"backup",
        r"private",
        r"secret",
        r"model",
        r"ml",
        r"ai",
        r"data",
        r"v2",
        r"v3",
        r"stage",
        r"dev",
        r"\.git",
        r"\.env",
        r"\.bak",
        r"inference",
        r"prompt",
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        robots_url = service.with_path("/robots.txt")
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                resp = await client.get(robots_url)

            if resp.error or resp.status_code != 200:
                return result

            content = resp.body
            disallowed = []
            interesting = []
            sitemaps = []

            for line in content.split("\n"):
                line = line.strip()
                line_lower = line.lower()

                if line_lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                        for pattern in self.INTERESTING_PATTERNS:
                            if re.search(pattern, path, re.I):
                                interesting.append(path)
                                break

                elif line_lower.startswith("sitemap:"):
                    sitemap = line.split(":", 1)[1].strip()
                    sitemaps.append(sitemap)

            if interesting:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Sensitive paths in robots.txt ({len(interesting)})",
                        description="robots.txt reveals potentially sensitive paths",
                        severity="low",
                        evidence=f"Interesting Disallow paths: {', '.join(interesting[:10])}",
                        host=service.host,
                        discriminator="sensitive-paths",
                        target=service,
                        target_url=robots_url,
                        raw_data={"disallowed": disallowed, "interesting": interesting},
                    )
                )

            if sitemaps:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Sitemaps disclosed ({len(sitemaps)})",
                        description="robots.txt reveals sitemap locations",
                        severity="info",
                        evidence=f"Sitemaps: {', '.join(sitemaps[:5])}",
                        host=service.host,
                        discriminator="sitemaps-disclosed",
                        target=service,
                        target_url=robots_url,
                    )
                )

            result.outputs[f"robots_{service.port}"] = {
                "disallowed": disallowed,
                "interesting": interesting,
                "sitemaps": sitemaps,
            }

        except Exception as e:
            result.errors.append(f"{robots_url}: {e}")

        return result
