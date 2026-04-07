"""
app/checks/web/paths.py - Path Discovery

Probe for common paths, admin interfaces, and sensitive endpoints.
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.evidence import fmt_endpoint_evidence
from app.lib.observations import make_observation_id_hashed
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict


class PathProbeCheck(ServiceIteratingCheck):
    """Probe for common sensitive paths and admin interfaces."""

    name = "path_probe"
    description = "Check for common admin panels, config files, and sensitive endpoints"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["discovered_paths"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 90.0
    requests_per_second = 5.0
    delay_between_targets = 0.5

    reason = "Common paths often lead to admin panels, backups, or configuration files"
    references = ["OWASP WSTG-CONF-05", "CWE-538"]
    techniques = ["directory enumeration", "forced browsing", "path traversal"]

    COMMON_PATHS = [
        # Admin
        "/admin",
        "/admin/",
        "/administrator",
        "/admin.php",
        "/wp-admin",
        "/manager",
        "/console",
        "/dashboard",
        # Config/Debug
        "/.env",
        "/config.json",
        "/config.yaml",
        "/settings.json",
        "/debug",
        "/phpinfo.php",
        "/server-status",
        "/health",
        # Git/VCS
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        # Backups
        "/backup",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        # API
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        # AI/ML specific
        "/model",
        "/models",
        "/inference",
        "/predict",
        "/v1/models",
        "/api/models",
        "/embeddings",
        # Metrics/monitoring
        "/metrics",
        "/prometheus",
        "/actuator",
        "/actuator/health",
        # Common
        "/.well-known/",
        "/static/",
        "/assets/",
    ]

    # Paths that warrant higher severity
    HIGH_SEVERITY_PATTERNS = [".env", ".git", "backup.sql", "db.sql", "database.sql"]
    MEDIUM_SEVERITY_PATTERNS = [
        "config",
        "backup",
        "admin",
        "debug",
        "model",
        "inference",
        "predict",
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        accessible = []
        forbidden = []
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False, follow_redirects=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.COMMON_PATHS:
                    await self._rate_limit()
                    url = service.with_path(path)

                    resp = await client.get(url)
                    if resp.error:
                        continue

                    headers_lower = extract_headers_dict(resp.headers)
                    content_type = headers_lower.get("content-type", "")

                    if resp.status_code == 200:
                        accessible.append(path)

                        severity = "info"
                        path_lower = path.lower()
                        if any(s in path_lower for s in self.HIGH_SEVERITY_PATTERNS):
                            severity = "high"
                        elif any(s in path_lower for s in self.MEDIUM_SEVERITY_PATTERNS):
                            severity = "medium"

                        # Use hashed ID since many paths may hit the same host
                        observation_id = make_observation_id_hashed(
                            self.name, service.host, "accessible", path
                        )
                        from app.checks.base import Observation

                        result.observations.append(
                            Observation(
                                id=observation_id,
                                title=f"Accessible path: {path}",
                                description=f"Path {path} returned HTTP 200",
                                severity=severity,
                                evidence=fmt_endpoint_evidence(url, resp.status_code, content_type),
                                target=service,
                                target_url=url,
                                check_name=self.name,
                            )
                        )

                    elif resp.status_code == 403:
                        forbidden.append(path)
                        path_lower = path.lower()
                        if any(s in path_lower for s in ["admin", "config", "internal", "debug"]):
                            observation_id = make_observation_id_hashed(
                                self.name, service.host, "forbidden", path
                            )
                            from app.checks.base import Observation

                            result.observations.append(
                                Observation(
                                    id=observation_id,
                                    title=f"Protected path exists: {path}",
                                    description=f"Path {path} exists but is forbidden — potential authorization bypass target",
                                    severity="low",
                                    evidence=fmt_endpoint_evidence(url, 403),
                                    target=service,
                                    target_url=url,
                                    check_name=self.name,
                                )
                            )

                    elif resp.status_code in (301, 302, 307, 308):
                        location = extract_headers_dict(resp.headers).get("location", "")
                        observation_id = make_observation_id_hashed(
                            self.name, service.host, "redirect", path
                        )
                        from app.checks.base import Observation

                        result.observations.append(
                            Observation(
                                id=observation_id,
                                title=f"Redirect at {path}",
                                description=f"Path redirects to {location}",
                                severity="info",
                                evidence=f"GET {path} -> {resp.status_code} Location: {location}",
                                target=service,
                                target_url=url,
                                check_name=self.name,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.outputs[f"paths_{service.port}"] = {
            "accessible": accessible,
            "forbidden": forbidden,
        }

        return result
