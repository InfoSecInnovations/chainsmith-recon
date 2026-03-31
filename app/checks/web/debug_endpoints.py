"""
app/checks/web/debug_endpoints.py - Exposed Debug Endpoint Analysis

When path_probe finds debug endpoints (/debug, /actuator, /server-status, etc.)
returning 200, this check fetches and analyzes their content for sensitive data.
"""

import re
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding
from app.lib.evidence import fmt_status_evidence


class DebugEndpointCheck(ServiceIteratingCheck):
    """Analyze accessible debug endpoints for sensitive information disclosure."""

    name = "debug_endpoints"
    description = "Analyze exposed debug/actuator/status endpoints for sensitive data"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["debug_findings"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Debug endpoints frequently expose environment variables, connection strings, and internal IPs"
    references = ["OWASP WSTG-CONF-05", "CWE-215"]
    techniques = ["debug endpoint analysis", "information disclosure"]

    # Debug paths to probe (may overlap with path_probe but this check analyzes content)
    DEBUG_PATHS = [
        "/debug", "/__debug__/", "/actuator", "/actuator/env",
        "/actuator/configprops", "/actuator/mappings", "/actuator/beans",
        "/server-status", "/server-info", "/.well-known/health",
        "/health", "/healthcheck", "/elmah.axd",
        "/phpinfo.php", "/_profiler", "/trace",
    ]

    # Spring Boot Actuator sub-endpoints
    ACTUATOR_ENDPOINTS = [
        "/actuator/env", "/actuator/configprops", "/actuator/mappings",
        "/actuator/beans", "/actuator/info", "/actuator/metrics",
        "/actuator/loggers", "/actuator/threaddump",
    ]

    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        ("environment_variables", re.compile(r"(?:password|secret|key|token|credential|api_key)\s*[=:]\s*\S+", re.I)),
        ("connection_string", re.compile(r"(?:DATABASE_URL|MONGO_URI|REDIS_URL|jdbc:|mongodb://|postgres://|mysql://)", re.I)),
        ("internal_ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
        ("stack_trace", re.compile(r"(?:Traceback|at\s+\w+\.\w+\(|Exception in|Error:.*at\s+line)", re.I)),
    ]

    # Framework-specific debug signatures
    FRAMEWORK_SIGNATURES = {
        "django_debug": re.compile(r"You're seeing this error because you have DEBUG\s*=\s*True", re.I),
        "werkzeug_debugger": re.compile(r"Werkzeug\s+Debug(?:ger)?|The debugger caught an exception", re.I),
        "spring_whitelabel": re.compile(r"Whitelabel Error Page", re.I),
        "express_error": re.compile(r"Cannot GET /|at Layer\.handle", re.I),
        "laravel_ignition": re.compile(r"Ignition|laravel.*exception", re.I),
        "aspnet_error": re.compile(r"Server Error in '/' Application", re.I),
    }

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Combine our probe paths with those found by path_probe
        paths_to_check = list(self.DEBUG_PATHS)
        accessible = self._get_accessible_paths(service, context)
        for p in accessible:
            p_lower = p.lower()
            if any(kw in p_lower for kw in ["debug", "actuator", "status", "health", "phpinfo", "profiler", "trace"]):
                if p not in paths_to_check:
                    paths_to_check.append(p)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                actuator_found = False

                for path in paths_to_check:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    body = resp.body

                    # Check for Spring Boot Actuator root
                    if path == "/actuator" and not actuator_found:
                        actuator_found = True
                        actuator_endpoints = await self._enumerate_actuator(client, service)
                        if actuator_endpoints:
                            result.findings.append(build_finding(
                                check_name=self.name,
                                title=f"Spring Boot Actuator exposed: {service.host}",
                                description=f"{len(actuator_endpoints)} actuator endpoints accessible",
                                severity="high",
                                evidence=f"Accessible endpoints: {', '.join(actuator_endpoints[:10])}",
                                host=service.host,
                                discriminator="actuator-exposed",
                                target=service,
                                target_url=url,
                                raw_data={"endpoints": actuator_endpoints},
                            ))
                        continue

                    # Check for framework debug modes
                    framework = self._detect_framework_debug(body)

                    # Check for sensitive data
                    sensitive = self._find_sensitive_data(body)

                    if framework == "werkzeug_debugger":
                        # Werkzeug debugger = potential RCE
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Werkzeug debugger exposed: {service.host}{path}",
                            description="Interactive debugger detected — potential remote code execution",
                            severity="critical",
                            evidence=fmt_status_evidence(url, 200, body[:200]),
                            host=service.host,
                            discriminator=f"werkzeug-debugger-{path.replace('/', '-').strip('-')}",
                            target=service,
                            target_url=url,
                        ))
                    elif framework == "django_debug":
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Django DEBUG=True: {service.host}",
                            description="Django debug mode enabled — detailed error pages with source code",
                            severity="high",
                            evidence=fmt_status_evidence(url, 200, body[:200]),
                            host=service.host,
                            discriminator="django-debug",
                            target=service,
                            target_url=url,
                        ))
                    elif sensitive:
                        # Categorize by what was found
                        categories = list(set(s[0] for s in sensitive))
                        has_env = "environment_variables" in categories
                        severity = "critical" if has_env else "high"

                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Debug endpoint leaks sensitive data: {service.host}{path}",
                            description=f"Sensitive data categories: {', '.join(categories)}",
                            severity=severity,
                            evidence=f"GET {url} -> 200 | Sensitive patterns: {', '.join(categories)}",
                            host=service.host,
                            discriminator=f"sensitive-{path.replace('/', '-').strip('-')}",
                            target=service,
                            target_url=url,
                            raw_data={"categories": categories, "path": path},
                        ))
                    elif framework:
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Framework identified from debug page: {framework} at {service.host}{path}",
                            description=f"Debug/error page reveals framework: {framework}",
                            severity="low",
                            evidence=fmt_status_evidence(url, 200, body[:200]),
                            host=service.host,
                            discriminator=f"framework-{framework}",
                            target=service,
                            target_url=url,
                        ))
                    elif path in ("/health", "/healthcheck", "/.well-known/health"):
                        # Verbose health endpoints
                        if len(body) > 100:
                            result.findings.append(build_finding(
                                check_name=self.name,
                                title=f"Verbose health endpoint: {service.host}{path}",
                                description=f"Health endpoint returns detailed info ({len(body)} bytes)",
                                severity="medium",
                                evidence=fmt_status_evidence(url, 200, body[:200]),
                                host=service.host,
                                discriminator=f"verbose-health-{path.replace('/', '-').strip('-')}",
                                target=service,
                                target_url=url,
                            ))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _enumerate_actuator(self, client: AsyncHttpClient, service: Service) -> list[str]:
        """Enumerate accessible Spring Boot Actuator endpoints."""
        accessible = []
        for path in self.ACTUATOR_ENDPOINTS:
            resp = await client.get(service.with_path(path))
            if not resp.error and resp.status_code == 200:
                accessible.append(path)
        return accessible

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
