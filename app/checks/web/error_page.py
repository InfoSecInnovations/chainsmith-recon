"""
app/checks/web/error_page.py - Error Page Fingerprinting

Requests paths designed to trigger errors and analyzes responses
against known framework signatures to identify the underlying
technology stack and detect debug mode exposure.

Probes:
- 404: random nonexistent path
- 405: POST to a GET-only path
- 500: malformed JSON to API endpoints
"""

import logging
import re
import uuid
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

# Framework signatures: (pattern, framework_name, is_debug_mode, severity)
FRAMEWORK_SIGNATURES = [
    # Django
    (
        re.compile(r"You're seeing this error because you have\s+DEBUG\s*=\s*True", re.I),
        "Django",
        True,
        "medium",
    ),
    (re.compile(r"Django Version:", re.I), "Django", True, "medium"),
    (re.compile(r"Using the URLconf defined in\s+\S+\.urls", re.I), "Django", True, "medium"),
    # Flask / Werkzeug
    (re.compile(r"Werkzeug\s+Debugger", re.I), "Werkzeug/Flask", True, "high"),
    (re.compile(r"<title>.*Werkzeug.*</title>", re.I), "Werkzeug/Flask", True, "high"),
    (re.compile(r"The debugger caught an exception", re.I), "Werkzeug/Flask", True, "high"),
    (re.compile(r'class="traceback"', re.I), "Flask", False, "low"),
    # Spring Boot
    (re.compile(r"Whitelabel Error Page", re.I), "Spring Boot", False, "low"),
    (
        re.compile(r"This application has no explicit mapping for /error", re.I),
        "Spring Boot",
        False,
        "low",
    ),
    # Express.js
    (re.compile(r"Cannot (GET|POST|PUT|DELETE|PATCH) /\S+", re.I), "Express.js", False, "low"),
    (re.compile(r"ReferenceError:.*at\s+\S+\.js:\d+", re.I), "Express.js/Node.js", True, "medium"),
    # ASP.NET
    (re.compile(r"Server Error in '/' Application", re.I), "ASP.NET", False, "low"),
    (re.compile(r"ASP\.NET.*Version Information", re.I), "ASP.NET", True, "medium"),
    (re.compile(r"<title>.*Runtime Error.*</title>", re.I), "ASP.NET", False, "low"),
    # Laravel
    (re.compile(r"Ignition\s", re.I), "Laravel", True, "medium"),
    (re.compile(r"laravel.*exception", re.I), "Laravel", True, "medium"),
    (
        re.compile(r"Symfony\\Component\\HttpKernel\\Exception", re.I),
        "Laravel/Symfony",
        True,
        "medium",
    ),
    # FastAPI
    (
        re.compile(r'"detail"\s*:\s*"(Not Found|Method Not Allowed)"', re.I),
        "FastAPI",
        False,
        "info",
    ),
    # Ruby on Rails
    (re.compile(r"Action\s*Controller::RoutingError", re.I), "Ruby on Rails", True, "medium"),
    (re.compile(r"Rails\.root:", re.I), "Ruby on Rails", True, "medium"),
    # Tomcat
    (re.compile(r"Apache Tomcat/\d+", re.I), "Apache Tomcat", False, "low"),
    # nginx
    (re.compile(r"<center>nginx/[\d.]+</center>", re.I), "nginx", False, "info"),
    # Apache
    (re.compile(r"Apache/[\d.]+ .* Server at", re.I), "Apache HTTPD", False, "info"),
]

# Patterns indicating a stack trace in the response
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at\s+\S+\.(java|scala|kt):\d+", re.I),
    re.compile(r"File\s+\".*\.py\",\s+line\s+\d+", re.I),
    re.compile(r"at\s+\S+\s+\(\S+\.js:\d+:\d+\)", re.I),
    re.compile(r"at\s+\S+\.cs:\s*line\s+\d+", re.I),
]


class ErrorPageCheck(ServiceIteratingCheck):
    """Fingerprint web frameworks from error page responses."""

    name = "error_page"
    description = "Trigger error responses and fingerprint framework from error pages"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["error_page_info"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Error pages reveal framework identity and debug mode, enabling targeted attacks"
    references = ["OWASP WSTG-INFO-08", "CWE-209"]
    techniques = ["error page analysis", "technology fingerprinting"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        detected_frameworks: dict[str, dict[str, Any]] = {}
        debug_detected = False

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                # 1. Trigger 404 with random path
                random_path = f"/chainsmith-probe-{uuid.uuid4().hex[:8]}"
                await self._rate_limit()
                resp_404 = await client.get(service.with_path(random_path))
                if not resp_404.error and resp_404.body:
                    self._analyze_body(
                        resp_404.body, resp_404.status_code, service, result, detected_frameworks
                    )
                    if self._has_stack_trace(resp_404.body):
                        debug_detected = True
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Stack trace in 404 response: {service.host}",
                                description="Error response contains a stack trace, leaking internal code structure",
                                severity="low",
                                evidence=f"GET {random_path} -> HTTP {resp_404.status_code} | Stack trace detected in response body",
                                host=service.host,
                                discriminator="stack-trace-404",
                                target=service,
                                references=["CWE-209"],
                            )
                        )

                # 2. Trigger 405 with POST to root
                await self._rate_limit()
                resp_405 = await client.post(service.url)
                if not resp_405.error and resp_405.body:
                    self._analyze_body(
                        resp_405.body, resp_405.status_code, service, result, detected_frameworks
                    )

                # 3. Trigger 500 with malformed JSON to common API paths
                api_paths = self._get_api_paths(context)
                for api_path in api_paths[:3]:
                    await self._rate_limit()
                    resp_500 = await client.post(
                        service.with_path(api_path),
                        headers={"Content-Type": "application/json"},
                        data="{invalid json{{{",
                    )
                    if not resp_500.error and resp_500.body:
                        self._analyze_body(
                            resp_500.body,
                            resp_500.status_code,
                            service,
                            result,
                            detected_frameworks,
                        )
                        if self._has_stack_trace(resp_500.body):
                            debug_detected = True

        except Exception as e:
            result.errors.append(f"Error page check: {e}")

        # If no framework was identified but we got responses
        if not detected_frameworks and not debug_detected:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Custom error pages (framework not identified): {service.host}",
                    description="Error pages do not reveal framework identity",
                    severity="info",
                    evidence="No known framework signatures detected in error responses",
                    host=service.host,
                    discriminator="custom-errors",
                    target=service,
                )
            )

        result.outputs["error_page_info"] = {
            "frameworks": detected_frameworks,
            "debug_mode": debug_detected,
        }

        return result

    def _analyze_body(
        self,
        body: str,
        status_code: int,
        service: Service,
        result: CheckResult,
        detected: dict[str, dict[str, Any]],
    ) -> None:
        """Match response body against framework signatures."""
        for pattern, framework, is_debug, severity in FRAMEWORK_SIGNATURES:
            if framework in detected:
                continue  # Already detected this framework
            match = pattern.search(body)
            if match:
                detected[framework] = {
                    "debug_mode": is_debug,
                    "evidence": match.group(0)[:200],
                    "status_code": status_code,
                }

                if is_debug:
                    title = f"Debug mode enabled: {framework} at {service.host}"
                    description = f"{framework} debug/development mode detected via error page — may expose source code, environment variables, or interactive debugger"
                    # Werkzeug debugger is especially dangerous (RCE)
                    if "werkzeug" in framework.lower():
                        severity = "high"
                        description += (
                            ". Werkzeug interactive debugger may allow remote code execution"
                        )
                else:
                    title = f"Framework identified from error page: {framework}"
                    description = f"{framework} identified from error response signatures"

                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=title,
                        description=description,
                        severity=severity,
                        evidence=f"HTTP {status_code} response matched: {match.group(0)[:150]}",
                        host=service.host,
                        discriminator=f"framework-{framework.lower().replace('/', '-').replace(' ', '-')}",
                        target=service,
                        references=["CWE-209"] if is_debug else [],
                    )
                )

    def _has_stack_trace(self, body: str) -> bool:
        """Check if response body contains a stack trace."""
        return any(p.search(body) for p in STACK_TRACE_PATTERNS)

    def _get_api_paths(self, context: dict[str, Any]) -> list[str]:
        """Get API paths from context for 500 error triggering."""
        # Try openapi discovered endpoints
        api_endpoints = context.get("api_endpoints", [])
        if api_endpoints:
            return [ep.get("path", "") for ep in api_endpoints if ep.get("path")][:5]

        # Fallback to common API paths
        return ["/api", "/api/v1", "/graphql"]
