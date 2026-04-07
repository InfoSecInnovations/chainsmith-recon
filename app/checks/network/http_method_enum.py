"""
app/checks/network/http_method_enum.py

HTTP Method Enumeration

Probes HTTP services with OPTIONS, TRACE, PUT, DELETE, and PATCH
to detect unexpected or dangerous methods enabled.

Depends on: services (needs HTTP services from service_probe)
Feeds: security posture assessment, web checks
"""

import logging
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.observations import build_observation

logger = logging.getLogger(__name__)

# Methods to probe and their security implications
DANGEROUS_METHODS = {
    "TRACE": {
        "severity": "medium",
        "desc": (
            "TRACE method is enabled, which can be exploited for Cross-Site "
            "Tracing (XST) attacks. An attacker can use TRACE to steal "
            "credentials from HttpOnly cookies via JavaScript."
        ),
    },
    "PUT": {
        "severity": "medium",
        "desc": (
            "PUT method is accepted, which may allow unauthorized file uploads "
            "or resource modification. On AI/ML endpoints this could enable "
            "unauthorized model or data manipulation."
        ),
    },
    "DELETE": {
        "severity": "low",
        "desc": (
            "DELETE method is accepted, which may allow unauthorized resource "
            "deletion. On AI/ML endpoints this could enable unauthorized "
            "model or data removal."
        ),
    },
    "PATCH": {
        "severity": "low",
        "desc": (
            "PATCH method is accepted, which may allow unauthorized partial resource modification."
        ),
    },
}

# WebDAV methods that indicate extended functionality
WEBDAV_METHODS = ["PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]


class HttpMethodEnumCheck(BaseCheck):
    """
    Enumerate allowed HTTP methods on discovered services.

    Sends OPTIONS request to discover allowed methods, then probes
    individually for TRACE, PUT, DELETE, PATCH. Also checks for WebDAV
    methods on non-standard services.

    Produces:
        http_methods - dict[host:port, {allowed: list[str], dangerous: list[str]}]
    """

    name = "http_method_enum"
    description = "HTTP method enumeration and dangerous method detection"

    conditions = [
        CheckCondition("services", "truthy"),
    ]
    produces = ["http_methods"]

    timeout_seconds = 60.0
    requests_per_second = 5.0  # Conservative — WAFs block rapid method probing

    reason = (
        "Unexpected HTTP methods on production services indicate misconfiguration. "
        "TRACE enables cross-site tracing (XST), while PUT/DELETE on AI endpoints "
        "may allow unauthorized model modification or data deletion."
    )
    references = [
        "OWASP WSTG-CONF-06 — Test HTTP Methods",
        "CWE-16 — Configuration",
        "CWE-749 — Exposed Dangerous Method or Function",
    ]
    techniques = [
        "HTTP method enumeration",
        "OPTIONS probing",
        "cross-site tracing detection",
    ]

    # Status codes that indicate a method is accepted (not just "not allowed")
    ACCEPTED_CODES = {200, 201, 204, 207, 301, 302, 307, 308, 405}
    # 405 is "Method Not Allowed" — server explicitly rejects, so method is NOT accepted
    # We include it in the set to differentiate from connection errors
    METHOD_ALLOWED_CODES = {200, 201, 204, 207, 301, 302, 307, 308}

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        services: list[Service] = context.get("services", [])
        if not services:
            result.errors.append("No services in context")
            result.success = False
            return result

        # Filter to HTTP/HTTPS services only
        http_services = [svc for svc in services if svc.scheme in ("http", "https")]

        if not http_services:
            result.outputs["http_methods"] = {}
            return result

        # Deduplicate by host:port
        seen: set[tuple[str, int]] = set()
        unique_services: list[Service] = []
        for svc in http_services:
            key = (svc.host, svc.port)
            if key not in seen:
                seen.add(key)
                unique_services.append(svc)

        http_methods_data: dict[str, dict] = {}

        for svc in unique_services:
            endpoint = f"{svc.host}:{svc.port}"
            method_info = await self._probe_service(svc)
            http_methods_data[endpoint] = method_info
            result.targets_checked += 1

            # Generate observations
            self._generate_observations(result, svc, method_info)

        result.outputs["http_methods"] = http_methods_data
        return result

    async def _probe_service(self, svc: Service) -> dict[str, Any]:
        """Probe a single service for allowed HTTP methods."""
        import httpx

        info: dict[str, Any] = {
            "allowed": [],
            "dangerous": [],
            "webdav": [],
            "options_allow": None,
        }

        base_url = svc.url.rstrip("/")

        # Step 1: OPTIONS request to get Allow header
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=10.0,
                follow_redirects=False,
            ) as client:
                resp = await client.options(base_url + "/")
                allow_header = resp.headers.get("allow", "")
                if allow_header:
                    info["options_allow"] = allow_header
                    info["allowed"] = [m.strip().upper() for m in allow_header.split(",")]
        except Exception as exc:
            logger.debug(f"OPTIONS failed for {base_url}: {exc}")

        # Step 2: Probe dangerous methods individually
        for method in DANGEROUS_METHODS:
            accepted = await self._probe_method(base_url, method)
            if accepted:
                if method not in info["allowed"]:
                    info["allowed"].append(method)
                info["dangerous"].append(method)

        # Step 3: Check WebDAV methods
        for method in WEBDAV_METHODS:
            accepted = await self._probe_method(base_url, method)
            if accepted:
                info["webdav"].append(method)
                if method not in info["allowed"]:
                    info["allowed"].append(method)

        return info

    async def _probe_method(self, base_url: str, method: str) -> bool:
        """Send a single method probe and check if it's accepted."""
        import httpx

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=8.0,
                follow_redirects=False,
            ) as client:
                resp = await client.request(method, base_url + "/")
                # Method is "accepted" if server doesn't return 405/501
                return resp.status_code not in (405, 501, 400)
        except Exception:
            return False

    def _generate_observations(
        self,
        result: CheckResult,
        svc: Service,
        method_info: dict[str, Any],
    ) -> None:
        """Generate observations from method enumeration results."""
        endpoint = f"{svc.host}:{svc.port}"
        allowed = method_info.get("allowed", [])
        dangerous = method_info.get("dangerous", [])
        webdav = method_info.get("webdav", [])

        # Info observation: allowed methods summary
        if allowed:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Allowed methods: {endpoint}",
                    description=(
                        f"HTTP method enumeration on {endpoint} discovered "
                        f"{len(allowed)} allowed method(s)."
                    ),
                    severity="info",
                    evidence=f"Allowed: {', '.join(sorted(allowed))}",
                    host=svc.host,
                    discriminator=f"methods-{svc.port}",
                    raw_data=method_info,
                )
            )

        # Dangerous method observations
        for method in dangerous:
            meta = DANGEROUS_METHODS[method]
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"{method} method enabled: {endpoint}",
                    description=meta["desc"],
                    severity=meta["severity"],
                    evidence=f"HTTP {method} {svc.url}/ returned a non-405 response",
                    host=svc.host,
                    discriminator=f"{method.lower()}-{svc.port}",
                    references=(
                        ["CWE-693 — Protection Mechanism Failure"] if method == "TRACE" else []
                    ),
                )
            )

        # WebDAV methods observation
        if webdav:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"WebDAV methods enabled: {endpoint}",
                    description=(
                        f"WebDAV methods ({', '.join(webdav)}) are enabled on "
                        f"{endpoint}. This indicates extended file management "
                        f"capabilities that may expose sensitive operations."
                    ),
                    severity="medium",
                    evidence=f"WebDAV methods: {', '.join(webdav)}",
                    host=svc.host,
                    discriminator=f"webdav-{svc.port}",
                )
            )
