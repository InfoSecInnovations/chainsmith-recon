"""
app/checks/network/banner_grab.py

Banner Grabbing (Non-HTTP)

Raw TCP connect to non-HTTP ports, reads initial banner bytes.
Parses version strings and service identifiers for databases,
message queues, and custom protocols.

Depends on: services (needs open ports from port_scan)
Feeds: service version identification, vulnerability correlation
"""

import asyncio
import logging
import socket
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.findings import build_finding

logger = logging.getLogger(__name__)

# Banner patterns: (compiled later) -> (service_name, version_regex_group)
# Each entry: (match_bytes_or_str, service_name, severity_if_open, extra_probe)
BANNER_SIGNATURES = [
    # Redis
    {
        "name": "Redis",
        "default_ports": [6379],
        "probe": b"PING\r\n",
        "match": "+PONG",
        "version_probe": b"INFO server\r\n",
        "version_prefix": "redis_version:",
        "auth_check": True,
        "no_auth_severity": "critical",
    },
    # PostgreSQL
    {
        "name": "PostgreSQL",
        "default_ports": [5432],
        "probe": None,  # PostgreSQL sends initial bytes on connect
        "match": None,  # Check for specific byte pattern
        "banner_indicator": b"SFATAL",  # Common in PG error responses
        "version_prefix": None,
        "auth_check": False,
        "no_auth_severity": "info",
    },
    # MongoDB
    {
        "name": "MongoDB",
        "default_ports": [27017],
        "probe": None,
        "match": None,
        "banner_indicator": b"It looks like you are trying to access MongoDB",
        "version_prefix": None,
        "auth_check": False,
        "no_auth_severity": "info",
    },
    # MySQL / MariaDB
    {
        "name": "MySQL",
        "default_ports": [3306],
        "probe": None,
        "match": None,
        "banner_indicator": b"mysql",
        "version_prefix": None,
        "auth_check": False,
        "no_auth_severity": "info",
    },
    # SMTP
    {
        "name": "SMTP",
        "default_ports": [25, 587],
        "probe": None,
        "match": "220 ",
        "version_prefix": None,
        "auth_check": False,
        "no_auth_severity": "info",
    },
    # FTP
    {
        "name": "FTP",
        "default_ports": [21],
        "probe": None,
        "match": "220 ",  # Same prefix as SMTP but different ports
        "version_prefix": None,
        "auth_check": False,
        "no_auth_severity": "info",
    },
    # SSH
    {
        "name": "SSH",
        "default_ports": [22],
        "probe": None,
        "match": "SSH-",
        "version_prefix": "SSH-",
        "auth_check": False,
        "no_auth_severity": "info",
    },
    # Memcached
    {
        "name": "Memcached",
        "default_ports": [11211],
        "probe": b"version\r\n",
        "match": "VERSION",
        "version_prefix": "VERSION ",
        "auth_check": True,
        "no_auth_severity": "high",
    },
    # Elasticsearch
    {
        "name": "Elasticsearch",
        "default_ports": [9200, 9300],
        "probe": None,
        "match": "elasticsearch",
        "version_prefix": None,
        "auth_check": False,
        "no_auth_severity": "info",
    },
]

# Ports that are clearly HTTP and should be skipped
HTTP_PORTS = {80, 443, 8080, 8443, 8081, 8082, 8083, 8000, 8888, 3000, 5000, 8501, 7860, 4000, 9090}


class BannerGrabCheck(BaseCheck):
    """
    Grab banners from non-HTTP services on open ports.

    Performs raw TCP connections to open ports, reads initial banner
    bytes, and optionally sends protocol-specific probes (e.g., Redis PING).
    Identifies service names and versions from banner content.

    Produces:
        banner_data - dict[host:port, {service, banner, version, auth_required}]
    """

    name = "banner_grab"
    description = "Banner grabbing and service identification on non-HTTP ports"

    conditions = [
        CheckCondition("services", "truthy"),
    ]
    produces = ["banner_data"]

    timeout_seconds = 60.0
    requests_per_second = 10.0

    reason = (
        "Non-HTTP services (databases, caches, message queues) often send "
        "version banners on connect. An exposed Redis with no authentication "
        "is a critical finding. Service version identification enables "
        "vulnerability correlation."
    )
    references = [
        "OWASP WSTG-INFO-02 — Fingerprint Web Server",
        "CWE-200 — Exposure of Sensitive Information",
        "CWE-306 — Missing Authentication for Critical Function",
    ]
    techniques = [
        "TCP banner grabbing",
        "service fingerprinting",
        "protocol probing",
    ]

    BANNER_READ_TIMEOUT = 3.0
    CONNECT_TIMEOUT = 5.0
    MAX_BANNER_BYTES = 4096

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        services: list[Service] = context.get("services", [])
        if not services:
            result.errors.append("No services in context")
            result.success = False
            return result

        # Filter to non-HTTP services (unknown type or non-HTTP ports)
        targets: list[Service] = []
        seen: set[tuple[str, int]] = set()
        for svc in services:
            key = (svc.host, svc.port)
            if key in seen:
                continue
            seen.add(key)
            # Skip services already identified as HTTP
            if svc.scheme in ("http", "https") and svc.port in HTTP_PORTS:
                continue
            # Include unknown services or known non-HTTP ports
            if svc.service_type in ("unknown", "tcp") or svc.port not in HTTP_PORTS:
                targets.append(svc)

        if not targets:
            result.outputs["banner_data"] = {}
            return result

        banner_data: dict[str, dict] = {}

        for svc in targets:
            endpoint = f"{svc.host}:{svc.port}"
            banner_info = await self._grab_banner(svc.host, svc.port)
            if banner_info:
                banner_data[endpoint] = banner_info
                self._generate_findings(result, svc, banner_info)
            result.targets_checked += 1

        result.outputs["banner_data"] = banner_data
        return result

    async def _grab_banner(self, host: str, port: int) -> dict[str, Any] | None:
        """Connect to host:port and grab the banner."""
        asyncio.get_event_loop()

        info: dict[str, Any] = {
            "service": "unknown",
            "banner": "",
            "version": None,
            "auth_required": None,
            "raw_bytes": None,
        }

        # Step 1: Try passive read (server-speaks-first)
        banner_bytes = await self._tcp_read(host, port, probe=None)

        # Step 2: If no passive banner, try protocol-specific probes
        if not banner_bytes:
            for sig in BANNER_SIGNATURES:
                if sig.get("probe") and port in sig.get("default_ports", []):
                    banner_bytes = await self._tcp_read(host, port, probe=sig["probe"])
                    if banner_bytes:
                        break

        if not banner_bytes:
            # Try generic probes for common services by port
            for sig in BANNER_SIGNATURES:
                if port in sig.get("default_ports", []) and sig.get("probe"):
                    banner_bytes = await self._tcp_read(host, port, probe=sig["probe"])
                    if banner_bytes:
                        break

        if not banner_bytes:
            return None

        # Decode banner (best effort)
        try:
            banner_text = banner_bytes.decode("utf-8", errors="replace").strip()
        except Exception:
            banner_text = repr(banner_bytes[:200])

        info["banner"] = banner_text[:500]  # Cap length
        info["raw_bytes"] = banner_bytes[:200].hex()

        # Step 3: Identify service from banner
        identified = self._identify_service(banner_text, banner_bytes, port)
        info["service"] = identified["service"]
        info["version"] = identified.get("version")

        # Step 4: For Redis, check auth requirement
        if info["service"] == "Redis":
            auth_required = await self._check_redis_auth(host, port)
            info["auth_required"] = auth_required

        # Step 5: For Memcached, check auth
        if info["service"] == "Memcached":
            info["auth_required"] = not banner_text.startswith("VERSION")
            # If we got VERSION response, no auth is required
            if banner_text.startswith("VERSION"):
                info["auth_required"] = False

        return info

    async def _tcp_read(self, host: str, port: int, probe: bytes | None = None) -> bytes | None:
        """Raw TCP connect, optionally send probe, read response."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_tcp_read, host, port, probe),
                timeout=self.CONNECT_TIMEOUT + self.BANNER_READ_TIMEOUT,
            )
        except (TimeoutError, Exception) as exc:
            logger.debug(f"TCP read failed {host}:{port}: {exc}")
            return None

    def _sync_tcp_read(self, host: str, port: int, probe: bytes | None) -> bytes | None:
        """Synchronous TCP connect + read."""
        try:
            with socket.create_connection((host, port), timeout=self.CONNECT_TIMEOUT) as sock:
                sock.settimeout(self.BANNER_READ_TIMEOUT)

                if probe:
                    sock.sendall(probe)

                try:
                    data = sock.recv(self.MAX_BANNER_BYTES)
                    return data if data else None
                except TimeoutError:
                    return None

        except OSError as exc:
            logger.debug(f"TCP connect failed {host}:{port}: {exc}")
            return None

    def _identify_service(self, banner_text: str, banner_bytes: bytes, port: int) -> dict[str, Any]:
        """Identify service and version from banner content."""
        result: dict[str, Any] = {"service": "unknown", "version": None}
        banner_lower = banner_text.lower()

        # Check each signature — prefer port-matched signatures first
        # Sort signatures so those matching the port come first
        sorted_sigs = sorted(
            BANNER_SIGNATURES,
            key=lambda s: 0 if port in s.get("default_ports", []) else 1,
        )

        for sig in sorted_sigs:
            matched = False

            # Match by string pattern
            if sig.get("match") and sig["match"] in banner_text:
                matched = True

            # Match by bytes indicator
            if (
                not matched
                and sig.get("banner_indicator")
                and sig["banner_indicator"] in banner_bytes
            ):
                matched = True

            # Match by port + partial content hint
            if (
                not matched
                and port in sig.get("default_ports", [])
                and sig["name"].lower() in banner_lower
            ):
                matched = True

            if matched:
                result["service"] = sig["name"]

                # Extract version if possible
                if sig.get("version_prefix") and sig["version_prefix"] in banner_text:
                    prefix = sig["version_prefix"]
                    start = banner_text.index(prefix) + len(prefix)
                    # Read until whitespace or newline
                    end = start
                    while end < len(banner_text) and banner_text[end] not in (" ", "\r", "\n"):
                        end += 1
                    version = banner_text[start:end].strip()
                    if version:
                        result["version"] = version

                break

        # SSH version extraction (special case: SSH-2.0-OpenSSH_8.9)
        if result["service"] == "SSH" and banner_text.startswith("SSH-"):
            parts = banner_text.split("-", 2)
            if len(parts) >= 3:
                result["version"] = parts[2].split()[0] if parts[2] else None

        return result

    async def _check_redis_auth(self, host: str, port: int) -> bool:
        """Check if Redis requires authentication."""
        # Send INFO command — if auth is required, Redis returns -NOAUTH
        response = await self._tcp_read(host, port, probe=b"INFO\r\n")
        if response:
            text = response.decode("utf-8", errors="replace")
            if "-NOAUTH" in text or "DENIED" in text.upper():
                return True
            if "redis_version" in text or "# Server" in text:
                return False
        return True  # Assume auth required if unclear

    def _generate_findings(
        self,
        result: CheckResult,
        svc: Service,
        banner_info: dict[str, Any],
    ) -> None:
        """Generate findings from banner grabbing results."""
        endpoint = f"{svc.host}:{svc.port}"
        service_name = banner_info["service"]
        version = banner_info.get("version")
        banner = banner_info.get("banner", "")[:200]
        auth_required = banner_info.get("auth_required")

        version_str = f" {version}" if version else ""

        # Info finding: service identified
        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"{service_name}{version_str} detected: {endpoint}",
                description=(
                    f"{service_name}{version_str} service identified on {endpoint} "
                    f"via banner grabbing."
                ),
                severity="info",
                evidence=f"Banner: {banner}",
                host=svc.host,
                discriminator=f"banner-{svc.port}",
                raw_data=banner_info,
            )
        )

        # Critical: Database/cache with no authentication
        if auth_required is False:
            # Find the severity for this service
            severity = "high"
            for sig in BANNER_SIGNATURES:
                if sig["name"] == service_name:
                    severity = sig.get("no_auth_severity", "high")
                    break

            if severity in ("critical", "high"):
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title=(
                            f"{service_name} accepting commands without authentication: {endpoint}"
                        ),
                        description=(
                            f"{service_name} on {endpoint} does not require "
                            f"authentication. An attacker with network access can "
                            f"read, modify, or delete data. This is a critical "
                            f"security misconfiguration."
                        ),
                        severity=severity,
                        evidence=(
                            f"Service: {service_name}{version_str} | "
                            f"Auth required: False | Banner: {banner}"
                        ),
                        host=svc.host,
                        discriminator=f"noauth-{svc.port}",
                        references=[
                            "CWE-306 — Missing Authentication for Critical Function",
                        ],
                    )
                )

        # Version disclosure finding (if version detected on non-standard ports)
        if version and service_name != "unknown":
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Service version disclosed: {service_name}{version_str} on {endpoint}",
                    description=(
                        f"{service_name} on {endpoint} discloses its version "
                        f"({version}) in the connection banner. Version information "
                        f"aids attackers in identifying known vulnerabilities."
                    ),
                    severity="low",
                    evidence=f"Version: {version} | Banner: {banner}",
                    host=svc.host,
                    discriminator=f"version-{svc.port}",
                )
            )

        # Unknown service with banner — worth investigating
        if service_name == "unknown" and banner:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Unidentified service with banner: {endpoint}",
                    description=(
                        f"An unidentified service on {endpoint} returned a banner "
                        f"that does not match known service signatures. Manual "
                        f"investigation is recommended."
                    ),
                    severity="medium",
                    evidence=f"Banner (first 200 chars): {banner}",
                    host=svc.host,
                    discriminator=f"unknown-{svc.port}",
                )
            )
