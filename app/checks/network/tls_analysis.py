"""
app/checks/network/tls_analysis.py

TLS/Certificate Analysis

Connects to TLS-enabled ports and inspects:
- Certificate chain (issuer, subject, validity dates)
- Subject Alternative Names (SANs) — additional hostnames, internal names
- TLS protocol versions supported (TLS 1.0/1.1/1.2/1.3)
- Self-signed certificate detection
- Certificate expiry warnings

Depends on: services (needs discovered services with HTTPS ports)
Feeds: additional hostname discovery (from SANs), security posture
"""

import asyncio
import datetime
import logging
import socket
import ssl
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.observations import build_observation

logger = logging.getLogger(__name__)


# TLS protocol versions to probe (version name -> ssl constant if available)
TLS_VERSIONS = [
    ("TLS 1.0", "PROTOCOL_TLSv1"),
    ("TLS 1.1", "PROTOCOL_TLSv1_1"),
    ("TLS 1.2", "PROTOCOL_TLSv1_2"),
]


class TlsAnalysisCheck(BaseCheck):
    """
    Inspect TLS certificates and protocol support on discovered services.

    Connects to each HTTPS service to extract certificate details,
    SANs (additional hostnames), expiry status, and self-signed detection.
    Probes for deprecated TLS protocol versions.

    Produces:
        tls_data - dict[host:port, {subject, issuer, sans, not_before,
                   not_after, self_signed, protocols, serial}]
        tls_hosts - list[str] of additional hostnames discovered from SANs
    """

    name = "tls_analysis"
    description = "TLS certificate inspection and protocol version detection"

    conditions = [
        CheckCondition("services", "truthy"),
    ]
    produces = ["tls_data", "tls_hosts"]

    timeout_seconds = 60.0
    requests_per_second = 10.0

    reason = (
        "TLS certificates reveal additional hostnames via SANs that subdomain "
        "enumeration may have missed (internal names, staging environments). "
        "Weak TLS configurations and expired/self-signed certificates are "
        "security observations in themselves."
    )
    references = [
        "OWASP WSTG-CRYP-01 — Testing for Weak TLS/SSL Ciphers",
        "CWE-295 — Improper Certificate Validation",
        "CWE-326 — Inadequate Encryption Strength",
    ]
    techniques = [
        "TLS certificate analysis",
        "SAN enumeration",
        "protocol version detection",
    ]

    # Ports commonly running TLS
    TLS_PORTS = {443, 8443, 8080, 3000, 5000, 5001, 8000, 9443}

    # Days thresholds for certificate expiry warnings
    EXPIRY_CRITICAL_DAYS = 0  # Already expired
    EXPIRY_WARNING_DAYS = 30

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        services: list[Service] = context.get("services", [])
        if not services:
            result.errors.append("No services in context")
            result.success = False
            return result

        # Collect TLS-capable services (HTTPS or common TLS ports)
        tls_targets: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        for svc in services:
            key = (svc.host, svc.port)
            if key in seen:
                continue
            seen.add(key)
            # Include if scheme is https or port is a known TLS port
            if svc.scheme == "https" or svc.port in self.TLS_PORTS:
                tls_targets.append(key)

        if not tls_targets:
            result.outputs["tls_data"] = {}
            result.outputs["tls_hosts"] = []
            return result

        tls_data: dict[str, dict] = {}
        all_san_hosts: set[str] = set()
        base_domain = context.get("base_domain", "")

        for host, port in tls_targets:
            cert_info = await self._get_cert_info(host, port)
            if cert_info is None:
                continue

            endpoint = f"{host}:{port}"
            tls_data[endpoint] = cert_info
            result.targets_checked += 1

            # Generate observations
            self._generate_cert_observations(result, host, port, cert_info, base_domain)

            # Collect SANs as additional hosts
            for san in cert_info.get("sans", []):
                # Skip wildcard entries and the host itself
                if san.startswith("*."):
                    continue
                if san != host:
                    all_san_hosts.add(san)

        # Probe deprecated TLS versions on discovered TLS endpoints
        for host, port in tls_targets:
            endpoint = f"{host}:{port}"
            if endpoint not in tls_data:
                continue
            protocols = await self._probe_protocols(host, port)
            tls_data[endpoint]["protocols"] = protocols
            self._generate_protocol_observations(result, host, port, protocols)

        result.outputs["tls_data"] = tls_data
        result.outputs["tls_hosts"] = sorted(all_san_hosts)

        return result

    async def _get_cert_info(self, host: str, port: int) -> dict[str, Any] | None:
        """Connect to host:port with TLS and extract certificate details."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._fetch_cert, host, port),
                timeout=10.0,
            )
        except (TimeoutError, Exception) as exc:
            logger.debug(f"TLS connect failed for {host}:{port}: {exc}")
            return None

    def _fetch_cert(self, host: str, port: int) -> dict[str, Any] | None:
        """Synchronous TLS certificate fetch."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Accept self-signed for inspection

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    pem_cert = ssock.getpeercert(binary_form=False)

                    if not der_cert and not pem_cert:
                        return None

                    info: dict[str, Any] = {
                        "subject": {},
                        "issuer": {},
                        "sans": [],
                        "not_before": None,
                        "not_after": None,
                        "self_signed": False,
                        "serial": None,
                        "version": None,
                        "protocols": [],
                    }

                    # Parse PEM cert dict (returned by getpeercert())
                    if pem_cert:
                        info["subject"] = self._parse_dn(pem_cert.get("subject", ()))
                        info["issuer"] = self._parse_dn(pem_cert.get("issuer", ()))
                        info["serial"] = pem_cert.get("serialNumber")
                        info["version"] = pem_cert.get("version")

                        # SANs
                        san_entries = pem_cert.get("subjectAltName", ())
                        info["sans"] = [val for typ, val in san_entries if typ == "DNS"]

                        # Dates
                        not_before = pem_cert.get("notBefore")
                        not_after = pem_cert.get("notAfter")
                        if not_before:
                            info["not_before"] = self._parse_cert_date(not_before)
                        if not_after:
                            info["not_after"] = self._parse_cert_date(not_after)

                        # Self-signed detection
                        info["self_signed"] = info["subject"] == info["issuer"]
                    else:
                        # Binary-only cert — limited info
                        info["serial"] = der_cert[:20].hex()

                    # Record negotiated TLS version
                    tls_version = ssock.version()
                    if tls_version:
                        info["negotiated_version"] = tls_version

                    return info

        except (ssl.SSLError, OSError) as exc:
            logger.debug(f"TLS handshake failed {host}:{port}: {exc}")
            return None

    def _parse_dn(self, dn_tuple: tuple) -> dict[str, str]:
        """Parse an SSL distinguished name tuple into a flat dict."""
        result: dict[str, str] = {}
        for rdn in dn_tuple:
            for attr_type, attr_value in rdn:
                result[attr_type] = attr_value
        return result

    def _parse_cert_date(self, date_str: str) -> str:
        """Parse SSL certificate date string to ISO format."""
        # Format: 'Mar 10 12:00:00 2025 GMT'
        for fmt in (
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
        ):
            try:
                dt = datetime.datetime.strptime(date_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue
        return date_str

    def _generate_cert_observations(
        self,
        result: CheckResult,
        host: str,
        port: int,
        cert_info: dict,
        base_domain: str,
    ) -> None:
        """Generate observations from certificate inspection."""
        endpoint = f"{host}:{port}"
        subject = cert_info.get("subject", {})
        issuer = cert_info.get("issuer", {})
        issuer_cn = issuer.get("commonName", "unknown")
        subject_cn = subject.get("commonName", host)
        sans = cert_info.get("sans", [])

        # Info observation: certificate summary
        san_str = ", ".join(sans[:10])
        if len(sans) > 10:
            san_str += f" (+{len(sans) - 10} more)"
        evidence = f"Subject: {subject_cn} | Issuer: {issuer_cn} | SANs: {san_str or 'none'}"
        result.observations.append(
            build_observation(
                check_name=self.name,
                title=f"TLS certificate: {endpoint} ({issuer_cn})",
                description=(
                    f"Certificate for {subject_cn} issued by {issuer_cn}. "
                    f"{len(sans)} Subject Alternative Name(s) found."
                ),
                severity="info",
                evidence=evidence,
                host=host,
                discriminator=f"cert-{port}",
                raw_data=cert_info,
            )
        )

        # SANs with new hostnames
        new_sans = [s for s in sans if s != host and not s.startswith("*.")]
        if new_sans:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Certificate SANs discovered: {endpoint}",
                    description=(
                        f"The TLS certificate for {endpoint} contains "
                        f"{len(new_sans)} additional hostname(s) not yet known. "
                        f"These may include internal or staging environments."
                    ),
                    severity="info",
                    evidence=f"New SANs: {', '.join(new_sans[:20])}",
                    host=host,
                    discriminator=f"sans-{port}",
                )
            )

        # Self-signed certificate
        if cert_info.get("self_signed"):
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Self-signed certificate: {endpoint}",
                    description=(
                        f"The certificate on {endpoint} is self-signed "
                        f"(subject and issuer match: {issuer_cn}). "
                        f"This may indicate a development/staging environment "
                        f"or a misconfigured production service."
                    ),
                    severity="medium",
                    evidence=f"Subject CN: {subject_cn} | Issuer CN: {issuer_cn}",
                    host=host,
                    discriminator=f"self-signed-{port}",
                )
            )

        # Certificate expiry
        not_after = cert_info.get("not_after")
        if not_after:
            try:
                expiry = datetime.datetime.fromisoformat(not_after)
                now = datetime.datetime.utcnow()
                days_left = (expiry - now).days

                if days_left < self.EXPIRY_CRITICAL_DAYS:
                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"Expired certificate: {endpoint}",
                            description=(
                                f"The certificate for {endpoint} expired "
                                f"{abs(days_left)} day(s) ago on {not_after}."
                            ),
                            severity="medium",
                            evidence=f"Expired: {not_after} ({abs(days_left)} days ago)",
                            host=host,
                            discriminator=f"expired-{port}",
                        )
                    )
                elif days_left <= self.EXPIRY_WARNING_DAYS:
                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"Certificate expires soon: {endpoint}",
                            description=(
                                f"The certificate for {endpoint} expires in "
                                f"{days_left} day(s) on {not_after}."
                            ),
                            severity="low",
                            evidence=f"Expires: {not_after} ({days_left} days remaining)",
                            host=host,
                            discriminator=f"expiring-{port}",
                        )
                    )
            except (ValueError, TypeError):
                logger.debug(f"Could not parse expiry date: {not_after}")

    async def _probe_protocols(self, host: str, port: int) -> list[str]:
        """Probe for supported TLS protocol versions."""
        loop = asyncio.get_event_loop()
        supported: list[str] = []

        for version_name, attr_name in TLS_VERSIONS:
            protocol_const = getattr(ssl, attr_name, None)
            if protocol_const is None:
                continue
            try:
                ok = await asyncio.wait_for(
                    loop.run_in_executor(None, self._try_protocol, host, port, protocol_const),
                    timeout=5.0,
                )
                if ok:
                    supported.append(version_name)
            except (TimeoutError, Exception):
                pass

        # TLS 1.2 and 1.3 via default context (always check)
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._check_modern_tls, host, port),
                timeout=5.0,
            )
            for v in result:
                if v not in supported:
                    supported.append(v)
        except (TimeoutError, Exception):
            pass

        return supported

    def _try_protocol(self, host: str, port: int, protocol_const: int) -> bool:
        """Try connecting with a specific TLS protocol version."""
        try:
            ctx = ssl.SSLContext(protocol_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError):
            return False

    def _check_modern_tls(self, host: str, port: int) -> list[str]:
        """Check for TLS 1.2/1.3 support via default context."""
        versions: list[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ver = ssock.version()
                    if ver:
                        if "TLSv1.3" in ver:
                            versions.append("TLS 1.3")
                        elif "TLSv1.2" in ver:
                            versions.append("TLS 1.2")
        except (ssl.SSLError, OSError):
            pass
        return versions

    def _generate_protocol_observations(
        self,
        result: CheckResult,
        host: str,
        port: int,
        protocols: list[str],
    ) -> None:
        """Generate observations for deprecated TLS versions."""
        endpoint = f"{host}:{port}"

        deprecated = [p for p in protocols if p in ("TLS 1.0", "TLS 1.1")]
        for proto in deprecated:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"{proto} supported: {endpoint}",
                    description=(
                        f"{endpoint} accepts connections using {proto}, which is "
                        f"deprecated and has known vulnerabilities (BEAST, POODLE). "
                        f"Modern clients should use TLS 1.2 or 1.3."
                    ),
                    severity="low",
                    evidence=f"Supported protocols: {', '.join(protocols)}",
                    host=host,
                    discriminator=f"deprecated-{proto.replace(' ', '').replace('.', '')}-{port}",
                    references=[
                        "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
                    ],
                )
            )
