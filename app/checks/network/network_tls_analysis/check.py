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

**Probe/grade.** `run()` makes up to five TLS handshakes per
endpoint — one to fetch the certificate, then one per deprecated protocol version
plus a modern one — and records each; `grade()` reads all five back and emits one
verdict per judgement. They are *one* candidate rather than five, because the
judgements cross them: "TLS 1.0 supported" is read off a protocol probe, and the
endpoint it describes is the one the certificate came from.

`tls_data` and `tls_hosts` are outputs (SANs feed back into discovery), so the
probe parses the certificate for itself — §6.2's two parses — but the parsed form
is what 57.2 already writes into `response_body` as JSON, so `grade()` reads back
rather than re-derives.

One judgement here is not reproducible and cannot be: certificate expiry is
measured against *now*, so an "expires in 12 days" verdict re-graded next month is
honestly a different verdict. `grade()` says so in its reasoning.
"""

import asyncio
import json
import logging
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Evidence, GradeContext, Verdict
from app.lib.timeutils import now_utc

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

    name = "network_tls_analysis"
    description = "TLS certificate inspection and protocol version detection"

    conditions = [
        CheckCondition("services", "truthy"),
    ]
    produces = ["tls_data", "tls_hosts"]

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
        # Every handshake made against one endpoint, certificate and protocol
        # probes together: they are one candidate, because the judgements cross
        # them (§0.11).
        exchanges: dict[str, list[Exchange]] = {}

        for host, port in tls_targets:
            cert_exchange = await self._get_cert_info(host, port)
            cert_info = _cert_from(cert_exchange)
            if cert_info is None:
                continue

            endpoint = f"{host}:{port}"
            tls_data[endpoint] = cert_info
            exchanges.setdefault(endpoint, []).append(cert_exchange)
            result.targets_checked += 1

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
            protocols, protocol_exchanges = await self._probe_protocols(host, port)
            tls_data[endpoint]["protocols"] = protocols
            exchanges[endpoint].extend(protocol_exchanges)

            candidate = self.create_candidate(host=host)
            for exchange in exchanges[endpoint]:
                candidate.attach(exchange)
            result.candidates.append(candidate)

        result.outputs["tls_data"] = tls_data
        result.outputs["tls_hosts"] = sorted(all_san_hosts)

        return result

    async def _get_cert_info(self, host: str, port: int) -> Exchange | None:
        """Connect to host:port with TLS and extract certificate details.

        Returns the recorded exchange (57.4 wave 2). The certificate is its
        `response_body`, as JSON — which is what 57.2 already wrote there.
        """
        loop = asyncio.get_event_loop()
        prb = None
        try:
            async with capture.probe(
                "tls", host, request_body=f"ClientHello sni={host}", port=port
            ) as prb:
                info = await asyncio.wait_for(
                    loop.run_in_executor(None, self._fetch_cert, host, port),
                    timeout=10.0,
                )
                prb.responded(json.dumps(info, default=str) if info else "")
        except (TimeoutError, Exception) as exc:
            logger.debug(f"TLS connect failed for {host}:{port}: {exc}")
        return prb.exchange if prb is not None else None

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
                dt = datetime.strptime(date_str, fmt).replace(tzinfo=UTC)
                return dt.isoformat()
            except ValueError:
                continue
        return date_str

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one endpoint's recorded handshakes."""
        cert_exchange = next((e for e in evidence if _cert_from(e)), None)
        if cert_exchange is None:
            return []

        cert_info = _cert_from(cert_exchange)
        host = ctx.host
        port = _port_of(cert_exchange)
        protocols = _protocols_from(evidence)

        return self._cert_verdicts(
            host, port, cert_info, cert_exchange.id
        ) + self._protocol_verdicts(host, port, protocols, [e.id for e in evidence])

    def _cert_verdicts(
        self, host: str, port: int | str, cert_info: dict, evidence_id: str
    ) -> list[Verdict]:
        """Grade one certificate."""
        ids = [evidence_id]
        verdicts: list[Verdict] = []
        endpoint = f"{host}:{port}"
        subject = cert_info.get("subject", {})
        issuer = cert_info.get("issuer", {})
        issuer_cn = issuer.get("commonName", "unknown")
        subject_cn = subject.get("commonName", host)
        sans = cert_info.get("sans", [])

        # ── The certificate itself ─────────────────────────
        san_str = ", ".join(sans[:10])
        if len(sans) > 10:
            san_str += f" (+{len(sans) - 10} more)"
        verdicts.append(
            Verdict(
                severity="info",
                # The certificate the server presented. Nothing is inferred.
                confidence=0.99,
                discriminator=f"cert-{port}",
                title=f"TLS certificate: {endpoint} ({issuer_cn})",
                description=(
                    f"Certificate for {subject_cn} issued by {issuer_cn}. "
                    f"{len(sans)} Subject Alternative Name(s) found."
                ),
                evidence=(
                    f"Subject: {subject_cn} | Issuer: {issuer_cn} | SANs: {san_str or 'none'}"
                ),
                reasoning="Certificate read from the handshake",
                signals={"issuer_cn": issuer_cn, "subject_cn": subject_cn, "san_count": len(sans)},
                raw_data=cert_info,
                evidence_ids=ids,
            )
        )

        # ── Hostnames in the SANs ──────────────────────────
        new_sans = [s for s in sans if s != host and not s.startswith("*.")]
        if new_sans:
            verdicts.append(
                Verdict(
                    severity="info",
                    # The SANs are certain; "not yet known" is not. This compares
                    # each name against the endpoint's own host and nothing else,
                    # so names the enumeration already found count as new here.
                    confidence=0.85,
                    discriminator=f"sans-{port}",
                    title=f"Certificate SANs discovered: {endpoint}",
                    description=(
                        f"The TLS certificate for {endpoint} contains "
                        f"{len(new_sans)} additional hostname(s) not yet known. "
                        f"These may include internal or staging environments."
                    ),
                    evidence=f"New SANs: {', '.join(new_sans[:20])}",
                    reasoning=f"{len(new_sans)} SAN(s) name something other than {host}",
                    signals={"new_sans": new_sans},
                    evidence_ids=ids,
                )
            )

        # ── Self-signed ───────────────────────────────────
        if cert_info.get("self_signed"):
            verdicts.append(
                Verdict(
                    severity="medium",
                    # Subject equal to issuer is exact. It is also what a CA
                    # root looks like, which is why this is not 0.99.
                    confidence=0.95,
                    discriminator=f"self-signed-{port}",
                    title=f"Self-signed certificate: {endpoint}",
                    description=(
                        f"The certificate on {endpoint} is self-signed "
                        f"(subject and issuer match: {issuer_cn}). "
                        f"This may indicate a development/staging environment "
                        f"or a misconfigured production service."
                    ),
                    evidence=f"Subject CN: {subject_cn} | Issuer CN: {issuer_cn}",
                    reasoning="Subject and issuer distinguished names are identical",
                    signals={"issuer_cn": issuer_cn},
                    evidence_ids=ids,
                )
            )

        # ── Expiry ────────────────────────────────────────
        #
        # The one judgement in this check that is not reproducible: it compares
        # the certificate against *now*, so re-grading the same stored handshake
        # next month honestly yields a different verdict. Said in the reasoning
        # rather than hidden.
        not_after = cert_info.get("not_after")
        if not_after:
            try:
                expiry = datetime.fromisoformat(not_after)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=UTC)
                now = now_utc()
                days_left = (expiry - now).days

                if days_left < self.EXPIRY_CRITICAL_DAYS:
                    verdicts.append(
                        Verdict(
                            severity="medium",
                            # Date arithmetic.
                            confidence=0.99,
                            discriminator=f"expired-{port}",
                            title=f"Expired certificate: {endpoint}",
                            description=(
                                f"The certificate for {endpoint} expired "
                                f"{abs(days_left)} day(s) ago on {not_after}."
                            ),
                            evidence=f"Expired: {not_after} ({abs(days_left)} days ago)",
                            reasoning=(
                                f"notAfter {not_after} is {abs(days_left)} day(s) before "
                                f"{now.date()}, the date this was graded"
                            ),
                            signals={"not_after": not_after, "days_left": days_left},
                            evidence_ids=ids,
                        )
                    )
                elif days_left <= self.EXPIRY_WARNING_DAYS:
                    verdicts.append(
                        Verdict(
                            severity="low",
                            confidence=0.99,
                            discriminator=f"expiring-{port}",
                            title=f"Certificate expires soon: {endpoint}",
                            description=(
                                f"The certificate for {endpoint} expires in "
                                f"{days_left} day(s) on {not_after}."
                            ),
                            evidence=f"Expires: {not_after} ({days_left} days remaining)",
                            reasoning=(
                                f"notAfter {not_after} is {days_left} day(s) after "
                                f"{now.date()}, the date this was graded"
                            ),
                            signals={"not_after": not_after, "days_left": days_left},
                            evidence_ids=ids,
                        )
                    )
            except (ValueError, TypeError):
                logger.debug(f"Could not parse expiry date: {not_after}")

        return verdicts

    async def _probe_protocols(self, host: str, port: int) -> tuple[list[str], list[Exchange]]:
        """Probe for supported TLS protocol versions.

        Returns the versions `tls_data` carries *and* the handshakes they were
        read from, so the grader reads the same answers from the same bytes.
        """
        loop = asyncio.get_event_loop()
        supported: list[str] = []
        exchanges: list[Exchange] = []

        for version_name, attr_name in TLS_VERSIONS:
            protocol_const = getattr(ssl, attr_name, None)
            if protocol_const is None:
                continue
            prb = None
            try:
                async with capture.probe(
                    "tls", host, request_body=f"ClientHello version={version_name}", port=port
                ) as prb:
                    ok = await asyncio.wait_for(
                        loop.run_in_executor(None, self._try_protocol, host, port, protocol_const),
                        timeout=5.0,
                    )
                    prb.responded("accepted" if ok else "rejected")
                if ok:
                    supported.append(version_name)
            except (TimeoutError, Exception):
                pass
            if prb is not None and prb.exchange is not None:
                exchanges.append(prb.exchange)

        # TLS 1.2 and 1.3 via default context (always check)
        prb = None
        try:
            async with capture.probe(
                "tls", host, request_body="ClientHello version=modern", port=port
            ) as prb:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._check_modern_tls, host, port),
                    timeout=5.0,
                )
                prb.responded(", ".join(result))
            for v in result:
                if v not in supported:
                    supported.append(v)
        except (TimeoutError, Exception):
            pass
        if prb is not None and prb.exchange is not None:
            exchanges.append(prb.exchange)

        return supported, exchanges

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

    def _protocol_verdicts(
        self,
        host: str,
        port: int | str,
        protocols: list[str],
        evidence_ids: list[str],
    ) -> list[Verdict]:
        """Grade the protocol versions one endpoint accepted."""
        endpoint = f"{host}:{port}"

        deprecated = [p for p in protocols if p in ("TLS 1.0", "TLS 1.1")]
        return [
            Verdict(
                severity="low",
                # A handshake completed against a context pinned to that
                # version. The probe either spoke TLS 1.0 to the server or it
                # did not.
                confidence=0.95,
                discriminator=f"deprecated-{proto.replace(' ', '').replace('.', '')}-{port}",
                title=f"{proto} supported: {endpoint}",
                description=(
                    f"{endpoint} accepts connections using {proto}, which is "
                    f"deprecated and has known vulnerabilities (BEAST, POODLE). "
                    f"Modern clients should use TLS 1.2 or 1.3."
                ),
                evidence=f"Supported protocols: {', '.join(protocols)}",
                reasoning=f"A {proto} handshake completed",
                signals={"protocol": proto, "supported": protocols},
                references=[
                    "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
                ],
                evidence_ids=evidence_ids,
            )
            for proto in deprecated
        ]


def _cert_from(exchange: Exchange | None) -> dict[str, Any] | None:
    """The certificate one recorded handshake came back with.

    57.2 wrote it into `response_body` as JSON, so this reads back rather than
    re-deriving. Only the certificate-fetch handshake has one; the protocol
    probes answer "accepted" or a version list, and return `None` here.
    """
    if exchange is None or exchange.error is not None or not exchange.response_body:
        return None
    try:
        info = json.loads(exchange.response_body)
    except (ValueError, TypeError):
        return None
    return info if isinstance(info, dict) and "sans" in info else None


def _port_of(exchange: Exchange) -> int | str:
    """The port a TLS handshake was made against, off its request metadata."""
    port = (exchange.request_headers or {}).get("port", "")
    try:
        return int(port)
    except (TypeError, ValueError):
        return port


def _protocols_from(exchanges: Any) -> list[str]:
    """The versions the protocol probes found acceptable, in the order probed."""
    supported: list[str] = []
    for exchange in exchanges:
        body = exchange.request_body or ""
        if "version=" not in body:
            continue
        version = body.split("version=", 1)[1].strip()
        answer = (exchange.response_body or "").strip()
        if version == "modern":
            for found in answer.split(","):
                found = found.strip()
                if found and found not in supported:
                    supported.append(found)
        elif answer == "accepted" and version not in supported:
            supported.append(version)
    return supported
