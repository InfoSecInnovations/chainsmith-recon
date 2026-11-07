"""
app/checks/network/banner_grab.py

Banner Grabbing (Non-HTTP)

Raw TCP connect to non-HTTP ports, reads initial banner bytes.
Parses version strings and service identifiers for databases,
message queues, and custom protocols.

Depends on: services (needs open ports from port_scan)
Feeds: service version identification, vulnerability correlation

**Probe/grade.** `run()` connects, sends whatever probe the
port suggests, and records each read; `grade()` reads the banner back and says
what the service is and whether it is asking for a password. `banner_data` is an
output, so both halves call the same `_banner_from()` over the same exchanges —
§6.2's two parses with one parser.

**The exchange now carries the banner twice, on purpose.** `response_body` holds
the decoded text, because that is what a reader — human or, with the planned LLM tier, a model
— actually reads; `response_headers["raw_hex"]` holds the bytes verbatim, because
a binary handshake does not survive `decode(errors="replace")` and two of the
signatures here match on raw bytes. Before wave 2 the hex was computed in
`_grab_banner` and thrown away; keeping it on the exchange is what lets a stored
banner be identified as exactly as a live one.
"""

import asyncio
import logging
import socket
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Evidence, GradeContext, Verdict

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

#: The command `_grab_banner` sends to ask Redis whether it wants a password.
#: Named because `_redis_auth_from` identifies its exchange by this payload.
REDIS_AUTH_PROBE = b"INFO\r\n"

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

    name = "network_banner_grab"
    description = "Banner grabbing and service identification on non-HTTP ports"

    conditions = [
        CheckCondition("services", "truthy"),
    ]
    produces = ["banner_data"]

    reason = (
        "Non-HTTP services (databases, caches, message queues) often send "
        "version banners on connect. An exposed Redis with no authentication "
        "is a critical observation. Service version identification enables "
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
            banner_info, exchanges = await self._grab_banner(svc.host, svc.port)
            if banner_info:
                banner_data[endpoint] = banner_info
                candidate = self.create_candidate(host=svc.host, target=svc)
                for exchange in exchanges:
                    candidate.attach(exchange)
                result.candidates.append(candidate)
            result.targets_checked += 1

        result.outputs["banner_data"] = banner_data
        return result

    async def _grab_banner(
        self, host: str, port: int
    ) -> tuple[dict[str, Any] | None, list[Exchange]]:
        """Connect to host:port and grab the banner.

        Returns the summary `banner_data` carries *and* every read it was taken
        from, so the grader reads the same banner from the same bytes.
        """
        exchanges: list[Exchange] = []

        def _answered() -> bool:
            return any(_responded(e) for e in exchanges)

        # Step 1: Try passive read (server-speaks-first)
        exchanges.append(await self._tcp_read(host, port, probe=None))

        # Step 2: If no passive banner, try protocol-specific probes.
        #
        # Two attempts. The pre-57.4 code had this block written out twice,
        # verbatim and under identical conditions, so its second copy only ever
        # acted as a retry — named here rather than duplicated.
        for _attempt in range(2):
            if _answered():
                break
            for sig in BANNER_SIGNATURES:
                if sig.get("probe") and port in sig.get("default_ports", []):
                    exchanges.append(await self._tcp_read(host, port, probe=sig["probe"]))
                    if _responded(exchanges[-1]):
                        break

        info = self._banner_from(exchanges, port)
        if info is None:
            return None, exchanges

        # Step 3: For Redis, ask whether it wants a password. The answer is read
        # out of the exchange by `_banner_from`, so the summary is recomputed
        # once the probe exists rather than patched in place.
        if info["service"] == "Redis":
            exchanges.append(await self._tcp_read(host, port, probe=REDIS_AUTH_PROBE))
            info = self._banner_from(exchanges, port)

        return info, exchanges

    def _banner_from(self, exchanges: list[Exchange], port: int) -> dict[str, Any] | None:
        """Read one endpoint's service identity out of its recorded reads.

        The single parser behind §6.2's two parses: `_grab_banner` calls it to
        populate `banner_data`, and `grade()` calls it again over the stored
        copies.
        """
        auth_probe = next((e for e in exchanges if _is_auth_probe(e)), None)
        banner_exchange = next(
            (e for e in exchanges if e is not auth_probe and _responded(e)), None
        )
        if banner_exchange is None:
            return None

        banner_bytes = _raw_bytes(banner_exchange)
        banner_text = banner_exchange.response_body.strip()

        info: dict[str, Any] = {
            "service": "unknown",
            "banner": banner_text[:500],  # Cap length
            "version": None,
            "auth_required": None,
            "raw_bytes": banner_bytes[:200].hex(),
        }

        identified = self._identify_service(banner_text, banner_bytes, port)
        info["service"] = identified["service"]
        info["version"] = identified.get("version")

        if info["service"] == "Redis":
            info["auth_required"] = self._redis_auth_from(auth_probe)

        if info["service"] == "Memcached":
            # A VERSION answer means the command ran, so nothing asked us for a
            # password.
            info["auth_required"] = not banner_text.startswith("VERSION")

        return info

    async def _tcp_read(self, host: str, port: int, probe: bytes | None = None) -> Exchange | None:
        """Raw TCP connect, optionally send probe, read response.

        Returns the recorded exchange (57.4 wave 2). The banner is its
        `response_body` as text and its `raw_hex` header as bytes.
        """
        loop = asyncio.get_event_loop()
        prb = None
        try:
            # `request_body` carries the protocol-native payload —
            # here, the bytes written to the socket. A port that accepts the
            # connection and says nothing records an empty response, which is
            # the honest record of what happened.
            async with capture.probe(
                "tcp",
                host,
                request_body=probe.decode("utf-8", errors="replace") if probe else "",
                port=port,
            ) as prb:
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, self._sync_tcp_read, host, port, probe),
                    timeout=self.CONNECT_TIMEOUT + self.BANNER_READ_TIMEOUT,
                )
                # Text for reading, hex for matching. See the module docstring:
                # two of these signatures match on raw bytes, and a binary
                # handshake does not survive a lossy decode.
                prb.responded(
                    data.decode("utf-8", errors="replace") if data else "",
                    raw_hex=data.hex() if data else "",
                )
        except (TimeoutError, Exception) as exc:
            logger.debug(f"TCP read failed {host}:{port}: {exc}")
        return prb.exchange if prb is not None else None

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

    def _redis_auth_from(self, exchange: Exchange | None) -> bool:
        """Whether Redis asked for a password, read off the INFO probe.

        The I/O half of this lives in `_grab_banner`, which sends
        `REDIS_AUTH_PROBE`; this is the reading, so a stored exchange answers the
        same question without a socket. Unclear still means "assume auth
        required": claiming an open Redis on an ambiguous answer is the expensive
        mistake.
        """
        if exchange is not None and _responded(exchange):
            text = exchange.response_body
            if "-NOAUTH" in text or "DENIED" in text.upper():
                return True
            if "redis_version" in text or "# Server" in text:
                return False
        return True

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one endpoint's recorded banner."""
        exchanges = list(evidence)
        port = ctx.target.port if ctx.target else _port_of(exchanges)
        banner_info = self._banner_from(exchanges, port if isinstance(port, int) else 0)
        if banner_info is None:
            return []

        host = ctx.host
        endpoint = f"{host}:{port}"
        service_name = banner_info["service"]
        version = banner_info.get("version")
        banner = banner_info.get("banner", "")[:200]
        auth_required = banner_info.get("auth_required")
        version_str = f" {version}" if version else ""

        evidence_ids = [e.id for e in exchanges]
        verdicts: list[Verdict] = []

        # ── What is listening here ──────────────────────────
        verdicts.append(
            Verdict(
                severity="info",
                # The banner is verbatim; naming the service from it is a
                # signature match, and these signatures are short — "220 " is
                # shared by SMTP and FTP and separated only by port number.
                confidence=0.9 if service_name != "unknown" else 0.99,
                discriminator=f"banner-{port}",
                title=f"{service_name}{version_str} detected: {endpoint}",
                description=(
                    f"{service_name}{version_str} service identified on {endpoint} "
                    f"via banner grabbing."
                ),
                evidence=f"Banner: {banner}",
                reasoning=(
                    f"Banner matched the {service_name} signature"
                    if service_name != "unknown"
                    else "A banner was returned but matched no known signature"
                ),
                signals={"service": service_name, "version": version},
                raw_data=banner_info,
                evidence_ids=evidence_ids,
            )
        )

        # ── No authentication at all ───────────────────────
        if auth_required is False:
            # Find the severity for this service
            severity = "high"
            for sig in BANNER_SIGNATURES:
                if sig["name"] == service_name:
                    severity = sig.get("no_auth_severity", "high")
                    break

            if severity in ("critical", "high"):
                verdicts.append(
                    Verdict(
                        severity=severity,
                        # The strongest verdict in the suite, and it is earned:
                        # the check ran a command and the service answered it.
                        # This is compliance, not a guess.
                        confidence=0.95,
                        discriminator=f"noauth-{port}",
                        title=(
                            f"{service_name} accepting commands without authentication: {endpoint}"
                        ),
                        description=(
                            f"{service_name} on {endpoint} does not require "
                            f"authentication. An attacker with network access can "
                            f"read, modify, or delete data. This is a critical "
                            f"security misconfiguration."
                        ),
                        evidence=(
                            f"Service: {service_name}{version_str} | "
                            f"Auth required: False | Banner: {banner}"
                        ),
                        reasoning=(
                            f"{service_name} answered a command without being sent credentials"
                        ),
                        signals={"service": service_name, "auth_required": False},
                        references=[
                            "CWE-306 — Missing Authentication for Critical Function",
                        ],
                        evidence_ids=evidence_ids,
                    )
                )

        # ── Version disclosure ────────────────────────────
        if version and service_name != "unknown":
            verdicts.append(
                Verdict(
                    severity="low",
                    # Read from a documented position in the banner.
                    confidence=0.95,
                    discriminator=f"version-{port}",
                    title=f"Service version disclosed: {service_name}{version_str} on {endpoint}",
                    description=(
                        f"{service_name} on {endpoint} discloses its version "
                        f"({version}) in the connection banner. Version information "
                        f"aids attackers in identifying known vulnerabilities."
                    ),
                    evidence=f"Version: {version} | Banner: {banner}",
                    reasoning=f"Version string followed the {service_name} banner prefix",
                    signals={"version": version},
                    evidence_ids=evidence_ids,
                )
            )

        # ── A banner nothing recognises ────────────────────
        if service_name == "unknown" and banner:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # "Matches none of nine signatures" is a statement about the
                    # signature list, not about the service. It is `medium`
                    # because it asks for a human, not because it found one.
                    confidence=0.6,
                    discriminator=f"unknown-{port}",
                    title=f"Unidentified service with banner: {endpoint}",
                    description=(
                        f"An unidentified service on {endpoint} returned a banner "
                        f"that does not match known service signatures. Manual "
                        f"investigation is recommended."
                    ),
                    evidence=f"Banner (first 200 chars): {banner}",
                    reasoning=f"Banner matched none of the {len(BANNER_SIGNATURES)} signatures",
                    signals={"banner": banner},
                    evidence_ids=evidence_ids,
                )
            )

        return verdicts


def _responded(exchange: Exchange | None) -> bool:
    """True when this read came back with bytes."""
    return exchange is not None and exchange.error is None and bool(exchange.response_body)


def _is_auth_probe(exchange: Exchange | None) -> bool:
    """True for the Redis INFO probe, which is a question and not a banner."""
    if exchange is None:
        return False
    return (exchange.request_body or "") == REDIS_AUTH_PROBE.decode()


def _raw_bytes(exchange: Exchange) -> bytes:
    """The banner exactly as it arrived.

    `raw_hex` is written by `_tcp_read` and is the lossless copy; the decoded
    body is the readable one. Falling back to re-encoding the text keeps an
    exchange recorded before wave 2 — or by a test that builds one by hand —
    usable, at the cost of the bytes a lossy decode already dropped.
    """
    raw_hex = (exchange.response_headers or {}).get("raw_hex", "")
    if raw_hex:
        try:
            return bytes.fromhex(raw_hex)
        except ValueError:
            pass
    return exchange.response_body.encode("utf-8", errors="replace")


def _port_of(exchanges: list[Exchange]) -> int | str:
    """The port these reads were made against, off their request metadata."""
    for exchange in exchanges:
        port = (exchange.request_headers or {}).get("port", "")
        if port:
            try:
                return int(port)
            except (TypeError, ValueError):
                return port
    return ""
