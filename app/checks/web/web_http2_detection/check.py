"""
app/checks/web/http2_detection.py - HTTP/2 and HTTP/3 Detection

Detects HTTP/2 support via TLS ALPN negotiation and HTTP/3 (QUIC)
availability via the Alt-Svc response header. Useful for infrastructure
profiling and understanding the target's protocol capabilities.

**Probe/grade.** `check_service()` performs the ALPN
handshake and the HEAD request, hands both exchanges over, and judges nothing;
`grade()` re-reads them and names the protocol posture. The two exchanges are of
different protocols — one `tls`, one `http` — which is the first place in the
web suite a candidate carries mixed evidence; `grade()` tells them apart by
`Exchange.protocol` rather than by position.

`http_protocols` is an output, so the probe has to know the answer before a
grader runs. Both halves call `_protocols()` over the same exchanges (§6.2's two
parses, with one parser).

The confidences here separate three things this check used to assert
identically:

- **ALPN is proof.** The TLS handshake *selected* `h2`; there is nothing to
  interpret.
- **Alt-Svc is an advertisement.** This check never speaks QUIC, so every `h3`
  claim is the server's own word about a port nobody connected to.
- **"HTTP/1.1 only" is an absence claim, and on a plain-HTTP service it is
  barely tested at all** — ALPN needs TLS, so for `http://` the check never
  probed for h2 and is reporting the absence of a header.
"""

import logging
import socket
import ssl
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

logger = logging.getLogger(__name__)

# Known Alt-Svc protocol identifiers for HTTP/3
H3_PROTOCOLS = {"h3", "h3-29", "h3-28", "h3-27"}


class HTTP2DetectionCheck(ServiceIteratingCheck):
    """Detect HTTP/2 and HTTP/3 protocol support."""

    name = "web_http2_detection"
    description = "Check for HTTP/2 (ALPN) and HTTP/3 (Alt-Svc) protocol support"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["http_protocols"]
    service_types = ["http", "html", "api", "ai"]

    reason = (
        "Protocol detection profiles infrastructure maturity and identifies QUIC/HTTP3 endpoints"
    )
    references = ["RFC 7540", "RFC 9114"]
    techniques = ["protocol detection", "infrastructure profiling"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Handshake, request, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # One candidate per service: the four postures are mutually exclusive,
        # so the candidate stays undiscriminated and `grade()` names the one
        # that holds.
        candidate = self.create_candidate(host=service.host, target=service)

        # 1. Check HTTP/2 via TLS ALPN (only for HTTPS)
        if service.scheme == "https":
            prb = None
            try:
                # This handshake opens its own socket rather than
                # going through AsyncHttpClient, so it records its own evidence.
                # `tls`, like the other socket protocols, is opt-in.
                async with capture.probe(
                    "tls",
                    service.host,
                    request_body="ClientHello alpn=h2,http/1.1",
                    port=service.port,
                ) as prb:
                    alpn_protocol = self._check_alpn(service.host, service.port)
                    prb.responded(alpn_protocol or "")
            except Exception as e:
                logger.debug(f"ALPN check failed for {service.host}:{service.port}: {e}")
            # `probe()` sets `exchange` before re-raising, so a failed handshake
            # hands over its failure rather than nothing at all.
            if prb is not None:
                candidate.attach(prb.exchange)

        # 2. Check HTTP/3 via Alt-Svc header (works for both HTTP and HTTPS)
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                await self._rate_limit()
                resp = await client.head(service.url)
            candidate.attach(
                exchange_from_response(
                    resp,
                    check_name=self.name,
                    scan_id=context.get("scan_id") or "",
                    host=service.host,
                    method="HEAD",
                )
            )
        except Exception as e:
            result.errors.append(f"HTTP protocol detection error: {e}")

        result.candidates.append(candidate)
        # `alpn` is grading input, not part of this output's shape — the four
        # keys `http_protocols` has always carried are the four it still does.
        reading = _protocols(candidate.exchanges)
        result.outputs["http_protocols"] = {
            "h2": reading["h2"],
            "h3": reading["h3"],
            "protocols": reading["protocols"],
            "alt_svc": reading["alt_svc"],
        }
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded handshake and headers. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Name one service's protocol posture. Exactly one verdict."""
        exchanges = list(evidence)
        reading = _protocols(exchanges)
        h2 = reading["h2"]
        h3 = reading["h3"]
        alt_svc_value = reading["alt_svc"]
        # `h2` reached by ALPN is proof; reached by an `Upgrade: h2c` hint it is
        # an offer of cleartext h2, which is rarely actually usable.
        by_alpn = reading["alpn"] == "h2"
        tls_attempted = any(e.protocol == "tls" for e in exchanges)
        ids = [e.id for e in exchanges]
        endpoint = f"{ctx.host}:{ctx.target.port if ctx.target else ''}"

        if h2 and h3:
            return [
                Verdict(
                    severity="info",
                    # A compound claim is only as strong as its weaker half, and
                    # the h3 half was never verified over QUIC.
                    confidence=0.7,
                    discriminator="h2-h3",
                    title=f"HTTP/2 and HTTP/3 supported: {ctx.host}",
                    description=(
                        "Both HTTP/2 and HTTP/3 (QUIC) are available, indicating modern "
                        "infrastructure"
                    ),
                    evidence=f"ALPN: h2 | Alt-Svc: {alt_svc_value[:200]}",
                    reasoning=(
                        "h2 is settled by the ALPN selection; h3 rests on the Alt-Svc "
                        "advertisement, and no QUIC connection was attempted"
                        if by_alpn
                        else "both halves are the server's own word — an h2c upgrade hint "
                        "and an Alt-Svc advertisement, neither exercised"
                    ),
                    signals=reading,
                    references=["RFC 7540", "RFC 9114"],
                    evidence_ids=ids,
                )
            ]

        if h2:
            return [
                Verdict(
                    severity="info",
                    # ALPN negotiated h2: the handshake picked it, so there is
                    # nothing left to interpret. An h2c hint is only an offer.
                    confidence=0.99 if by_alpn else 0.6,
                    discriminator="h2-only",
                    title=f"HTTP/2 supported: {endpoint}",
                    description="HTTP/2 is supported via TLS ALPN negotiation",
                    evidence="TLS ALPN negotiated protocol: h2",
                    reasoning=(
                        "the TLS handshake selected h2"
                        if by_alpn
                        else "no ALPN h2; read from an `Upgrade: h2c` header, which offers "
                        "cleartext h2 rather than demonstrating it"
                    ),
                    signals=reading,
                    references=["RFC 7540"],
                    evidence_ids=ids,
                )
            ]

        if h3:
            return [
                Verdict(
                    severity="info",
                    # Alt-Svc is an advertisement. The QUIC port was never
                    # connected to, so this is the server's claim about itself.
                    confidence=0.7,
                    discriminator="h3-only",
                    title=f"HTTP/3 (QUIC) available: {ctx.host}",
                    description="HTTP/3 advertised via Alt-Svc header",
                    evidence=f"Alt-Svc: {alt_svc_value[:200]}",
                    reasoning=(
                        "Alt-Svc names an h3 protocol; no QUIC connection was attempted, "
                        "so availability is advertised rather than observed"
                    ),
                    signals=reading,
                    references=["RFC 9114"],
                    evidence_ids=ids,
                )
            ]

        return [
            Verdict(
                severity="info",
                # An absence claim, and how well tested it is depends entirely
                # on the scheme: over TLS the handshake actually offered h2 and
                # came back with http/1.1, whereas on a plain-HTTP service ALPN
                # never ran and this is the absence of one header.
                confidence=0.85 if tls_attempted else 0.5,
                discriminator="h1-only",
                title=f"HTTP/1.1 only: {endpoint}",
                description="No HTTP/2 or HTTP/3 support detected — legacy HTTP/1.1 only",
                evidence="No ALPN h2 negotiation, no Alt-Svc header with h3",
                reasoning=(
                    "ALPN offered h2 and the server chose otherwise, and Alt-Svc named no h3"
                    if tls_attempted
                    else "no TLS, so ALPN never ran — h2 is untested here and only the "
                    "absence of Alt-Svc and Upgrade headers was observed"
                ),
                signals=reading,
                evidence_ids=ids,
            )
        ]

    def _check_alpn(self, host: str, port: int) -> str | None:
        """Perform TLS handshake and return negotiated ALPN protocol."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    return tls_sock.selected_alpn_protocol()
        except (TimeoutError, ssl.SSLError, OSError):
            return None


# ── The one parser, called by both halves ────────────────────────────


def _protocols(exchanges: list[Exchange]) -> dict[str, Any]:
    """Read one service's protocol support out of its recorded exchanges.

    `alpn` is the extra the grader needs and the output does not: which of the
    two routes to `h2` actually answered, so a verdict can say whether it was
    negotiated or merely offered.
    """
    alpn = ""
    alt_svc = ""
    upgrade = ""

    for exchange in exchanges:
        if exchange.protocol == "tls":
            if exchange.error is None:
                alpn = exchange.response_body or ""
        elif exchange.protocol == "http" and exchange.error is None:
            headers = extract_headers_dict(exchange.response_headers or {})
            alt_svc = headers.get("alt-svc", "")
            upgrade = headers.get("upgrade", "").lower()

    protocols: list[str] = []
    h2 = False

    if alpn:
        if alpn == "h2":
            h2 = True
            protocols.append("h2")
        else:
            protocols.append(alpn)

    h3 = any(proto in alt_svc.lower() for proto in H3_PROTOCOLS)
    if h3:
        protocols.append("h3")

    # Check for HTTP/2 upgrade hint in headers (non-TLS)
    if not h2 and "h2c" in upgrade:
        h2 = True
        protocols.append("h2c")

    return {
        "h2": h2,
        "h3": h3,
        "protocols": protocols,
        "alt_svc": alt_svc,
        "alpn": alpn,
    }
