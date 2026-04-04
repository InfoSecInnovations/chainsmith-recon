"""
app/checks/web/http2_detection.py - HTTP/2 and HTTP/3 Detection

Detects HTTP/2 support via TLS ALPN negotiation and HTTP/3 (QUIC)
availability via the Alt-Svc response header. Useful for infrastructure
profiling and understanding the target's protocol capabilities.
"""

import logging
import socket
import ssl
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

# Known Alt-Svc protocol identifiers for HTTP/3
H3_PROTOCOLS = {"h3", "h3-29", "h3-28", "h3-27"}


class HTTP2DetectionCheck(ServiceIteratingCheck):
    """Detect HTTP/2 and HTTP/3 protocol support."""

    name = "http2_detection"
    description = "Check for HTTP/2 (ALPN) and HTTP/3 (Alt-Svc) protocol support"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["http_protocols"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 30.0
    delay_between_targets = 0.2

    reason = (
        "Protocol detection profiles infrastructure maturity and identifies QUIC/HTTP3 endpoints"
    )
    references = ["RFC 7540", "RFC 9114"]
    techniques = ["protocol detection", "infrastructure profiling"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        protocols_detected: list[str] = []
        h2_supported = False
        h3_available = False
        alt_svc_value = ""

        # 1. Check HTTP/2 via TLS ALPN (only for HTTPS)
        if service.scheme == "https":
            try:
                alpn_protocol = self._check_alpn(service.host, service.port)
                if alpn_protocol:
                    if alpn_protocol == "h2":
                        h2_supported = True
                        protocols_detected.append("h2")
                    else:
                        protocols_detected.append(alpn_protocol)
            except Exception as e:
                logger.debug(f"ALPN check failed for {service.host}:{service.port}: {e}")

        # 2. Check HTTP/3 via Alt-Svc header (works for both HTTP and HTTPS)
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                await self._rate_limit()
                resp = await client.head(service.url)
                if not resp.error:
                    alt_svc = resp.headers.get("alt-svc", "")
                    if alt_svc:
                        alt_svc_value = alt_svc
                        for proto in H3_PROTOCOLS:
                            if proto in alt_svc.lower():
                                h3_available = True
                                protocols_detected.append("h3")
                                break

                    # Check for HTTP/2 upgrade hint in headers (non-TLS)
                    if not h2_supported:
                        upgrade = resp.headers.get("upgrade", "").lower()
                        if "h2c" in upgrade:
                            h2_supported = True
                            protocols_detected.append("h2c")
        except Exception as e:
            result.errors.append(f"HTTP protocol detection error: {e}")

        # Generate findings
        if h2_supported and h3_available:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"HTTP/2 and HTTP/3 supported: {service.host}",
                    description="Both HTTP/2 and HTTP/3 (QUIC) are available, indicating modern infrastructure",
                    severity="info",
                    evidence=f"ALPN: h2 | Alt-Svc: {alt_svc_value[:200]}",
                    host=service.host,
                    discriminator="h2-h3",
                    target=service,
                    references=["RFC 7540", "RFC 9114"],
                )
            )
        elif h2_supported:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"HTTP/2 supported: {service.host}:{service.port}",
                    description="HTTP/2 is supported via TLS ALPN negotiation",
                    severity="info",
                    evidence="TLS ALPN negotiated protocol: h2",
                    host=service.host,
                    discriminator="h2-only",
                    target=service,
                    references=["RFC 7540"],
                )
            )
        elif h3_available:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"HTTP/3 (QUIC) available: {service.host}",
                    description="HTTP/3 advertised via Alt-Svc header",
                    severity="info",
                    evidence=f"Alt-Svc: {alt_svc_value[:200]}",
                    host=service.host,
                    discriminator="h3-only",
                    target=service,
                    references=["RFC 9114"],
                )
            )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"HTTP/1.1 only: {service.host}:{service.port}",
                    description="No HTTP/2 or HTTP/3 support detected — legacy HTTP/1.1 only",
                    severity="info",
                    evidence="No ALPN h2 negotiation, no Alt-Svc header with h3",
                    host=service.host,
                    discriminator="h1-only",
                    target=service,
                )
            )

        result.outputs["http_protocols"] = {
            "h2": h2_supported,
            "h3": h3_available,
            "protocols": protocols_detected,
            "alt_svc": alt_svc_value,
        }
        return result

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
