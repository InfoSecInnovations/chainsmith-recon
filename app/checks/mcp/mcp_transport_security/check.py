"""
app/checks/mcp/transport_security.py - Transport Security Analysis

Analyzes security of MCP transport layer:
- Plain HTTP (no TLS)
- SSE authentication per-connection
- CORS misconfiguration
- Origin header validation

**Probe/grade.** The probe records a CORS preflight
(`OPTIONS` with a hostile Origin), an Origin-validation `POST`, and — for SSE
transports — an unauthenticated stream `GET`, one candidate per server carrying
its `target_url` (§0.15). `_findings()` is the one analyser both halves call
(§0.12): each recorded exchange is attributed by its request *method* (§0.16),
and the plain-HTTP finding is derived from the target URL's scheme, which needs
no request at all. `grade()` places the severity.

The "transport adequate" verdict is graded per server: `grade()` emits it when
that server's evidence yields no finding. It used to be one probe-emitted
summary across every server, which put an ungraded judgement — with no
confidence — outside the grade path; per server it is identical for the
single-server case and states how much was actually tested.

**Fixed**: the discriminators are a closed set, so the
contract carries the full `observations:` map, each at its single severity.
Confidence is where the split pays: a wildcard/reflected CORS header is the
disclosure itself (high certainty), while "no Origin validation" reads a 200 to
a spoofed Origin — a server that never validated returns the same as one that
whitelisted this caller.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/transports/
"""

from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

CORS_HEADERS = {
    "Origin": "https://evil.attacker.com",
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "Content-Type",
}
ORIGIN_HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://evil.attacker.com",
    "Referer": "https://evil.attacker.com/attack.html",
}
SSE_HEADERS = {"Accept": "text/event-stream"}


class TransportSecurityCheck(BaseCheck):
    """
    Analyze MCP transport layer security.

    Checks for plaintext HTTP, SSE auth, CORS headers,
    and Origin header validation on discovered MCP endpoints.
    """

    name = "mcp_transport_security"
    description = "Analyze MCP transport layer security (TLS, CORS, SSE auth)"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_transport_security"]
    service_types = ["ai", "api", "http"]

    reason = "MCP endpoints may transmit tool results and credentials in cleartext or allow cross-origin access"
    references = [
        "MCP Specification - Transports - https://spec.modelcontextprotocol.io/specification/basic/transports/",
        "OWASP - Transport Layer Security",
    ]
    techniques = ["transport analysis", "CORS testing", "TLS verification"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        transport_observations = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            scheme = service_data.get("scheme", "http")
            transport = server.get("transport", "http")

            exchanges: list[Exchange] = []
            try:
                async with AsyncHttpClient(cfg) as client:
                    # CORS preflight with a hostile origin.
                    resp = await client.options(server_url, headers=CORS_HEADERS)
                    exchanges.append(
                        exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=host,
                            method="OPTIONS",
                            request_headers=CORS_HEADERS,
                        )
                    )

                    # Origin validation on a real JSON-RPC POST.
                    payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
                    resp = await client.post(server_url, json=payload, headers=ORIGIN_HEADERS)
                    exchanges.append(
                        exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=host,
                            method="POST",
                            request_headers=ORIGIN_HEADERS,
                            request_json=payload,
                        )
                    )

                    # SSE stream reachable without per-connection auth.
                    if transport == "sse":
                        resp = await client.get(server_url, headers=SSE_HEADERS)
                        exchanges.append(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=host,
                                method="GET",
                                request_headers=SSE_HEADERS,
                            )
                        )
            except Exception as e:
                result.errors.append(f"Transport security test: {e}")

            findings = self._findings(server_url, scheme, exchanges)
            server_transport = {
                "url": server_url,
                "host": host,
                "tls": scheme == "https",
                "transport_type": transport,
                "issues": [f["tag"] for f in findings],
            }
            transport_observations.append(server_transport)

            candidate = self.create_candidate(host=host, target_url=server_url)
            for exchange in exchanges:
                candidate.attach(exchange)
            result.candidates.append(candidate)

        if transport_observations:
            result.outputs["mcp_transport_security"] = transport_observations

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        server_url = ctx.target_url or ""
        scheme = urlparse(server_url).scheme or "http"
        exchanges = list(evidence)
        findings = self._findings(server_url, scheme, exchanges)

        if not findings:
            return [self._adequate(server_url, exchanges, ctx)]

        return [
            Verdict(
                severity=f["severity"],
                confidence=f["confidence"],
                discriminator=f["tag_discriminator"],
                title=f["title"],
                description=f["description"],
                evidence=f["evidence"],
                reasoning=f["reasoning"],
                signals=f.get("signals", {}),
                references=self.references,
                raw_data=f.get("raw_data"),
                tier=ctx.tier,
                evidence_ids=f["evidence_ids"],
            )
            for f in findings
        ]

    def _adequate(self, server_url: str, exchanges: list[Exchange], ctx: GradeContext) -> Verdict:
        """The no-finding verdict for one server, as confident as what was tested."""
        answered = [
            method
            for method in ("OPTIONS", "POST")
            if (ex := self._by_method(exchanges, method)) is not None and not ex.error
        ]
        if len(answered) == 2:
            confidence, why = (
                0.6,
                (
                    "TLS is in use, the hostile-Origin preflight drew no permissive ACAO and the "
                    "spoofed-Origin POST returned no tool list; 'adequate' is the absence of those "
                    "specific findings, and a server that refused the POST for an unrelated reason "
                    "(auth, wrong path) reads the same as one validating Origin"
                ),
            )
        else:
            confidence, why = (
                0.3,
                (
                    "TLS is in use, but the CORS preflight or the Origin POST never produced a "
                    "response, so 'adequate' here mostly means untested"
                ),
            )
        return Verdict(
            severity="info",
            confidence=confidence,
            discriminator="transport-ok",
            title="Transport security adequate: TLS + origin validation",
            description="MCP transport layer security checks passed.",
            evidence=f"Server: {server_url}",
            reasoning=why,
            signals={"answered": answered},
            tier=ctx.tier,
            evidence_ids=[e.id for e in exchanges],
        )

    # ── The analyser both halves share ───────────────────────────────

    def _findings(self, server_url: str, scheme: str, exchanges: list[Exchange]) -> list[dict]:
        """Every transport finding for one server, in the original test order.

        Attributes each recorded exchange by its request method; the plain-HTTP
        finding is derived from the scheme and carries no exchange.
        """
        findings: list[dict] = []

        # Test 1: Plain HTTP — derived from the scheme, no request needed.
        if scheme != "https":
            findings.append(
                {
                    "tag": "no_tls",
                    "tag_discriminator": "no-tls",
                    "severity": "high",
                    "confidence": 0.95,
                    "title": "MCP served over plain HTTP (no TLS)",
                    "description": (
                        f"The MCP endpoint at {server_url} is served over plain HTTP. "
                        "Credentials, tool invocations, and results are transmitted in cleartext, "
                        "allowing network interception."
                    ),
                    "evidence": f"URL: {server_url}\nScheme: {scheme}",
                    "reasoning": (
                        "the endpoint URL is an http:// scheme, which is the cleartext exposure "
                        "itself; the only softening is that a TLS-terminating proxy could sit in "
                        "front unseen from here"
                    ),
                    "raw_data": {"url": server_url, "scheme": scheme},
                    "evidence_ids": [],
                }
            )

        options_ex = self._by_method(exchanges, "OPTIONS")
        if options_ex is not None and not options_ex.error:
            acao = self._header(options_ex, "access-control-allow-origin")
            if acao == "*":
                findings.append(
                    {
                        "tag": "cors_wildcard",
                        "tag_discriminator": "cors-wildcard",
                        "severity": "high",
                        "confidence": 0.9,
                        "title": "MCP endpoint allows cross-origin requests from any origin (CORS: *)",
                        "description": (
                            "The MCP endpoint returns Access-Control-Allow-Origin: *, "
                            "allowing browser-based JavaScript from any origin to interact with "
                            "the MCP server. This enables cross-site MCP exploitation."
                        ),
                        "evidence": f"URL: {server_url}\nAccess-Control-Allow-Origin: *",
                        "reasoning": (
                            "the server returned Access-Control-Allow-Origin: * in the preflight, "
                            "which is the misconfiguration in the bytes; a wildcard ACAO does not "
                            "expose credentialed requests, so the impact depends on whether auth "
                            "rides cookies"
                        ),
                        "raw_data": {"acao": acao},
                        "evidence_ids": [options_ex.id],
                    }
                )
            elif acao == "https://evil.attacker.com":
                findings.append(
                    {
                        "tag": "cors_reflects_origin",
                        "tag_discriminator": "cors-reflect",
                        "severity": "high",
                        "confidence": 0.9,
                        "title": "MCP endpoint reflects arbitrary Origin in CORS response",
                        "description": (
                            "The MCP endpoint reflects the request Origin header in "
                            "Access-Control-Allow-Origin, accepting cross-origin requests from any domain."
                        ),
                        "evidence": (
                            f"URL: {server_url}\nOrigin sent: https://evil.attacker.com\nACAO: {acao}"
                        ),
                        "reasoning": (
                            "the server echoed our hostile Origin back in ACAO, which combined "
                            "with credentialed CORS is the full cross-site vector; a single "
                            "reflected value is conclusive for the origin tested"
                        ),
                        "raw_data": {"acao": acao},
                        "evidence_ids": [options_ex.id],
                    }
                )

        post_ex = self._by_method(exchanges, "POST")
        if post_ex is not None and not post_ex.error:
            body = (post_ex.response_body or "").lower()
            if post_ex.response_status == 200 and '"tools"' in body:
                findings.append(
                    {
                        "tag": "no_origin_validation",
                        "tag_discriminator": "no-origin-check",
                        "severity": "medium",
                        "confidence": 0.5,
                        "title": "MCP endpoint does not validate Origin header",
                        "description": (
                            "The MCP server processes requests with a foreign Origin header, "
                            "indicating no Origin/Referer validation. Combined with permissive "
                            "CORS, this enables browser-based MCP attacks."
                        ),
                        "evidence": (
                            f"URL: {server_url}\nSpoofed Origin: https://evil.attacker.com\n"
                            f"Status: {post_ex.response_status}"
                        ),
                        "reasoning": (
                            "a 200 with a tool list came back despite a spoofed Origin, but that "
                            "is not-rejected, not proof of missing validation — a server that "
                            "never checked Origin and one that whitelisted this caller look the "
                            "same, and a browser would still be blocked by CORS without a "
                            "permissive ACAO"
                        ),
                        "raw_data": {"status": post_ex.response_status},
                        "evidence_ids": [post_ex.id],
                    }
                )

        get_ex = self._by_method(exchanges, "GET")
        if get_ex is not None and not get_ex.error:
            content_type = self._header(get_ex, "content-type") or ""
            if get_ex.response_status == 200 and "text/event-stream" in content_type:
                findings.append(
                    {
                        "tag": "sse_no_auth",
                        "tag_discriminator": "sse-no-auth",
                        "severity": "medium",
                        "confidence": 0.65,
                        "title": "SSE stream accessible without per-connection authentication",
                        "description": (
                            "The MCP SSE stream endpoint can be accessed without authentication. "
                            "An attacker can subscribe to the event stream and observe tool invocations "
                            "and results."
                        ),
                        "evidence": (
                            f"URL: {server_url}\nContent-Type: {content_type}\n"
                            f"Status: {get_ex.response_status}"
                        ),
                        "reasoning": (
                            "an unauthenticated GET opened an event-stream (200 + "
                            "text/event-stream), so the stream is reachable; what rides it is not "
                            "read here, so an empty or idle stream would look identical"
                        ),
                        "raw_data": {
                            "content_type": content_type,
                            "status": get_ex.response_status,
                        },
                        "evidence_ids": [get_ex.id],
                    }
                )

        return findings

    @staticmethod
    def _by_method(exchanges: list[Exchange], method: str) -> Exchange | None:
        for exchange in exchanges:
            if (exchange.request_method or "").upper() == method:
                return exchange
        return None

    @staticmethod
    def _header(exchange: Exchange, name: str) -> str:
        for key, value in (exchange.response_headers or {}).items():
            if key.lower() == name:
                return value
        return ""
