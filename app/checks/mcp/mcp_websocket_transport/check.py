"""
app/checks/mcp/websocket_transport.py - WebSocket Transport Discovery

Discovers MCP servers accessible via WebSocket transport.
The existing MCPDiscoveryCheck only detects SSE and HTTP transports.
This check probes for WebSocket upgrade on common MCP paths.

**Probe/grade.** The probe attempts a WebSocket upgrade on
each candidate path for each server, records every GET it sends, and hands them
over as one candidate per server. `grade()` re-reads the recorded exchanges,
recovers each path from its own `request_url`, and places the verdict: a 101
Switching Protocols is the discovery, an `Upgrade: websocket` header without the
101 is a partial, and a server whose paths all refused is the not-found info.
`_upgrade_state()` is the one reading both halves share (§0.12).

`grade()` never sees the candidate's discriminator (§0.16); which path an
exchange exercised is read from its recorded URL. Whether the HTTP side demanded
auth — the difference between a `medium` discovery and a `high` bypass — is the
discovery's own `auth_required` claim, recovered from `ctx.context`.

**Fixed**: the discriminators embed a path
(`ws-<path>` / `ws-partial-<path>`), an unbounded set, so there is no
`observations:` map and `grade()` places the tier. Confidence is where the split
pays: a 101 is a real protocol switch, but the *auth bypass* it implies rests on
a discovery-time claim that the HTTP endpoint required auth, never re-verified
here.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/transports/
"""

import base64
import os
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig


class WebSocketTransportCheck(BaseCheck):
    """
    Discover MCP WebSocket transport endpoints.

    Attempts WebSocket upgrade on common MCP paths and discovered
    MCP server endpoints. Checks if WebSocket endpoints have
    different auth requirements than HTTP endpoints.
    """

    name = "mcp_websocket_transport"
    description = "Discover MCP servers accessible via WebSocket transport"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_websocket_servers"]
    service_types = ["ai", "api", "http"]

    reason = "MCP may be accessible via WebSocket with different auth than HTTP endpoints"
    references = [
        "MCP Specification - Transports - https://spec.modelcontextprotocol.io/specification/basic/transports/",
        "RFC 6455 - The WebSocket Protocol",
    ]
    techniques = ["transport discovery", "protocol detection", "authentication bypass"]

    # WebSocket paths to probe
    WS_PATHS = [
        "/ws",
        "/mcp/ws",
        "/v1/mcp/ws",
        "/api/mcp/ws",
        "/socket",
        "/mcp/socket",
        "/mcp/websocket",
        "/ws/mcp",
    ]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        ws_servers = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            base_url = service_data.get("url", "")
            base_path = server.get("path", "")

            if not base_url:
                continue

            exchanges: list[Exchange] = []

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Build paths to test: standard WS paths + discovered MCP path
                    paths = list(self.WS_PATHS)
                    if base_path and base_path not in paths:
                        paths.append(base_path)

                    for path in paths:
                        url = f"{base_url.rstrip('/')}{path}"
                        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
                        ws_headers = {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Version": "13",
                            "Sec-WebSocket-Key": ws_key,
                        }

                        resp = await client.get(url, headers=ws_headers)
                        exchange = exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=host,
                            method="GET",
                            request_headers=ws_headers,
                        )
                        exchanges.append(exchange)

                        if resp.error:
                            continue

                        if resp.status_code == 101:
                            ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
                            ws_servers.append(
                                {
                                    "url": ws_url,
                                    "http_url": url,
                                    "path": path,
                                    "host": host,
                                    "service": service_data,
                                }
                            )
                            break  # Found WS on this server

            except Exception as e:
                result.errors.append(f"{base_url}: {e}")

            if exchanges:
                candidate = self.create_candidate(
                    host=host,
                    discriminator=f"ws-server-{host}",
                    target_url=base_url,
                )
                for exchange in exchanges:
                    candidate.attach(exchange)
                result.candidates.append(candidate)

        if ws_servers:
            result.outputs["mcp_websocket_servers"] = ws_servers

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        server_auth = self._http_auth_required(ctx)

        verdicts: list[Verdict] = []
        for exchange in evidence:
            if exchange.error:
                continue
            path = self._path_of(exchange)
            state = self._upgrade_state(exchange)

            if state == "switched":
                verdicts.append(self._ws_verdict(exchange, path, server_auth, ctx))
                return verdicts
            if state == "partial":
                verdicts.append(self._partial_verdict(exchange, path, ctx))

        if verdicts:
            return verdicts

        return [self._not_found_verdict(ctx)]

    def _ws_verdict(
        self, exchange: Exchange, path: str, server_auth: Any, ctx: GradeContext
    ) -> Verdict:
        disc = f"ws-{path.strip('/').replace('/', '-') or 'root'}"
        url = exchange.request_url or ""
        ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
        if server_auth is True:
            return Verdict(
                severity="high",
                confidence=0.6,
                discriminator=disc,
                title="WebSocket MCP endpoint requires no authentication (HTTP endpoint requires auth)",
                description=(
                    f"The HTTP MCP endpoint requires authentication, but the WebSocket endpoint "
                    f"at {path} accepted the upgrade without credentials. This allows bypassing "
                    "HTTP auth via WebSocket."
                ),
                evidence=f"URL: {url}\nStatus: 101 Switching Protocols\nPath: {path}",
                reasoning=(
                    "the 101 is a real protocol switch, but the bypass rests on the discovery's "
                    "claim that the HTTP endpoint required auth, which was not re-verified here — "
                    "if that claim is stale the WS endpoint is merely open, not a bypass"
                ),
                signals={"status": 101, "http_auth_required": True},
                references=self.references,
                raw_data={"url": url, "ws_url": ws_url, "path": path},
                tier=ctx.tier,
                evidence_ids=[exchange.id],
            )
        return Verdict(
            severity="medium",
            confidence=0.7,
            discriminator=disc,
            title=f"MCP WebSocket transport discovered: {ws_url}",
            description=(
                f"MCP server accepts WebSocket connections at {path}. WebSocket transport may "
                "have different security properties than HTTP/SSE endpoints."
            ),
            evidence=f"URL: {url}\nStatus: 101 Switching Protocols\nPath: {path}",
            reasoning=(
                "a 101 Switching Protocols is a definitive upgrade, but 'different security "
                "properties' is inferred from the transport alone — nothing was exchanged over "
                "the socket to show the WS side is actually less guarded"
            ),
            signals={"status": 101, "http_auth_required": bool(server_auth)},
            references=self.references,
            raw_data={"url": url, "ws_url": ws_url, "path": path},
            tier=ctx.tier,
            evidence_ids=[exchange.id],
        )

    def _partial_verdict(self, exchange: Exchange, path: str, ctx: GradeContext) -> Verdict:
        status = exchange.response_status
        upgrade = self._header(exchange, "upgrade")
        return Verdict(
            severity="info",
            confidence=0.5,
            discriminator=f"ws-partial-{path.strip('/').replace('/', '-') or 'root'}",
            title=f"WebSocket upgrade indicated but not completed at {path}",
            description=(
                f"Server returned Upgrade: websocket header at {path} but status was {status} "
                "instead of 101. WebSocket may require additional parameters."
            ),
            evidence=f"URL: {exchange.request_url}\nStatus: {status}\nUpgrade: {upgrade}",
            reasoning=(
                "an Upgrade header without the 101 says the server knows the protocol but did "
                "not switch; a proxy can echo the request's Upgrade header without any WS support"
            ),
            signals={"status": status, "upgrade": upgrade},
            references=self.references,
            raw_data={"url": exchange.request_url, "status": status},
            tier=ctx.tier,
            evidence_ids=[exchange.id],
        )

    def _not_found_verdict(self, ctx: GradeContext) -> Verdict:
        return Verdict(
            severity="info",
            confidence=0.5,
            discriminator="ws-not-found",
            title="WebSocket upgrade rejected on all tested paths",
            description="No MCP WebSocket transport endpoints were discovered.",
            evidence=f"Paths tested: {', '.join(self.WS_PATHS)}",
            reasoning=(
                "the absence is bounded by a fixed path list; a WebSocket endpoint on any path "
                "not in that list would be missed"
            ),
            signals={"paths_tested": len(self.WS_PATHS)},
            references=self.references,
            tier=ctx.tier,
        )

    # ── The reading both halves share ────────────────────────────────

    @staticmethod
    def _upgrade_state(exchange: Exchange) -> str:
        """`switched` for a 101, `partial` for an `Upgrade: websocket` header
        without the 101, `none` otherwise."""
        if exchange.response_status == 101:
            return "switched"
        upgrade = WebSocketTransportCheck._header(exchange, "upgrade")
        if upgrade.lower() == "websocket":
            return "partial"
        return "none"

    @staticmethod
    def _header(exchange: Exchange, name: str) -> str:
        for k, v in (exchange.response_headers or {}).items():
            if k.lower() == name.lower():
                return v
        return ""

    @staticmethod
    def _path_of(exchange: Exchange) -> str:
        return urlparse(exchange.request_url or "").path or "/"

    @staticmethod
    def _http_auth_required(ctx: GradeContext) -> Any:
        for server in ctx.context.get("mcp_servers", []):
            if server.get("service", {}).get("host") == ctx.host:
                return server.get("auth_required")
        return None
