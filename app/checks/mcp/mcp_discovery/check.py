"""
app/checks/mcp/discovery.py - MCP Server Discovery

Discovers Model Context Protocol (MCP) server endpoints on target services.
Probes well-known paths, checks for MCP-specific headers, and identifies
transport types and capabilities.

**Probe/grade.** The probe walks the MCP paths in order,
GET then a JSON-RPC `initialize` POST, records every request it sends, and stops
at the first path that answers like an MCP server — one candidate per service,
carrying that path's `target_url` (§0.15). `_discover()` is the one parser both
halves call (§0.12): the probe reads its `mcp_servers` output off the exchanges
it just recorded, and `grade()` re-reads the same bytes and places severity.
Which path won is recovered from the exchanges' own request URLs, never a
remembered value (§0.16).

**Fixed**: the discriminator embeds the path
(`mcp-<path>`), an unbounded set, so the contract declares no `observations:`
map and `grade()` places the tier. Confidence comes from *what* matched: an
`Mcp-Session-Id` header is a header only an MCP server sets, while the
`mcp-keywords` fallback — the words "tools"/"resources" in any JSON body — is
what a generic REST API at `/mcp` looks like too.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/transports/
"""

import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}


class MCPDiscoveryCheck(ServiceIteratingCheck):
    """
    Discover MCP server endpoints on services.

    Probes common MCP paths and identifies servers by:
    - Well-known MCP endpoint responses
    - MCP-specific headers (Mcp-Session-Id, etc.)
    - JSON-RPC 2.0 response patterns with MCP methods

    Backlog (future expansion):
    - WebSocket transport detection
    - stdio transport via process spawning
    - MCP capability negotiation via initialize handshake
    """

    name = "mcp_discovery"
    description = "Discover Model Context Protocol (MCP) server endpoints"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["mcp_servers"]
    service_types = ["ai", "api", "http"]

    reason = "MCP servers expose tool-calling interfaces that may allow command execution, file access, or data exfiltration"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
    ]
    techniques = ["endpoint discovery", "protocol fingerprinting", "API enumeration"]

    # Paths to probe for MCP endpoints
    MCP_PATHS = [
        "/.well-known/mcp",
        "/mcp",
        "/mcp/sse",
        "/v1/mcp",
        "/api/mcp",
        "/mcp/v1",
        "/sse",
        "/events",
    ]

    # Headers that indicate MCP server presence
    MCP_HEADERS = [
        "mcp-session-id",
        "mcp-server-version",
        "x-mcp-version",
    ]

    # Response body patterns indicating MCP
    MCP_BODY_PATTERNS = [
        '"jsonrpc"',
        '"method"',
        "tools/list",
        "resources/list",
        "prompts/list",
        "initialize",
        "notifications/initialized",
    ]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        exchanges: list[Exchange] = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.MCP_PATHS:
                    url = service.with_path(path)

                    # Try GET first (SSE endpoints, well-known)
                    get_resp = await client.get(url)
                    exchanges.append(
                        exchange_from_response(
                            get_resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                    if self._server_info_from(exchanges[-1]) is None:
                        # Try POST with JSON-RPC initialize
                        payload = {
                            "jsonrpc": "2.0",
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "chainsmith-recon", "version": "1.0"},
                            },
                            "id": 1,
                        }
                        post_resp = await client.post(url, json=payload, headers=JSON_HEADERS)
                        exchanges.append(
                            exchange_from_response(
                                post_resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=service.host,
                                method="POST",
                                request_headers=JSON_HEADERS,
                                request_json=payload,
                            )
                        )
                        if self._server_info_from(exchanges[-1]) is None:
                            continue

                    # Found MCP on this service, don't probe remaining paths.
                    break

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        found = self._discover(exchanges)
        if found is None:
            return result

        path, url, server_info, transport, _win, _get = found
        server_info = dict(server_info)
        server_info["transport"] = transport
        server_info["service"] = service.to_dict()

        candidate = self.create_candidate(
            host=service.host,
            discriminator=f"mcp-{path.strip('/').replace('/', '-')}",
            target=service,
            target_url=url,
        )
        for exchange in exchanges:
            candidate.attach(exchange)
        result.candidates.append(candidate)

        result.outputs["mcp_servers"] = [
            {
                "url": url,
                "path": path,
                "transport": transport,
                "capabilities": server_info.get("capabilities", []),
                "auth_required": server_info.get("auth_required"),
                "server_info": server_info.get("server_info", {}),
                "service": service.to_dict(),
            }
        ]

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        found = self._discover(list(evidence))
        if found is None:
            return []
        path, url, server_info, transport, win, get_ex = found
        server_info = dict(server_info)
        server_info["transport"] = transport

        capabilities = server_info.get("capabilities")
        severity = "medium" if capabilities else "info"
        confidence, why = self._confidence(server_info)

        evidence_ids = [win.id]
        if get_ex is not None and get_ex.id != win.id:
            evidence_ids.append(get_ex.id)

        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=f"mcp-{path.strip('/').replace('/', '-')}",
                title=f"MCP server discovered: {path}",
                description=self._build_description(server_info),
                evidence=self._build_evidence(server_info),
                reasoning=why,
                signals={
                    "indicators": server_info.get("indicators", []),
                    "transport": transport,
                    "auth_required": server_info.get("auth_required"),
                },
                references=self.references,
                raw_data=server_info,
                tier=ctx.tier,
                evidence_ids=evidence_ids,
            )
        ]

    @staticmethod
    def _confidence(server_info: dict) -> tuple[float, str]:
        indicators = server_info.get("indicators", [])
        if server_info.get("auth_required") and len(indicators) == 1:
            return 0.55, (
                "the only signal is a 401, so an MCP server is inferred from a path that "
                "demands credentials rather than shown; a generic protected endpoint answers "
                "the same"
            )
        if any(i.startswith("header:") for i in indicators):
            return 0.9, (
                "an Mcp-* response header is set, which a generic HTTP service has no reason "
                "to send; nothing was invoked, so capabilities are the server's own claim"
            )
        if "jsonrpc-response" in indicators or "sse-transport" in indicators:
            return 0.75, (
                "a JSON-RPC result or an event-stream content type matched — strong for MCP "
                "but shared with any JSON-RPC or SSE service"
            )
        if any(i.startswith("body:") for i in indicators):
            return 0.6, (
                "an MCP method string appeared in the body; a documentation page or a proxy "
                "echoing the request carries the same token"
            )
        if "mcp-keywords" in indicators:
            return 0.4, (
                "only the fallback keywords (tools/resources/prompts in a JSON body) matched, "
                "which is what a generic REST API living at /mcp looks like"
            )
        return 0.5, "matched an MCP indicator with no stronger corroboration"

    # ── The parser both halves share ─────────────────────────────────

    def _discover(
        self, exchanges: list[Exchange]
    ) -> tuple[str, str, dict, str, Exchange, Exchange | None] | None:
        """The first path that answers like an MCP server, in recorded order.

        Returns (path, url, server_info, transport, winning_exchange,
        get_exchange). The GET exchange for the winning path carries the
        content-type transport detection reads, even when a POST is what matched.
        """
        get_by_path: dict[str, Exchange] = {}
        for exchange in exchanges:
            if exchange.request_method == "GET":
                get_by_path.setdefault(urlparse(exchange.request_url or "").path, exchange)

        for exchange in exchanges:
            info = self._server_info_from(exchange)
            if info is None:
                continue
            path = urlparse(exchange.request_url or "").path
            get_ex = get_by_path.get(path)
            transport = self._detect_transport(path, get_ex)
            return path, exchange.request_url or "", info, transport, exchange, get_ex
        return None

    def _server_info_from(self, exchange: Exchange) -> dict | None:
        """Analyze one recorded exchange for MCP server indicators."""
        status = exchange.response_status
        if exchange.error or status in (404, 405, 502, 503):
            return None

        method = exchange.request_method or "GET"
        path = urlparse(exchange.request_url or "").path
        headers = exchange.response_headers or {}
        body = exchange.response_body or ""

        server_info: dict = {}
        indicators: list[str] = []

        resp_headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in self.MCP_HEADERS:
            if header in resp_headers_lower:
                indicators.append(f"header:{header}")
                server_info["mcp_header"] = {header: resp_headers_lower[header]}

        for pattern in self.MCP_BODY_PATTERNS:
            if pattern.lower() in body.lower():
                indicators.append(f"body:{pattern}")

        content_type = resp_headers_lower.get("content-type", "")
        if "text/event-stream" in content_type:
            indicators.append("sse-transport")
            server_info["transport_hint"] = "sse"

        if '"jsonrpc"' in body and '"result"' in body:
            indicators.append("jsonrpc-response")
            server_info["protocol"] = "jsonrpc"

            try:
                data = json.loads(body)
                if "result" in data:
                    result_data = data["result"]
                    if "capabilities" in result_data:
                        caps = result_data["capabilities"]
                        server_info["capabilities"] = (
                            list(caps.keys()) if isinstance(caps, dict) else caps
                        )
                    if "serverInfo" in result_data:
                        server_info["server_info"] = result_data["serverInfo"]
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

        if status == 401:
            server_info["auth_required"] = True
            indicators.append("auth-required")
        elif status == 200:
            server_info["auth_required"] = False

        if not indicators:
            if status == 200 and "application/json" in content_type:
                if any(kw in body.lower() for kw in ["tools", "resources", "prompts"]):
                    indicators.append("mcp-keywords")

        if indicators:
            server_info["indicators"] = indicators
            server_info["status_code"] = status
            server_info["path"] = path
            server_info["method"] = method
            return server_info

        return None

    def _detect_transport(self, path: str, get_exchange: Exchange | None) -> str:
        """Detect MCP transport type from path and the GET response headers."""
        path_lower = path.lower()

        if "sse" in path_lower or "/events" in path_lower:
            return "sse"

        headers = (get_exchange.response_headers if get_exchange else None) or {}
        content_type = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break
        if "text/event-stream" in content_type:
            return "sse"

        # Default to HTTP for now (WebSocket detection is backlogged)
        return "http"

    def _build_description(self, server_info: dict) -> str:
        """Build human-readable description of MCP server."""
        parts = ["MCP server endpoint discovered."]

        transport = server_info.get("transport", "unknown")
        parts.append(f"Transport: {transport}.")

        if server_info.get("capabilities"):
            caps = ", ".join(server_info["capabilities"])
            parts.append(f"Capabilities: {caps}.")

        if server_info.get("auth_required") is False:
            parts.append("No authentication required.")
        elif server_info.get("auth_required") is True:
            parts.append("Authentication required (401 response).")

        if server_info.get("server_info"):
            info = server_info["server_info"]
            name = info.get("name", "unknown")
            version = info.get("version", "")
            parts.append(f"Server: {name} {version}".strip() + ".")

        return " ".join(parts)

    def _build_evidence(self, server_info: dict) -> str:
        """Build evidence string for observation."""
        lines = []

        lines.append(f"Path: {server_info.get('path', 'unknown')}")
        lines.append(f"Method: {server_info.get('method', 'unknown')}")
        lines.append(f"Status: {server_info.get('status_code', 'unknown')}")

        if server_info.get("indicators"):
            lines.append(f"Indicators: {', '.join(server_info['indicators'])}")

        if server_info.get("mcp_header"):
            for k, v in server_info["mcp_header"].items():
                lines.append(f"Header {k}: {v}")

        return "\n".join(lines)
