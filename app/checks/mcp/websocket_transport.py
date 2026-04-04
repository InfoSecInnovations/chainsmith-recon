"""
app/checks/mcp/websocket_transport.py - WebSocket Transport Discovery

Discovers MCP servers accessible via WebSocket transport.
The existing MCPDiscoveryCheck only detects SSE and HTTP transports.
This check probes for WebSocket upgrade on common MCP paths.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/transports/
"""

import base64
import os
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding
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

    timeout_seconds = 60.0

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

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        ws_servers = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            base_url = service_data.get("url", "")
            base_path = server.get("path", "")
            server_auth = server.get("auth_required")

            if not base_url:
                continue

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Build paths to test: standard WS paths + discovered MCP path
                    paths = list(self.WS_PATHS)
                    if base_path and base_path not in paths:
                        paths.append(base_path)

                    for path in paths:
                        url = f"{base_url.rstrip('/')}{path}"
                        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")

                        # Attempt WebSocket upgrade
                        resp = await client.get(
                            url,
                            headers={
                                "Upgrade": "websocket",
                                "Connection": "Upgrade",
                                "Sec-WebSocket-Version": "13",
                                "Sec-WebSocket-Key": ws_key,
                            },
                        )

                        if resp.error:
                            continue

                        # Check for 101 Switching Protocols
                        if resp.status_code == 101:
                            ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
                            ws_info = {
                                "url": ws_url,
                                "http_url": url,
                                "path": path,
                                "host": host,
                                "service": service_data,
                            }
                            ws_servers.append(ws_info)

                            # Check if WS has different auth than HTTP
                            severity = "medium"
                            title = f"MCP WebSocket transport discovered: {ws_url}"
                            desc = (
                                f"MCP server accepts WebSocket connections at {path}. "
                                "WebSocket transport may have different security properties "
                                "than HTTP/SSE endpoints."
                            )

                            if server_auth is True:
                                # HTTP requires auth — does WS?
                                severity = "high"
                                title = "WebSocket MCP endpoint requires no authentication (HTTP endpoint requires auth)"
                                desc = (
                                    f"The HTTP MCP endpoint requires authentication, but the "
                                    f"WebSocket endpoint at {path} accepted the upgrade without "
                                    "credentials. This allows bypassing HTTP auth via WebSocket."
                                )

                            result.findings.append(
                                build_finding(
                                    check_name=self.name,
                                    title=title,
                                    description=desc,
                                    severity=severity,
                                    evidence=f"URL: {url}\nStatus: 101 Switching Protocols\nPath: {path}",
                                    host=host,
                                    discriminator=f"ws-{path.strip('/').replace('/', '-') or 'root'}",
                                    raw_data=ws_info,
                                )
                            )
                            break  # Found WS on this server

                        # Check for upgrade-related headers even on non-101
                        upgrade_header = ""
                        for k, v in resp.headers.items():
                            if k.lower() == "upgrade":
                                upgrade_header = v
                                break

                        if upgrade_header.lower() == "websocket" and resp.status_code != 101:
                            result.findings.append(
                                build_finding(
                                    check_name=self.name,
                                    title=f"WebSocket upgrade indicated but not completed at {path}",
                                    description=(
                                        f"Server returned Upgrade: websocket header at {path} "
                                        f"but status was {resp.status_code} instead of 101. "
                                        "WebSocket may require additional parameters."
                                    ),
                                    severity="info",
                                    evidence=f"URL: {url}\nStatus: {resp.status_code}\nUpgrade: {upgrade_header}",
                                    host=host,
                                    discriminator=f"ws-partial-{path.strip('/').replace('/', '-') or 'root'}",
                                    raw_data={"url": url, "status": resp.status_code},
                                )
                            )

            except Exception as e:
                result.errors.append(f"{base_url}: {e}")

        if not ws_servers:
            # Add info finding that WS was not found
            if mcp_servers:
                host = mcp_servers[0].get("service", {}).get("host", "unknown")
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="WebSocket upgrade rejected on all tested paths",
                        description="No MCP WebSocket transport endpoints were discovered.",
                        severity="info",
                        evidence=f"Paths tested: {', '.join(self.WS_PATHS)}",
                        host=host,
                        discriminator="ws-not-found",
                    )
                )

        if ws_servers:
            result.outputs["mcp_websocket_servers"] = ws_servers

        return result
