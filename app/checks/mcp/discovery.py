"""
app/checks/mcp/discovery.py - MCP Server Discovery

Discovers Model Context Protocol (MCP) server endpoints on target services.
Probes well-known paths, checks for MCP-specific headers, and identifies
transport types and capabilities.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/transports/
"""

from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


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

    conditions = [CheckCondition("services", "truthy")]
    produces = ["mcp_servers"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

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
        'tools/list',
        'resources/list',
        'prompts/list',
        'initialize',
        'notifications/initialized',
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.MCP_PATHS:
                    url = service.with_path(path)
                    
                    # Try GET first (SSE endpoints, well-known)
                    get_resp = await client.get(url)
                    
                    server_info = self._analyze_response(get_resp, path, "GET")
                    
                    if not server_info:
                        # Try POST with JSON-RPC initialize
                        post_resp = await client.post(
                            url,
                            json={
                                "jsonrpc": "2.0",
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "chainsmith-recon", "version": "1.0"}
                                },
                                "id": 1
                            },
                            headers={"Content-Type": "application/json"},
                        )
                        server_info = self._analyze_response(post_resp, path, "POST")
                    
                    if server_info:
                        # Determine transport type
                        transport = self._detect_transport(path, get_resp)
                        server_info["transport"] = transport
                        server_info["service"] = service.to_dict()
                        
                        # Build finding
                        severity = "medium" if server_info.get("capabilities") else "info"
                        
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"MCP server discovered: {path}",
                            description=self._build_description(server_info),
                            severity=severity,
                            evidence=self._build_evidence(server_info),
                            host=service.host,
                            discriminator=f"mcp-{path.strip('/').replace('/', '-')}",
                            target=service,
                            target_url=url,
                            raw_data=server_info,
                        ))
                        
                        mcp_servers.append({
                            "url": url,
                            "path": path,
                            "transport": transport,
                            "capabilities": server_info.get("capabilities", []),
                            "auth_required": server_info.get("auth_required", None),
                            "server_info": server_info.get("server_info", {}),
                            "service": service.to_dict(),
                        })
                        
                        # Found MCP on this service, don't probe remaining paths
                        break

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if mcp_servers:
            result.outputs["mcp_servers"] = mcp_servers

        return result

    def _analyze_response(self, resp, path: str, method: str) -> dict | None:
        """Analyze HTTP response for MCP server indicators."""
        if resp.error or resp.status_code in (404, 405, 502, 503):
            return None
        
        server_info = {}
        indicators = []
        
        # Check for MCP headers
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header in self.MCP_HEADERS:
            if header in resp_headers_lower:
                indicators.append(f"header:{header}")
                server_info["mcp_header"] = {header: resp_headers_lower[header]}
        
        # Check response body for MCP patterns
        body = resp.body or ""
        for pattern in self.MCP_BODY_PATTERNS:
            if pattern.lower() in body.lower():
                indicators.append(f"body:{pattern}")
        
        # Check for SSE content type (common for MCP streaming)
        content_type = resp_headers_lower.get("content-type", "")
        if "text/event-stream" in content_type:
            indicators.append("sse-transport")
            server_info["transport_hint"] = "sse"
        
        # Check for JSON-RPC response structure
        if '"jsonrpc"' in body and '"result"' in body:
            indicators.append("jsonrpc-response")
            server_info["protocol"] = "jsonrpc"
            
            # Try to extract capabilities from initialize response
            try:
                import json
                data = json.loads(body)
                if "result" in data:
                    result_data = data["result"]
                    if "capabilities" in result_data:
                        caps = result_data["capabilities"]
                        server_info["capabilities"] = list(caps.keys()) if isinstance(caps, dict) else caps
                    if "serverInfo" in result_data:
                        server_info["server_info"] = result_data["serverInfo"]
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
        
        # Check for auth requirement
        if resp.status_code == 401:
            server_info["auth_required"] = True
            indicators.append("auth-required")
        elif resp.status_code == 200:
            server_info["auth_required"] = False
        
        # Need at least one strong indicator
        if not indicators:
            # Check for generic API response that might be MCP
            if resp.status_code == 200 and "application/json" in content_type:
                if any(kw in body.lower() for kw in ["tools", "resources", "prompts"]):
                    indicators.append("mcp-keywords")
        
        if indicators:
            server_info["indicators"] = indicators
            server_info["status_code"] = resp.status_code
            server_info["path"] = path
            server_info["method"] = method
            return server_info
        
        return None

    def _detect_transport(self, path: str, resp) -> str:
        """Detect MCP transport type from path and response."""
        path_lower = path.lower()
        
        if "sse" in path_lower or "/events" in path_lower:
            return "sse"
        
        content_type = resp.headers.get("content-type", "").lower() if resp.headers else ""
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
        """Build evidence string for finding."""
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
