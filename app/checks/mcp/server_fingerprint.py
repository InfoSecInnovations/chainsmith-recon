"""
app/checks/mcp/server_fingerprint.py - MCP Server Fingerprinting

Identifies MCP server implementation from response patterns,
error messages, capability sets, and protocol behavior.

Operates on data already collected by MCPDiscoveryCheck.

References:
  https://modelcontextprotocol.io/specification
"""

import json
import re
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Server fingerprint signatures
SERVER_SIGNATURES = [
    {
        "name": "Official TypeScript SDK",
        "patterns": {
            "server_name": [r"@modelcontextprotocol/sdk", r"mcp-typescript"],
            "error_format": [r"MCP error", r"JsonRpcError"],
            "capabilities": ["tools", "resources", "prompts"],
        },
        "version_field": "version",
    },
    {
        "name": "Official Python SDK (mcp)",
        "patterns": {
            "server_name": [r"mcp", r"python-mcp"],
            "error_format": [r"McpError", r"Traceback", r"asyncio"],
            "capabilities": ["tools", "resources", "prompts"],
        },
        "version_field": "version",
    },
    {
        "name": "FastMCP",
        "patterns": {
            "server_name": [r"fastmcp", r"FastMCP"],
            "error_format": [r"FastMCP", r"fastmcp\."],
            "capabilities": ["tools"],
        },
        "version_field": "version",
    },
    {
        "name": "LangChain MCP Adapter",
        "patterns": {
            "server_name": [r"langchain", r"langchain-mcp"],
            "error_format": [r"langchain"],
        },
    },
    {
        "name": "Claude Desktop MCP",
        "patterns": {
            "server_name": [r"claude", r"anthropic"],
        },
    },
    {
        "name": "Cursor MCP",
        "patterns": {
            "server_name": [r"cursor"],
        },
    },
    {
        "name": "Ollama MCP Bridge",
        "patterns": {
            "server_name": [r"ollama"],
            "error_format": [r"ollama"],
        },
    },
]


class MCPServerFingerprintCheck(BaseCheck):
    """
    Fingerprint MCP server implementations.

    Identifies the MCP server framework/SDK from server info,
    error message patterns, and capability signatures.
    """

    name = "mcp_server_fingerprint"
    description = "Identify MCP server implementation and version"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_server_implementations"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 45.0

    reason = "Identifying the MCP server implementation enables targeted vulnerability research"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "CWE-200 Exposure of Sensitive Information",
    ]
    techniques = ["fingerprinting", "version detection", "error analysis"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        implementations = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            server_info = server.get("server_info", {})
            capabilities = server.get("capabilities", [])

            impl = {
                "url": server_url,
                "host": host,
                "identified": False,
                "implementation": None,
                "version": None,
                "confidence": "low",
            }

            # Step 1: Check serverInfo from initialize response
            if server_info:
                match = self._match_server_info(server_info)
                if match:
                    impl.update(match)

            # Step 2: Probe for error fingerprints
            if not impl["identified"]:
                try:
                    async with AsyncHttpClient(cfg) as client:
                        error_match = await self._probe_error_fingerprint(client, server_url, host)
                        if error_match:
                            impl.update(error_match)
                except Exception as e:
                    result.errors.append(f"Fingerprint probe: {e}")

            # Step 3: Capability-based heuristic
            if not impl["identified"] and capabilities:
                cap_match = self._match_capabilities(capabilities)
                if cap_match:
                    impl.update(cap_match)

            # Step 4: Check for custom/non-standard implementation
            if not impl["identified"]:
                impl["implementation"] = "Unknown/Custom"
                impl["confidence"] = "low"

            implementations.append(impl)

            # Generate observations
            if impl["identified"]:
                version_str = f" v{impl['version']}" if impl.get("version") else ""
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"MCP server identified: {impl['implementation']}{version_str}",
                        description=(
                            f"The MCP server at {server_url} is running "
                            f"{impl['implementation']}{version_str} "
                            f"(confidence: {impl['confidence']})."
                        ),
                        severity="info",
                        evidence=self._build_evidence(impl, server_info),
                        host=host,
                        discriminator=f"impl-{impl['implementation'].lower().replace(' ', '-')}",
                        raw_data=impl,
                    )
                )
            else:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="MCP server is custom implementation (non-standard)",
                        description=(
                            "The MCP server could not be matched to a known implementation. "
                            "Custom implementations may have unique vulnerabilities."
                        ),
                        severity="low",
                        evidence=f"URL: {server_url}\nServer info: {json.dumps(server_info)[:200]}",
                        host=host,
                        discriminator="impl-custom",
                        raw_data=impl,
                    )
                )

        if implementations:
            result.outputs["mcp_server_implementations"] = implementations

        return result

    def _match_server_info(self, server_info: dict) -> dict | None:
        """Match serverInfo fields against known signatures."""
        name = server_info.get("name", "").lower()
        version = server_info.get("version", "")

        for sig in SERVER_SIGNATURES:
            for pattern in sig["patterns"].get("server_name", []):
                if re.search(pattern, name, re.IGNORECASE):
                    return {
                        "identified": True,
                        "implementation": sig["name"],
                        "version": version or None,
                        "confidence": "high",
                        "match_method": "server_name",
                    }

        # If we have a name but no match, it's still useful info
        if name:
            return {
                "identified": True,
                "implementation": server_info.get("name", name),
                "version": version or None,
                "confidence": "medium",
                "match_method": "server_name_raw",
            }

        return None

    async def _probe_error_fingerprint(self, client, server_url: str, host: str) -> dict | None:
        """Send invalid requests and fingerprint from error responses."""
        # Send malformed JSON-RPC to trigger an error
        resp = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "method": "nonexistent/method_that_does_not_exist",
                "id": 999,
            },
            headers={"Content-Type": "application/json"},
        )

        if resp.error or not resp.body:
            return None

        body = resp.body.lower()

        for sig in SERVER_SIGNATURES:
            for pattern in sig["patterns"].get("error_format", []):
                if re.search(pattern, body, re.IGNORECASE):
                    return {
                        "identified": True,
                        "implementation": sig["name"],
                        "version": None,
                        "confidence": "medium",
                        "match_method": "error_format",
                    }

        # Check for Python-style tracebacks
        if "traceback" in body or 'file "' in body:
            return {
                "identified": True,
                "implementation": "Python-based (unknown SDK)",
                "version": None,
                "confidence": "low",
                "match_method": "error_format",
            }

        # Check for Node.js-style errors
        if "at object." in body or "at module." in body or "node_modules" in body:
            return {
                "identified": True,
                "implementation": "Node.js-based (unknown SDK)",
                "version": None,
                "confidence": "low",
                "match_method": "error_format",
            }

        return None

    def _match_capabilities(self, capabilities: list) -> dict | None:
        """Heuristic matching based on capability set."""
        cap_set = {c.lower() if isinstance(c, str) else "" for c in capabilities}

        # Most complete capability set suggests official SDK
        if {"tools", "resources", "prompts"}.issubset(cap_set):
            return {
                "identified": False,  # Low confidence, just a hint
                "implementation": "Full MCP SDK (tools+resources+prompts)",
                "confidence": "low",
                "match_method": "capabilities",
            }

        return None

    def _build_evidence(self, impl: dict, server_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Implementation: {impl.get('implementation', 'unknown')}",
            f"Version: {impl.get('version', 'unknown')}",
            f"Confidence: {impl.get('confidence', 'unknown')}",
            f"Match method: {impl.get('match_method', 'unknown')}",
        ]

        if server_info:
            lines.append(f"Server info: {json.dumps(server_info)[:200]}")

        return "\n".join(lines)
