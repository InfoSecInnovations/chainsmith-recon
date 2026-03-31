"""
app/checks/mcp - MCP Suite

Model Context Protocol (MCP) reconnaissance checks.
Discovers and audits AI systems exposing tool-calling over MCP.

Implemented checks:
  mcp_discovery         - Discover MCP server endpoints
  mcp_tool_enumeration  - Enumerate available tools and assess risk levels

Backlog (not yet implemented):
  mcp_tool_invoke       - Probe tool behavior with crafted inputs
  mcp_injection         - Test for prompt injection via tool results
  mcp_server_auth       - Check for missing/weak authentication
  mcp_transport_security - Verify TLS and transport security
  mcp_resource_access   - Probe resource URIs for path traversal
  mcp_sampling_abuse    - Test sampling endpoint for jailbreaks
  mcp_schema_leak       - Check tool schemas for sensitive field exposure
  mcp_chained_tools     - Multi-tool chain abuse scenarios
  mcp_websocket_transport - WebSocket transport detection and probing

Chain patterns:
  mcp_tool_injection       - Tool result -> prompt injection -> LLM action
  mcp_auth_bypass_to_tool  - Auth bypass -> privileged tool invocation
  mcp_resource_traversal   - Resource URI path traversal -> data exposure
  mcp_sampling_jailbreak   - Sampling endpoint jailbreak via tool call
  mcp_schema_recon         - Tool schema enumeration -> targeted injection
  mcp_cross_tool_pivot     - Pivot across tools to escalate access

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/server/tools/
  https://attack.mitre.org/techniques/T1059/  (Command execution via tools)
"""

from app.checks.base import BaseCheck
from app.checks.mcp.discovery import MCPDiscoveryCheck
from app.checks.mcp.tool_enumeration import MCPToolEnumerationCheck

__all__ = [
    "MCPDiscoveryCheck",
    "MCPToolEnumerationCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented MCP checks."""
    return [
        MCPDiscoveryCheck,
        MCPToolEnumerationCheck,
    ]
