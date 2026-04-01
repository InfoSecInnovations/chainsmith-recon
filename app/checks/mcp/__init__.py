"""
app/checks/mcp - MCP Suite

Model Context Protocol (MCP) reconnaissance checks.
Discovers and audits AI systems exposing tool-calling over MCP.

Implemented checks (18 total):
  Phase 0 (existing):
    mcp_discovery              - Discover MCP server endpoints
    mcp_tool_enumeration       - Enumerate available tools and assess risk levels

  Phase 9 Wave 1 (passive, high value):
    mcp_auth_check             - Test authentication enforcement at all levels
    mcp_websocket_transport    - Discover WebSocket MCP transport endpoints
    mcp_tool_chain_analysis    - Analyze tools for dangerous capability combinations
    mcp_shadow_tool_detection  - Detect shadow tool attack susceptibility

  Phase 9 Wave 2 (passive analysis):
    mcp_schema_leakage         - Analyze tool schemas for info leakage
    mcp_server_fingerprint     - Identify MCP server implementation/version
    mcp_transport_security     - Analyze transport layer security (TLS, CORS, SSE)
    mcp_notification_injection - Test for unsolicited notification acceptance

  Phase 9 Wave 3 (active probing):
    mcp_tool_invocation        - Probe tools with safe test payloads
    mcp_resource_traversal     - Test resource URIs for path traversal / SSRF
    mcp_template_injection     - Test resource template params for injection

  Phase 9 Wave 4 (cross-suite):
    mcp_prompt_injection       - Test prompt injection via tool results

  Phase 9 Wave 5 (lower priority):
    mcp_sampling_abuse         - Test sampling endpoint for LLM proxy abuse
    mcp_protocol_version       - Test protocol version downgrade
    mcp_tool_rate_limit        - Test tool invocation rate limiting
    mcp_undeclared_capabilities - Probe for undeclared capabilities

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

# Phase 9 Wave 1
from app.checks.mcp.auth_check import MCPAuthCheck
from app.checks.mcp.websocket_transport import WebSocketTransportCheck
from app.checks.mcp.tool_chain_analysis import ToolChainAnalysisCheck
from app.checks.mcp.shadow_tool_detection import ShadowToolDetectionCheck

# Phase 9 Wave 2
from app.checks.mcp.schema_leakage import ToolSchemaLeakageCheck
from app.checks.mcp.server_fingerprint import MCPServerFingerprintCheck
from app.checks.mcp.transport_security import TransportSecurityCheck
from app.checks.mcp.notification_injection import MCPNotificationInjectionCheck

# Phase 9 Wave 3
from app.checks.mcp.tool_invocation import MCPToolInvocationCheck
from app.checks.mcp.resource_traversal import MCPResourceTraversalCheck
from app.checks.mcp.template_injection import ResourceTemplateInjectionCheck

# Phase 9 Wave 4
from app.checks.mcp.prompt_injection import MCPPromptInjectionCheck

# Phase 9 Wave 5
from app.checks.mcp.sampling_abuse import MCPSamplingAbuseCheck
from app.checks.mcp.protocol_version import MCPProtocolVersionCheck
from app.checks.mcp.rate_limit import ToolRateLimitCheck
from app.checks.mcp.undeclared_capabilities import UndeclaredCapabilityCheck

__all__ = [
    "MCPDiscoveryCheck",
    "MCPToolEnumerationCheck",
    "MCPAuthCheck",
    "WebSocketTransportCheck",
    "ToolChainAnalysisCheck",
    "ShadowToolDetectionCheck",
    "ToolSchemaLeakageCheck",
    "MCPServerFingerprintCheck",
    "TransportSecurityCheck",
    "MCPNotificationInjectionCheck",
    "MCPToolInvocationCheck",
    "MCPResourceTraversalCheck",
    "ResourceTemplateInjectionCheck",
    "MCPPromptInjectionCheck",
    "MCPSamplingAbuseCheck",
    "MCPProtocolVersionCheck",
    "ToolRateLimitCheck",
    "UndeclaredCapabilityCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented MCP checks."""
    return [
        MCPDiscoveryCheck,
        MCPToolEnumerationCheck,
        MCPAuthCheck,
        WebSocketTransportCheck,
        ToolChainAnalysisCheck,
        ShadowToolDetectionCheck,
        ToolSchemaLeakageCheck,
        MCPServerFingerprintCheck,
        TransportSecurityCheck,
        MCPNotificationInjectionCheck,
        MCPToolInvocationCheck,
        MCPResourceTraversalCheck,
        ResourceTemplateInjectionCheck,
        MCPPromptInjectionCheck,
        MCPSamplingAbuseCheck,
        MCPProtocolVersionCheck,
        ToolRateLimitCheck,
        UndeclaredCapabilityCheck,
    ]
