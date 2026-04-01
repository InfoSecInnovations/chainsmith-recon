"""
app/checks/mcp/shadow_tool_detection.py - Shadow Tool Detection

Tests whether MCP tool names can be overwritten or collided with,
enabling attackers to shadow legitimate tools with malicious replacements.

Detection tests (safe, non-destructive):
1. Tool namespace analysis (flat vs prefixed names)
2. Common name collision risk
3. tools/list_changed notification acceptance
4. Re-registration via duplicate initialize

Operates primarily on already-enumerated data, with light protocol probing.

References:
  https://modelcontextprotocol.io/specification
  MITRE ATLAS - AML.T0051 LLM Plugin Compromise
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckResult, CheckCondition
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Common MCP tool names prone to collision in multi-server setups
COMMON_TOOL_NAMES = {
    "read_file", "write_file", "search", "fetch", "browse", "execute",
    "get_weather", "send_email", "query", "list_files", "create_file",
    "delete_file", "http_request", "run_command", "get_url",
    "read", "write", "get", "set", "list", "create", "delete",
    "update", "find", "open", "close", "send", "receive",
}


class ShadowToolDetectionCheck(BaseCheck):
    """
    Detect shadow tool attack susceptibility in MCP servers.

    Checks whether tool names use namespacing, whether common names
    create collision risk, and whether the server accepts unsolicited
    tool re-registration attempts.
    """

    name = "mcp_shadow_tool_detection"
    description = "Detect MCP shadow tool attack susceptibility"

    conditions = [CheckCondition("mcp_tools", "truthy")]
    produces = ["mcp_shadow_tool_risk"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 45.0

    reason = "In multi-server MCP setups, tool name collisions allow attackers to shadow legitimate tools with malicious replacements"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = ["namespace analysis", "protocol probing", "collision detection"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])

        if not mcp_tools:
            return result

        shadow_risk = {
            "namespace_analysis": {},
            "collision_candidates": [],
            "notification_tests": {},
        }

        host = mcp_tools[0].get("service_host", "unknown") if mcp_tools else "unknown"

        # Test 1: Namespace analysis
        self._analyze_namespacing(mcp_tools, host, result, shadow_risk)

        # Test 2: Common name collision detection
        self._detect_name_collisions(mcp_tools, host, result, shadow_risk)

        # Test 3: Protocol-level tests (if servers available)
        if mcp_servers:
            await self._test_protocol_attacks(mcp_servers, mcp_tools, host, result, shadow_risk)

        result.outputs["mcp_shadow_tool_risk"] = shadow_risk
        return result

    def _analyze_namespacing(
        self, tools: list[dict], host: str, result: CheckResult, shadow_risk: dict
    ) -> None:
        """Check if tool names use namespace prefixes."""
        tool_names = [t.get("name", "") for t in tools]

        namespaced = []
        flat = []

        for name in tool_names:
            # Namespaced: contains / or :: or server_name. prefix
            if "/" in name or "::" in name or (name.count(".") >= 2):
                namespaced.append(name)
            else:
                flat.append(name)

        shadow_risk["namespace_analysis"] = {
            "total_tools": len(tool_names),
            "namespaced": len(namespaced),
            "flat": len(flat),
            "namespaced_names": namespaced[:10],
            "flat_names": flat[:10],
        }

        if namespaced and not flat:
            result.findings.append(build_finding(
                check_name=self.name,
                title="Tools are namespaced (shadow tool resistant)",
                description=(
                    f"All {len(tool_names)} tools use namespaced naming "
                    f"(e.g., '{namespaced[0]}'). This makes shadow tool attacks "
                    "significantly harder in multi-server configurations."
                ),
                severity="info",
                evidence=f"Namespaced tools: {', '.join(namespaced[:5])}",
                host=host,
                discriminator="namespace-safe",
            ))
        elif flat:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"MCP tools use flat naming (no namespace prefix) — vulnerable to shadow tool attacks",
                description=(
                    f"{len(flat)} of {len(tool_names)} tools use flat (unprefixed) names. "
                    "In multi-server MCP configurations, an attacker-controlled server "
                    "could register tools with the same names, causing the client to "
                    "invoke the attacker's version instead."
                ),
                severity="medium",
                evidence=f"Flat tool names: {', '.join(flat[:10])}",
                host=host,
                discriminator="namespace-flat",
                raw_data={"flat_names": flat, "namespaced_names": namespaced},
            ))

    def _detect_name_collisions(
        self, tools: list[dict], host: str, result: CheckResult, shadow_risk: dict
    ) -> None:
        """Check tool names against common MCP tool names for collision risk."""
        tool_names = {t.get("name", "").lower() for t in tools}
        collisions = tool_names & COMMON_TOOL_NAMES

        shadow_risk["collision_candidates"] = sorted(collisions)

        if collisions:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Collision-risk tool names detected: {len(collisions)} match common MCP names",
                description=(
                    f"The following tool names match commonly-used MCP tool names: "
                    f"{', '.join(sorted(collisions))}. "
                    "In multi-server configurations, another server registering "
                    "the same names would create a shadow tool collision."
                ),
                severity="low",
                evidence=f"Collision candidates: {', '.join(sorted(collisions))}",
                host=host,
                discriminator="name-collision",
                raw_data={"collisions": sorted(collisions)},
            ))

    async def _test_protocol_attacks(
        self, mcp_servers: list[dict], tools: list[dict],
        host: str, result: CheckResult, shadow_risk: dict
    ) -> None:
        """Test protocol-level shadow tool vectors."""
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            base_path = server.get("path", "")

            if not server_url:
                continue

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Test: Send tools/list_changed notification
                    await self._test_list_changed_notification(
                        client, server_url, base_path, host, result, shadow_risk
                    )

                    # Test: Re-registration via second initialize
                    await self._test_reinitialize(
                        client, server_url, base_path, host, result, shadow_risk
                    )

            except Exception as e:
                result.errors.append(f"Shadow tool protocol test: {e}")

    async def _test_list_changed_notification(
        self, client, server_url: str, base_path: str,
        host: str, result: CheckResult, shadow_risk: dict
    ) -> None:
        """Test if server accepts tools/list_changed notification from client."""
        url = server_url  # Send to MCP endpoint directly

        # Send notification (no id = notification per JSON-RPC)
        resp = await client.post(
            url,
            json={
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
            },
            headers={"Content-Type": "application/json"},
        )

        accepted = not resp.error and resp.status_code in (200, 202, 204)
        shadow_risk["notification_tests"]["list_changed"] = {
            "accepted": accepted,
            "status": resp.status_code if not resp.error else None,
        }

        if accepted:
            result.findings.append(build_finding(
                check_name=self.name,
                title="Server accepts client notifications/tools/list_changed",
                description=(
                    "The MCP server accepted a tools/list_changed notification "
                    "from the client. This may allow a client to influence the "
                    "server's tool registration state."
                ),
                severity="high",
                evidence=f"URL: {url}\nMethod: notifications/tools/list_changed\nStatus: {resp.status_code}",
                host=host,
                discriminator="list-changed-accepted",
                raw_data={"status": resp.status_code},
            ))

    async def _test_reinitialize(
        self, client, server_url: str, base_path: str,
        host: str, result: CheckResult, shadow_risk: dict
    ) -> None:
        """Test if sending a second initialize changes behavior."""
        url = server_url

        # First initialize
        resp1 = await client.post(
            url,
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "clientInfo": {"name": "chainsmith-shadow-a", "version": "1.0"},
                },
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        if resp1.error or resp1.status_code not in (200, 201):
            return

        # Second initialize with different client info + tool capabilities
        resp2 = await client.post(
            url,
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "clientInfo": {"name": "chainsmith-shadow-b", "version": "2.0"},
                },
                "id": 2,
            },
            headers={"Content-Type": "application/json"},
        )

        if not resp2.error and resp2.status_code in (200, 201):
            shadow_risk["notification_tests"]["reinitialize"] = {
                "accepted": True,
                "status": resp2.status_code,
            }
            result.findings.append(build_finding(
                check_name=self.name,
                title="MCP server accepts tool re-registration: duplicate initialize accepted",
                description=(
                    "The MCP server accepted a second initialize request with different "
                    "clientInfo. This indicates the server may not enforce single-session "
                    "semantics, potentially allowing tool replacement."
                ),
                severity="low",
                evidence=f"First init: status {resp1.status_code}\nSecond init: status {resp2.status_code}",
                host=host,
                discriminator="reinitialize-accepted",
                raw_data={
                    "first_status": resp1.status_code,
                    "second_status": resp2.status_code,
                },
            ))
