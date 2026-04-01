"""
app/checks/mcp/undeclared_capabilities.py - Undeclared Capability Probing

Probes MCP servers for capabilities not declared in the initialize response.
Tests tools/list, resources/list, prompts/list, sampling, and non-standard
methods even when not declared.

References:
  https://modelcontextprotocol.io/specification
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckResult, CheckCondition
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Standard MCP capabilities and their probe methods
STANDARD_CAPABILITIES = [
    ("tools", "tools/list", "Tool enumeration"),
    ("resources", "resources/list", "Resource enumeration"),
    ("prompts", "prompts/list", "Prompt template listing"),
    ("sampling", "sampling/createMessage", "LLM sampling/proxy"),
]

# Non-standard methods that may reveal admin/debug interfaces
NON_STANDARD_METHODS = [
    ("admin/status", "Admin status endpoint"),
    ("debug/info", "Debug info endpoint"),
    ("internal/config", "Internal configuration"),
    ("server/info", "Server information"),
    ("server/status", "Server status"),
    ("health", "Health check"),
    ("metrics", "Metrics endpoint"),
    ("logging/setLevel", "Log level control"),
]


class UndeclaredCapabilityCheck(BaseCheck):
    """
    Probe for MCP capabilities not declared in initialize response.

    Some servers implement capabilities but forget to declare them,
    or expose admin/debug methods not part of the MCP spec.
    """

    name = "mcp_undeclared_capabilities"
    description = "Probe for MCP capabilities not declared in initialize response"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_undeclared_capabilities"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 60.0

    reason = "Servers may implement undeclared capabilities, exposing hidden attack surface"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
    ]
    techniques = ["capability probing", "hidden endpoint discovery"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        undeclared = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            declared_caps = set(
                str(c).lower() for c in server.get("capabilities", [])
            )

            if not server_url:
                continue

            server_undeclared = {
                "url": server_url,
                "host": host,
                "declared": list(declared_caps),
                "undeclared_accessible": [],
                "non_standard_accessible": [],
            }

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Test standard capabilities not in declared set
                    for cap_name, method, desc in STANDARD_CAPABILITIES:
                        if cap_name.lower() in declared_caps:
                            continue

                        accessible = await self._probe_method(client, server_url, method)

                        if accessible:
                            server_undeclared["undeclared_accessible"].append({
                                "capability": cap_name,
                                "method": method,
                            })
                            result.findings.append(build_finding(
                                check_name=self.name,
                                title=f"Undeclared capability accessible: {method} returns data but {cap_name} not declared",
                                description=(
                                    f"The server responds to {method} even though '{cap_name}' "
                                    f"was not declared in capabilities. {desc} is accessible "
                                    "despite not being advertised."
                                ),
                                severity="high",
                                evidence=f"URL: {server_url}\nMethod: {method}\nDeclared caps: {', '.join(declared_caps) or 'none'}",
                                host=host,
                                discriminator=f"undeclared-{cap_name}",
                                raw_data={"capability": cap_name, "method": method},
                            ))

                    # Test non-standard methods
                    for method, desc in NON_STANDARD_METHODS:
                        accessible = await self._probe_method(client, server_url, method)

                        if accessible:
                            server_undeclared["non_standard_accessible"].append({
                                "method": method,
                                "description": desc,
                            })
                            result.findings.append(build_finding(
                                check_name=self.name,
                                title=f"Non-standard method accepted: {method} returns data",
                                description=(
                                    f"The MCP server responds to non-standard method '{method}' "
                                    f"({desc}). This may expose administrative or debug functionality."
                                ),
                                severity="medium",
                                evidence=f"URL: {server_url}\nMethod: {method}",
                                host=host,
                                discriminator=f"nonstandard-{method.replace('/', '-')}",
                                raw_data={"method": method},
                            ))

                    if not server_undeclared["undeclared_accessible"] and not server_undeclared["non_standard_accessible"]:
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title="Server correctly rejects requests for undeclared capabilities",
                            description="All probed undeclared capabilities and non-standard methods were rejected.",
                            severity="info",
                            evidence=f"URL: {server_url}\nMethods tested: {len(STANDARD_CAPABILITIES) + len(NON_STANDARD_METHODS)}",
                            host=host,
                            discriminator="caps-clean",
                        ))

            except Exception as e:
                result.errors.append(f"Capability probe on {server_url}: {e}")

            undeclared.append(server_undeclared)

        if undeclared:
            result.outputs["mcp_undeclared_capabilities"] = undeclared

        return result

    async def _probe_method(self, client, server_url: str, method: str) -> bool:
        """Probe a JSON-RPC method and check if it returns data."""
        resp = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "method": method,
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        if resp.error or resp.status_code not in (200, 201):
            return False

        if not resp.body:
            return False

        try:
            data = json.loads(resp.body)
            if isinstance(data, dict):
                # JSON-RPC error means the server understood the protocol
                # but rejected the method — that's not "accessible"
                if "error" in data:
                    error = data["error"]
                    # Method not found = properly rejected
                    if isinstance(error, dict) and error.get("code") == -32601:
                        return False
                    # Other errors might still indicate the method exists
                    return False

                # Got a result
                if "result" in data:
                    rpc_result = data["result"]
                    # Empty result might just be an echo
                    if rpc_result in (None, {}, [], ""):
                        return False
                    return True
        except (json.JSONDecodeError, TypeError):
            pass

        return False
