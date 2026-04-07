"""
app/checks/mcp/protocol_version.py - MCP Protocol Version Probing

Tests older MCP protocol versions for downgrade vulnerabilities.
Checks if the server accepts older protocol versions with potentially
weaker security.

References:
  https://modelcontextprotocol.io/specification
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Known MCP protocol versions (oldest to newest)
PROTOCOL_VERSIONS = [
    ("2024-01-01", "Early draft"),
    ("2024-06-01", "Pre-release"),
    ("2024-10-07", "Release candidate"),
    ("2024-11-05", "Current stable"),
    ("2025-03-26", "Latest"),
]


class MCPProtocolVersionCheck(BaseCheck):
    """
    Test MCP server protocol version handling.

    Probes with older protocol versions to check for downgrade
    acceptance and capability differences.
    """

    name = "mcp_protocol_version"
    description = "Test MCP server for protocol version downgrade vulnerabilities"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_protocol_versions"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 45.0

    reason = "Older MCP protocol versions may have weaker security or missing capabilities"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
    ]
    techniques = ["protocol downgrade", "version probing"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        version_results = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")

            if not server_url:
                continue

            accepted_versions = []
            rejected_versions = []

            try:
                async with AsyncHttpClient(cfg) as client:
                    for version, desc in PROTOCOL_VERSIONS:
                        resp = await client.post(
                            server_url,
                            json={
                                "jsonrpc": "2.0",
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": version,
                                    "capabilities": {},
                                    "clientInfo": {
                                        "name": "chainsmith-version-probe",
                                        "version": "1.0",
                                    },
                                },
                                "id": 1,
                            },
                            headers={"Content-Type": "application/json"},
                        )

                        if resp.error or resp.status_code not in (200, 201):
                            rejected_versions.append(version)
                            continue

                        # Check if server accepted this version
                        try:
                            data = json.loads(resp.body or "{}")
                            if isinstance(data, dict) and "error" not in data:
                                rpc_result = data.get("result", {})
                                server_version = rpc_result.get("protocolVersion", "")
                                caps = rpc_result.get("capabilities", {})
                                accepted_versions.append(
                                    {
                                        "requested": version,
                                        "server_responded": server_version,
                                        "capabilities": list(caps.keys())
                                        if isinstance(caps, dict)
                                        else [],
                                        "description": desc,
                                    }
                                )
                            else:
                                rejected_versions.append(version)
                        except (json.JSONDecodeError, TypeError):
                            rejected_versions.append(version)

                    # Analyze results
                    version_info = {
                        "url": server_url,
                        "host": host,
                        "accepted": accepted_versions,
                        "rejected": rejected_versions,
                    }
                    version_results.append(version_info)

                    if len(accepted_versions) > 1:
                        # Check for downgrade
                        oldest = accepted_versions[0]
                        newest = accepted_versions[-1]

                        # Compare capabilities
                        oldest_caps = set(oldest.get("capabilities", []))
                        newest_caps = set(newest.get("capabilities", []))
                        missing_in_old = newest_caps - oldest_caps

                        if oldest["requested"] != newest["requested"]:
                            severity = "medium" if missing_in_old else "low"
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"MCP server supports protocol downgrade: accepted version {oldest['requested']}",
                                    description=(
                                        f"Server accepted protocol version {oldest['requested']} ({oldest['description']}). "
                                        f"Latest accepted: {newest['requested']}. "
                                        + (
                                            f"Older version missing capabilities: {', '.join(missing_in_old)}"
                                            if missing_in_old
                                            else ""
                                        )
                                    ),
                                    severity=severity,
                                    evidence=(
                                        f"Accepted versions: {', '.join(v['requested'] for v in accepted_versions)}\n"
                                        f"Oldest caps: {', '.join(oldest_caps) or 'none'}\n"
                                        f"Newest caps: {', '.join(newest_caps) or 'none'}"
                                    ),
                                    host=host,
                                    discriminator="protocol-downgrade",
                                    raw_data=version_info,
                                )
                            )
                    elif len(accepted_versions) == 1:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Server only accepts current protocol version",
                                description=f"MCP server only accepted version {accepted_versions[0]['requested']}.",
                                severity="info",
                                evidence=f"Accepted: {accepted_versions[0]['requested']}\nRejected: {', '.join(rejected_versions)}",
                                host=host,
                                discriminator="protocol-current",
                            )
                        )

            except Exception as e:
                result.errors.append(f"Protocol version probe on {server_url}: {e}")

        if version_results:
            result.outputs["mcp_protocol_versions"] = version_results

        return result
