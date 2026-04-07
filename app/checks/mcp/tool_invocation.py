"""
app/checks/mcp/tool_invocation.py - MCP Tool Invocation Probing

Sends safe test payloads to discovered MCP tools and observes behavior.
Validates whether tools classified as high-risk actually execute.

Safety constraints:
- NEVER sends destructive payloads
- Only read-only operations
- Response capped at 1000 bytes
- All invocations logged for proof-of-scope

References:
  https://modelcontextprotocol.io/specification
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import (
    build_probe_payload,
    cap_response,
    classify_tool_probe_type,
    is_payload_safe,
    log_invocation,
)
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation


class MCPToolInvocationCheck(BaseCheck):
    """
    Probe discovered MCP tools with safe test payloads.

    Sends minimal, non-destructive payloads to tools and observes
    whether they actually execute. Validates risk classifications.
    """

    name = "mcp_tool_invocation"
    description = "Probe MCP tools with safe test payloads to validate risk"

    conditions = [CheckCondition("mcp_tools", "truthy"), CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_invocation_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    intrusive = True  # Active probing — gated behind opt-in

    reason = "A tool classified as 'high risk' by name may not actually execute. Probing validates real risk."
    references = [
        "MCP Specification - Tools - https://spec.modelcontextprotocol.io/specification/server/tools/",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
    ]
    techniques = ["tool probing", "behavioral analysis", "risk validation"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])
        invocation_results = []

        if not mcp_tools or not mcp_servers:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        host = mcp_tools[0].get("service_host", "unknown")

        # Build server URL map
        server_urls = {}
        for server in mcp_servers:
            svc = server.get("service", {})
            server_urls[svc.get("host", "")] = server.get("url", "")

        for tool in mcp_tools:
            tool_name = tool.get("name", "unknown")
            tool_host = tool.get("service_host", host)
            server_url = tool.get("server_url") or server_urls.get(tool_host, "")

            if not server_url:
                continue

            probe_type = classify_tool_probe_type(tool)
            payload = build_probe_payload(tool, probe_type)

            if not is_payload_safe(payload):
                result.errors.append(f"Skipped unsafe payload for {tool_name}")
                continue

            try:
                async with AsyncHttpClient(cfg) as client:
                    resp = await client.post(
                        server_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": payload,
                            },
                            "id": 1,
                        },
                        headers={"Content-Type": "application/json"},
                    )

                    inv_log = log_invocation(
                        tool_name,
                        payload,
                        resp.status_code if not resp.error else None,
                        resp.body or "",
                    )
                    invocation_results.append(inv_log)

                    if resp.error:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Tool invocation failed: {tool_name} returned error for test payload",
                                description=f"Tool '{tool_name}' returned an error when invoked with a safe test payload.",
                                severity="info",
                                evidence=f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nError: {resp.error}",
                                host=tool_host,
                                discriminator=f"invoke-error-{tool_name}",
                                raw_data=inv_log,
                            )
                        )
                        continue

                    # Analyze response
                    self._analyze_invocation_response(
                        tool, probe_type, payload, resp, tool_host, result, inv_log
                    )

            except Exception as e:
                result.errors.append(f"Tool invocation {tool_name}: {e}")

        if invocation_results:
            result.outputs["mcp_invocation_results"] = invocation_results

        return result

    def _analyze_invocation_response(
        self,
        tool: dict,
        probe_type: str,
        payload: dict,
        resp,
        host: str,
        result: CheckResult,
        inv_log: dict,
    ) -> None:
        """Analyze tool invocation response to determine actual risk."""
        tool_name = tool.get("name", "unknown")
        body = cap_response(resp.body)
        status = resp.status_code

        if status == 401 or status == 403:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Tool executes but requires auth: '{tool_name}' returned permission denied",
                    description=f"Tool '{tool_name}' is protected by authentication/authorization.",
                    severity="medium",
                    evidence=f"Tool: {tool_name}\nStatus: {status}\nResponse: {body[:200]}",
                    host=host,
                    discriminator=f"invoke-auth-{tool_name}",
                    raw_data=inv_log,
                )
            )
            return

        if status != 200:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Tool invocation failed: {tool_name} (status {status})",
                    description=f"Tool '{tool_name}' returned non-200 status.",
                    severity="info",
                    evidence=f"Tool: {tool_name}\nStatus: {status}\nResponse: {body[:200]}",
                    host=host,
                    discriminator=f"invoke-fail-{tool_name}",
                    raw_data=inv_log,
                )
            )
            return

        # Parse JSON-RPC result
        tool_result = self._extract_tool_result(resp.body)
        result_text = str(tool_result)[:500] if tool_result else ""

        # Determine observation based on probe type and response
        if probe_type == "exec" and tool_result:
            if "chainsmith-probe" in result_text or any(
                kw in result_text.lower() for kw in ["root", "uid=", "hostname", "\\users\\"]
            ):
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Tool executes commands: '{tool_name}' returned real output",
                        description=(
                            f"Tool '{tool_name}' executed a command and returned real system output. "
                            "This confirms arbitrary command execution capability."
                        ),
                        severity="critical",
                        evidence=f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                        host=host,
                        discriminator=f"invoke-exec-{tool_name}",
                        raw_data=inv_log,
                    )
                )
                return

        elif probe_type == "file" and tool_result:
            if result_text and len(result_text) > 5:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Tool reads files: '{tool_name}' returned file contents",
                        description=(
                            f"Tool '{tool_name}' returned content when asked to read a file. "
                            "This confirms filesystem read access."
                        ),
                        severity="critical",
                        evidence=f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                        host=host,
                        discriminator=f"invoke-file-{tool_name}",
                        raw_data=inv_log,
                    )
                )
                return

        elif probe_type == "fetch" and tool_result:
            if any(kw in result_text.lower() for kw in ["origin", "headers", "url", "http"]):
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Tool makes HTTP requests: '{tool_name}' fetched external URL (SSRF risk)",
                        description=(
                            f"Tool '{tool_name}' successfully fetched an external URL. "
                            "This can be used for SSRF attacks."
                        ),
                        severity="high",
                        evidence=f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                        host=host,
                        discriminator=f"invoke-fetch-{tool_name}",
                        raw_data=inv_log,
                    )
                )
                return

        elif probe_type == "search" and tool_result:
            if result_text and len(result_text) > 10:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Tool queries database: '{tool_name}' returned real data",
                        description=f"Tool '{tool_name}' returned data from a query/search operation.",
                        severity="high",
                        evidence=f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                        host=host,
                        discriminator=f"invoke-search-{tool_name}",
                        raw_data=inv_log,
                    )
                )
                return

        # Generic: tool responded with data
        if tool_result and result_text:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Tool '{tool_name}' executed successfully with test payload",
                    description=f"Tool '{tool_name}' returned a result for the probe payload.",
                    severity="medium" if tool.get("risk_level") in ("critical", "high") else "low",
                    evidence=f"Tool: {tool_name}\nProbe type: {probe_type}\nOutput: {result_text[:300]}",
                    host=host,
                    discriminator=f"invoke-ok-{tool_name}",
                    raw_data=inv_log,
                )
            )

    def _extract_tool_result(self, body: str | None) -> Any:
        """Extract the result from a JSON-RPC tool call response."""
        if not body:
            return None
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                result = data.get("result", data)
                # MCP tool results may be wrapped in content array
                if isinstance(result, dict) and "content" in result:
                    content = result["content"]
                    if isinstance(content, list) and content:
                        return content[0].get("text", content[0])
                return result
        except (json.JSONDecodeError, TypeError):
            pass
        return body[:500] if body else None
