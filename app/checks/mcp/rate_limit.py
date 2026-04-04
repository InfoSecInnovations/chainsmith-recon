"""
app/checks/mcp/rate_limit.py - Tool Rate Limiting / Abuse

Tests if individual tool invocations are rate limited.
Unrestricted tools (especially fetch/http) could be abused as
SSRF proxies at scale.

References:
  https://modelcontextprotocol.io/specification
  OWASP - API4:2023 Unrestricted Resource Consumption
"""

import time
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import build_safe_payload
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig


class ToolRateLimitCheck(BaseCheck):
    """
    Test MCP tool invocation rate limits.

    Sends rapid tool invocations to check for per-tool and global
    rate limiting.
    """

    name = "mcp_tool_rate_limit"
    description = "Test if MCP tool invocations are rate limited"

    conditions = [CheckCondition("mcp_tools", "truthy"), CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_rate_limit_status"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 60.0
    intrusive = True

    reason = "Unrestricted tool invocations enable SSRF proxy abuse and resource exhaustion"
    references = [
        "OWASP API4:2023 Unrestricted Resource Consumption",
        "MCP Specification - https://modelcontextprotocol.io/specification",
    ]
    techniques = ["rate limit testing", "abuse potential assessment"]

    # Number of rapid requests to send
    BURST_SIZE = 10
    # Time window for burst (seconds)
    BURST_WINDOW = 2.0

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])
        rate_limit_status = []

        if not mcp_tools or not mcp_servers:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        host = mcp_tools[0].get("service_host", "unknown")

        # Pick a low-risk tool for testing (prefer info/low risk)
        test_tool = None
        for risk in ("info", "low", "medium"):
            for tool in mcp_tools:
                if tool.get("risk_level") == risk:
                    test_tool = tool
                    break
            if test_tool:
                break

        if not test_tool:
            test_tool = mcp_tools[0]

        tool_name = test_tool.get("name", "unknown")
        payload = build_safe_payload(test_tool)

        # Find server URL
        server_urls = {}
        for server in mcp_servers:
            svc = server.get("service", {})
            server_urls[svc.get("host", "")] = server.get("url", "")

        tool_host = test_tool.get("service_host", host)
        server_url = test_tool.get("server_url") or server_urls.get(tool_host, "")

        if not server_url:
            return result

        try:
            async with AsyncHttpClient(cfg) as client:
                # Send burst of requests
                start_time = time.monotonic()
                results_list = []

                for i in range(self.BURST_SIZE):
                    resp = await client.post(
                        server_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {"name": tool_name, "arguments": payload},
                            "id": i + 1,
                        },
                        headers={"Content-Type": "application/json"},
                    )
                    results_list.append(
                        {
                            "index": i,
                            "status": resp.status_code if not resp.error else None,
                            "error": resp.error,
                            "time": time.monotonic() - start_time,
                        }
                    )

                elapsed = time.monotonic() - start_time

                # Analyze results
                success_count = sum(1 for r in results_list if r["status"] == 200)
                rate_limited = sum(1 for r in results_list if r["status"] == 429)
                errors = sum(1 for r in results_list if r["status"] and r["status"] >= 500)

                status = {
                    "tool": tool_name,
                    "burst_size": self.BURST_SIZE,
                    "elapsed_seconds": round(elapsed, 2),
                    "success_count": success_count,
                    "rate_limited_count": rate_limited,
                    "error_count": errors,
                    "rate_limited": rate_limited > 0,
                }
                rate_limit_status.append(status)

                if rate_limited > 0:
                    result.findings.append(
                        build_finding(
                            check_name=self.name,
                            title=f"Tool rate limiting detected: {tool_name} limited to ~{success_count}/{self.BURST_SIZE} in {elapsed:.1f}s",
                            description=(
                                f"Tool '{tool_name}' was rate-limited after {success_count} "
                                f"successful invocations ({rate_limited} got 429 responses)."
                            ),
                            severity="info",
                            evidence=(
                                f"Tool: {tool_name}\n"
                                f"Burst: {self.BURST_SIZE} requests in {elapsed:.1f}s\n"
                                f"Success: {success_count}, Rate limited: {rate_limited}"
                            ),
                            host=host,
                            discriminator=f"ratelimit-{tool_name}",
                            raw_data=status,
                        )
                    )
                elif success_count == self.BURST_SIZE:
                    result.findings.append(
                        build_finding(
                            check_name=self.name,
                            title=f"No per-tool rate limiting: {tool_name} accepts unlimited rapid invocations",
                            description=(
                                f"Tool '{tool_name}' accepted all {self.BURST_SIZE} invocations "
                                f"in {elapsed:.1f}s without rate limiting. "
                                "This could be abused for SSRF proxying or resource exhaustion."
                            ),
                            severity="medium",
                            evidence=(
                                f"Tool: {tool_name}\n"
                                f"Burst: {self.BURST_SIZE} requests in {elapsed:.1f}s\n"
                                f"All succeeded with status 200"
                            ),
                            host=host,
                            discriminator=f"no-ratelimit-{tool_name}",
                            raw_data=status,
                        )
                    )

        except Exception as e:
            result.errors.append(f"Rate limit test: {e}")

        if rate_limit_status:
            result.outputs["mcp_rate_limit_status"] = rate_limit_status

        return result
