"""
app/checks/mcp/rate_limit.py - Tool Rate Limiting / Abuse

Tests if individual tool invocations are rate limited.
Unrestricted tools (especially fetch/http) could be abused as
SSRF proxies at scale.

**Probe/grade.** The probe sends a burst of identical tool
invocations, records every one, and hands them over as one candidate. `grade()`
re-reads the recorded burst — the tool name off the request body, the timing off
each exchange's `elapsed_ms` (never a wall clock, §0.17) — counts the status
codes, and places the verdict. `_burst_reading()` is the one parser both halves
call (§0.12).

The requests differ only in their JSON-RPC `id`, so which is which is their
recorded order (§0.15); the reading needs only the multiset of statuses, so
order does not actually matter to the verdict.

**Fixed**: both discriminators embed the tool name
(`ratelimit-<tool>` / `no-ratelimit-<tool>`), an unbounded set, so there is no
`observations:` map and `grade()` places the tier. Confidence is where the split
pays: a 429 is an explicit throttle, but *all-200* over a burst of ten is a weak
proxy for "unlimited" — a limit could sit above ten, and a 200 says the request
was accepted, not that the tool ran.

References:
  https://modelcontextprotocol.io/specification
  OWASP - API4:2023 Unrestricted Resource Consumption
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import build_safe_payload
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}


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

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])

        if not mcp_tools or not mcp_servers:
            return result

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

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        exchanges: list[Exchange] = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for i in range(self.BURST_SIZE):
                    body = {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": payload},
                        "id": i + 1,
                    }
                    resp = await client.post(server_url, json=body, headers=JSON_HEADERS)
                    exchanges.append(
                        exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=host,
                            method="POST",
                            request_headers=JSON_HEADERS,
                            request_json=body,
                        )
                    )
        except Exception as e:
            result.errors.append(f"Rate limit test: {e}")

        if exchanges:
            candidate = self.create_candidate(
                host=host,
                discriminator=f"ratelimit-{tool_name}",
                target_url=server_url,
            )
            for exchange in exchanges:
                candidate.attach(exchange)
            result.candidates.append(candidate)

            reading = self._burst_reading(exchanges)
            if reading:
                result.outputs["mcp_rate_limit_status"] = [reading]

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        reading = self._burst_reading(list(evidence))
        if not reading:
            return []

        tool_name = reading["tool"]
        elapsed = reading["elapsed_seconds"]

        if reading["rate_limited"]:
            return [
                Verdict(
                    severity="info",
                    confidence=0.8,
                    discriminator=f"ratelimit-{tool_name}",
                    title=(
                        f"Tool rate limiting detected: {tool_name} limited to "
                        f"~{reading['success_count']}/{self.BURST_SIZE} in {elapsed:.1f}s"
                    ),
                    description=(
                        f"Tool '{tool_name}' was rate-limited after {reading['success_count']} "
                        f"successful invocations ({reading['rate_limited_count']} got 429 responses)."
                    ),
                    evidence=(
                        f"Tool: {tool_name}\n"
                        f"Burst: {self.BURST_SIZE} requests in {elapsed:.1f}s\n"
                        f"Success: {reading['success_count']}, Rate limited: {reading['rate_limited_count']}"
                    ),
                    reasoning=(
                        "an explicit 429 is the server itself declaring a throttle, so the "
                        "presence of rate limiting is well-evidenced; only the exact threshold "
                        "is uncertain"
                    ),
                    signals={
                        "success_count": reading["success_count"],
                        "rate_limited_count": reading["rate_limited_count"],
                    },
                    references=self.references,
                    raw_data=reading,
                    tier=ctx.tier,
                    evidence_ids=[e.id for e in evidence],
                )
            ]

        if reading["success_count"] == self.BURST_SIZE:
            return [
                Verdict(
                    severity="medium",
                    confidence=0.55,
                    discriminator=f"no-ratelimit-{tool_name}",
                    title=(
                        f"No per-tool rate limiting: {tool_name} accepts unlimited rapid invocations"
                    ),
                    description=(
                        f"Tool '{tool_name}' accepted all {self.BURST_SIZE} invocations "
                        f"in {elapsed:.1f}s without rate limiting. "
                        "This could be abused for SSRF proxying or resource exhaustion."
                    ),
                    evidence=(
                        f"Tool: {tool_name}\n"
                        f"Burst: {self.BURST_SIZE} requests in {elapsed:.1f}s\n"
                        f"All succeeded with status 200"
                    ),
                    reasoning=(
                        f"a burst of {self.BURST_SIZE} all-200 responses is a weak proxy for "
                        "'unlimited': a limit could sit just above this burst, and a 200 says the "
                        "request was accepted, not that the tool actually executed the work"
                    ),
                    signals={"success_count": reading["success_count"]},
                    references=self.references,
                    raw_data=reading,
                    tier=ctx.tier,
                    evidence_ids=[e.id for e in evidence],
                )
            ]

        return []

    # ── The parser both halves share ─────────────────────────────────

    def _burst_reading(self, exchanges: list[Exchange]) -> dict | None:
        """Rebuild the burst summary off the recorded exchanges. Timing is the
        sum of each exchange's `elapsed_ms` (§0.17), never a wall clock."""
        if not exchanges:
            return None

        statuses = [e.response_status for e in exchanges]
        success_count = sum(1 for s in statuses if s == 200)
        rate_limited = sum(1 for s in statuses if s == 429)
        errors = sum(1 for s in statuses if s and s >= 500)
        elapsed = sum(e.elapsed_ms or 0.0 for e in exchanges) / 1000.0

        return {
            "tool": self._tool_of(exchanges[0]),
            "burst_size": len(exchanges),
            "elapsed_seconds": round(elapsed, 2),
            "success_count": success_count,
            "rate_limited_count": rate_limited,
            "error_count": errors,
            "rate_limited": rate_limited > 0,
        }

    @staticmethod
    def _tool_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
            return body.get("params", {}).get("name", "unknown")
        except (json.JSONDecodeError, TypeError):
            return "unknown"
