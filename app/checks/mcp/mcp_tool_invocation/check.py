"""
app/checks/mcp/tool_invocation.py - MCP Tool Invocation Probing

Sends safe test payloads to discovered MCP tools and observes behavior.
Validates whether tools classified as high-risk actually execute.

Safety constraints:
- NEVER sends destructive payloads
- Only read-only operations
- Response capped at 1000 bytes
- All invocations logged for proof-of-scope

**Probe/grade.** The probe sends one `tools/call` per tool,
records it via `exchange_from_response`, and hands one candidate per tool to the
grader. `grade()` re-reads each recorded exchange, recovers the tool name and the
exact arguments it sent from the request body (`params.name` / `params.arguments`,
§0.16 — never positional), re-derives the probe type from the tool in
`GradeContext.context` (falling back to the recorded payload's own markers), and
runs the same rule logic. `_analyze()` is the one classifier both halves would
call; here only `grade()` judges, since the probe emits no observation.

**Contextual**: "did the tool actually execute, or merely
answer?" is a continuum the evidence places, so the rule logic runs inside
`grade()` at `GradingTier.RULE` and the real call belongs to the planned LLM grading tier. The contract
keeps its wave-1 block (`default: medium`, `range: [info, critical]`, no map).
Confidence states the rule tier's weakness: a returned string is not proof the
tool ran — a model fronting the tool can fabricate `uid=0(root)` — and a 2xx is
accepted, not executed.

References:
  https://modelcontextprotocol.io/specification
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import (
    SAFE_COMMANDS,
    SAFE_FETCH_URLS,
    SAFE_QUERIES,
    SAFE_READ_PATHS,
    build_probe_payload,
    cap_response,
    classify_tool_probe_type,
    is_payload_safe,
    log_invocation,
)
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}


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

    intrusive = True  # Active probing — gated behind opt-in

    reason = "A tool classified as 'high risk' by name may not actually execute. Probing validates real risk."
    references = [
        "MCP Specification - Tools - https://spec.modelcontextprotocol.io/specification/server/tools/",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
    ]
    techniques = ["tool probing", "behavioral analysis", "risk validation"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])
        scan_id = context.get("scan_id") or ""
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

            request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": payload},
                "id": 1,
            }

            try:
                async with AsyncHttpClient(cfg) as client:
                    resp = await client.post(server_url, json=request, headers=JSON_HEADERS)
            except Exception as e:
                result.errors.append(f"Tool invocation {tool_name}: {e}")
                continue

            exchange = exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=tool_host,
                method="POST",
                request_headers=JSON_HEADERS,
                request_json=request,
            )
            candidate = self.create_candidate(host=tool_host, discriminator=f"invoke-{tool_name}")
            candidate.attach(exchange)
            result.candidates.append(candidate)

            invocation_results.append(
                log_invocation(
                    tool_name,
                    payload,
                    resp.status_code if not resp.error else None,
                    resp.body or "",
                )
            )

        if invocation_results:
            result.outputs["mcp_invocation_results"] = invocation_results

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        tools_by_name = {
            t.get("name"): t for t in (ctx.context.get("mcp_tools") or []) if isinstance(t, dict)
        }
        verdicts: list[Verdict] = []
        for exchange in evidence:
            request = self._request_of(exchange)
            if request is None:
                continue
            tool_name = request.get("params", {}).get("name", "unknown")
            payload = request.get("params", {}).get("arguments", {}) or {}
            tool = tools_by_name.get(tool_name, {"name": tool_name})
            probe_type = self._probe_type_for(tool, payload)

            verdict = self._analyze(tool_name, tool, probe_type, payload, exchange, ctx)
            if verdict is not None:
                verdicts.append(verdict)
        return verdicts

    def _analyze(
        self,
        tool_name: str,
        tool: dict,
        probe_type: str,
        payload: dict,
        exchange: Exchange,
        ctx: GradeContext,
    ) -> Verdict | None:
        inv_log = log_invocation(
            tool_name,
            payload,
            exchange.response_status if not exchange.error else None,
            exchange.response_body or "",
        )

        def verdict(severity, confidence, discriminator, title, description, evidence, why):
            return Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=discriminator,
                title=title,
                description=description,
                evidence=evidence,
                reasoning=why,
                signals={"probe_type": probe_type, "status": exchange.response_status},
                raw_data=inv_log,
                tier=ctx.tier,
                evidence_ids=[exchange.id],
            )

        if exchange.error:
            return verdict(
                "info",
                0.7,
                f"invoke-error-{tool_name}",
                f"Tool invocation failed: {tool_name} returned error for test payload",
                f"Tool '{tool_name}' returned an error when invoked with a safe test payload.",
                f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nError: {exchange.error}",
                "a transport error is a low-stakes fact about reachability, not a judgement "
                "about the tool's capability",
            )

        body = cap_response(exchange.response_body)
        status = exchange.response_status

        if status in (401, 403):
            return verdict(
                "medium",
                0.6,
                f"invoke-auth-{tool_name}",
                f"Tool executes but requires auth: '{tool_name}' returned permission denied",
                f"Tool '{tool_name}' is protected by authentication/authorization.",
                f"Tool: {tool_name}\nStatus: {status}\nResponse: {body[:200]}",
                "a 401/403 says something gates the call, but a WAF or a generic auth layer in "
                "front of the server returns the same without the tool existing",
            )

        if status != 200:
            return verdict(
                "info",
                0.7,
                f"invoke-fail-{tool_name}",
                f"Tool invocation failed: {tool_name} (status {status})",
                f"Tool '{tool_name}' returned non-200 status.",
                f"Tool: {tool_name}\nStatus: {status}\nResponse: {body[:200]}",
                "a non-200 status is a low-stakes fact, not a capability judgement",
            )

        tool_result = self._extract_tool_result(exchange.response_body)
        result_text = str(tool_result)[:500] if tool_result else ""

        if probe_type == "exec" and tool_result:
            if "chainsmith-probe" in result_text or any(
                kw in result_text.lower() for kw in ["root", "uid=", "hostname", "\\users\\"]
            ):
                return verdict(
                    "critical",
                    0.6,
                    f"invoke-exec-{tool_name}",
                    f"Tool executes commands: '{tool_name}' returned real output",
                    (
                        f"Tool '{tool_name}' executed a command and returned real system output. "
                        "This confirms arbitrary command execution capability."
                    ),
                    f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                    "the response carries a command-output marker, but a model or wrapper fronting "
                    "the tool can echo the probe string or fabricate uid=0(root) without any real "
                    "execution — hallucinated output is not proof the command ran",
                )

        elif probe_type == "file" and tool_result:
            if result_text and len(result_text) > 5:
                return verdict(
                    "critical",
                    0.4,
                    f"invoke-file-{tool_name}",
                    f"Tool reads files: '{tool_name}' returned file contents",
                    (
                        f"Tool '{tool_name}' returned content when asked to read a file. "
                        "This confirms filesystem read access."
                    ),
                    f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                    "any non-empty result over five characters trips this; the tool answering is "
                    "not proof it read the requested file rather than returning an error, a prompt "
                    "or a fabricated line",
                )

        elif probe_type == "fetch" and tool_result:
            if any(kw in result_text.lower() for kw in ["origin", "headers", "url", "http"]):
                return verdict(
                    "high",
                    0.45,
                    f"invoke-fetch-{tool_name}",
                    f"Tool makes HTTP requests: '{tool_name}' fetched external URL (SSRF risk)",
                    (
                        f"Tool '{tool_name}' successfully fetched an external URL. "
                        "This can be used for SSRF attacks."
                    ),
                    f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                    "the keywords matched are common in any JSON reply, including an echo of the "
                    "requested url; a real outbound fetch is not distinguished from a tool that "
                    "reflects its arguments",
                )

        elif probe_type == "search" and tool_result:
            if result_text and len(result_text) > 10:
                return verdict(
                    "high",
                    0.4,
                    f"invoke-search-{tool_name}",
                    f"Tool queries database: '{tool_name}' returned real data",
                    f"Tool '{tool_name}' returned data from a query/search operation.",
                    f"Tool: {tool_name}\nPayload: {json.dumps(payload)[:200]}\nOutput: {result_text[:300]}",
                    "any result over ten characters trips this; returned text is not proof a "
                    "backing datastore was queried rather than a canned or echoed response",
                )

        if tool_result and result_text:
            return verdict(
                "medium" if tool.get("risk_level") in ("critical", "high") else "low",
                0.4,
                f"invoke-ok-{tool_name}",
                f"Tool '{tool_name}' executed successfully with test payload",
                f"Tool '{tool_name}' returned a result for the probe payload.",
                f"Tool: {tool_name}\nProbe type: {probe_type}\nOutput: {result_text[:300]}",
                "the tool returned something for a safe payload, which is accepted, not shown to "
                "have performed a privileged action; the severity leans on the name-based risk "
                "class, not on observed effect",
            )

        return None

    @staticmethod
    def _probe_type_for(tool: dict, payload: dict) -> str:
        """The probe type, from the tool in context when present, else re-derived
        from the recorded payload's own safe markers."""
        if tool.get("description") is not None or tool.get("input_schema") is not None:
            return classify_tool_probe_type(tool)
        values = {str(v) for v in payload.values()}
        if SAFE_COMMANDS[0] in values:
            return "exec"
        if SAFE_FETCH_URLS[0] in values:
            return "fetch"
        if SAFE_READ_PATHS[0] in values:
            return "file"
        if values & set(SAFE_QUERIES):
            return "search"
        return "generic"

    @staticmethod
    def _request_of(exchange: Exchange) -> dict | None:
        """The recorded tools/call request, or None for anything else."""
        try:
            body = json.loads(exchange.request_body or "{}")
        except json.JSONDecodeError:
            return None
        if body.get("method") != "tools/call":
            return None
        return body

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
