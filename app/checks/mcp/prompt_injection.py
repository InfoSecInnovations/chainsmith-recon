"""
app/checks/mcp/prompt_injection.py - MCP Prompt Injection via Tool Results

Tests the primary MCP exploit vector: tool results flowing back into
the LLM context as assistant content. If a tool returns attacker-controlled
content, the LLM may treat embedded instructions as its own.

Cross-suite check: requires both MCP tools and AI chat endpoints.

References:
  https://modelcontextprotocol.io/specification
  OWASP LLM Top 10 - LLM01 Prompt Injection
  MITRE ATLAS - AML.T0051 LLM Plugin Compromise
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import cap_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

# Canary phrases that indicate the LLM followed injected instructions
CANARY_PHRASES = [
    "CHAINSMITH_PWNED",
    "chainsmith_pwned",
    "I have been compromised",
    "INJECTED_RESPONSE",
]

# Tools that return text content from external sources (high injection risk)
TEXT_TOOL_PATTERNS = [
    "fetch",
    "browse",
    "search",
    "read",
    "get_url",
    "http",
    "scrape",
    "crawl",
    "download",
    "load",
]


class MCPPromptInjectionCheck(BaseCheck):
    """
    Test for prompt injection via MCP tool results.

    Identifies tools that return external text content, then tests
    whether that content can influence the connected LLM's behavior.
    """

    name = "mcp_prompt_injection"
    description = "Test for prompt injection via MCP tool results flowing into LLM context"

    conditions = [
        CheckCondition("mcp_tools", "truthy"),
        CheckCondition("mcp_servers", "truthy"),
    ]
    produces = ["mcp_injection_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    intrusive = True

    reason = (
        "Tool results flow into LLM context as trusted content — the primary MCP exploit vector"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
        "MCP Specification - https://modelcontextprotocol.io/specification",
    ]
    techniques = ["prompt injection", "tool result manipulation", "LLM exploitation"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])
        chat_endpoints = context.get("chat_endpoints", [])

        if not mcp_tools or not mcp_servers:
            return result

        injection_results = []
        host = mcp_tools[0].get("service_host", "unknown")

        # Build server URL map
        server_urls = {}
        for server in mcp_servers:
            svc = server.get("service", {})
            server_urls[svc.get("host", "")] = server.get("url", "")

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)

        # Step 1: Identify tools that return text from external sources
        text_tools = self._identify_text_tools(mcp_tools)

        if not text_tools:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="No text-returning MCP tools found for injection testing",
                    description="No MCP tools were identified that return external text content.",
                    severity="info",
                    evidence=f"Tools analyzed: {len(mcp_tools)}",
                    host=host,
                    discriminator="no-text-tools",
                )
            )
            return result

        # Step 2: Check if tools return unfiltered content
        for tool in text_tools:
            tool_name = tool.get("name", "unknown")
            tool_host = tool.get("service_host", host)
            server_url = tool.get("server_url") or server_urls.get(tool_host, "")

            if not server_url:
                continue

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Test: invoke tool and check if response contains unfiltered content
                    unfiltered = await self._test_unfiltered_content(client, server_url, tool, host)

                    injection_results.append(
                        {
                            "tool": tool_name,
                            "returns_external_content": unfiltered.get("returns_content", False),
                            "content_filtered": unfiltered.get("filtered", None),
                        }
                    )

                    if unfiltered.get("returns_content") and not unfiltered.get("filtered"):
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Tool returns unfiltered external content: {tool_name}",
                                description=(
                                    f"Tool '{tool_name}' returns external content without sanitization. "
                                    "Content flowing into the LLM context could contain injection payloads."
                                ),
                                severity="high",
                                evidence=(
                                    f"Tool: {tool_name}\n"
                                    f"Content type: {unfiltered.get('content_type', 'unknown')}\n"
                                    f"Preview: {cap_response(unfiltered.get('preview', ''))[:200]}"
                                ),
                                host=host,
                                discriminator=f"unfiltered-{tool_name}",
                                raw_data=unfiltered,
                            )
                        )

                    # Test: check if tool result content appears in LLM responses
                    if chat_endpoints and unfiltered.get("returns_content"):
                        influence = await self._test_llm_influence(
                            client, server_url, tool, chat_endpoints, host
                        )

                        if influence.get("influenced"):
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Tool result injection: LLM influenced by content from {tool_name}",
                                    description=(
                                        f"Content returned by tool '{tool_name}' influenced the LLM's "
                                        "response, indicating that tool results are included in the "
                                        "LLM context without adequate filtering."
                                    ),
                                    severity="critical",
                                    evidence=(
                                        f"Tool: {tool_name}\n"
                                        f"Influence type: {influence.get('type', 'unknown')}\n"
                                        f"Evidence: {influence.get('evidence', '')[:300]}"
                                    ),
                                    host=host,
                                    discriminator=f"injection-{tool_name}",
                                    raw_data=influence,
                                )
                            )

            except Exception as e:
                result.errors.append(f"Prompt injection test for {tool_name}: {e}")

        if not any(
            f.severity in ("high", "critical")
            for f in result.observations
            if f.check_name == self.name
        ):
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Tool results appear sanitized before LLM processing",
                    description="No evidence that tool results can inject into the LLM context.",
                    severity="info",
                    evidence=f"Text tools tested: {len(text_tools)}",
                    host=host,
                    discriminator="injection-safe",
                )
            )

        if injection_results:
            result.outputs["mcp_injection_results"] = injection_results

        return result

    def _identify_text_tools(self, tools: list[dict]) -> list[dict]:
        """Identify tools that likely return text from external sources."""
        text_tools = []
        for tool in tools:
            name = tool.get("name", "").lower()
            desc = tool.get("description", "").lower()
            combined = f"{name} {desc}"

            if any(pattern in combined for pattern in TEXT_TOOL_PATTERNS):
                text_tools.append(tool)

        return text_tools

    async def _test_unfiltered_content(
        self, client, server_url: str, tool: dict, host: str
    ) -> dict:
        """Test if a tool returns unfiltered external content."""
        tool_name = tool.get("name", "")
        schema = tool.get("input_schema", tool.get("inputSchema", {}))
        props = schema.get("properties", {}) if schema else {}

        # Build a test payload
        payload = {}
        for param in ("url", "uri", "href", "query", "q", "search", "path", "input"):
            if param in props:
                if param in ("url", "uri", "href"):
                    payload[param] = "http://httpbin.org/html"
                else:
                    payload[param] = "test chainsmith probe"
                break

        if not payload:
            return {"returns_content": False}

        resp = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": payload},
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        if resp.error or resp.status_code != 200:
            return {"returns_content": False}

        body = resp.body or ""
        content = self._extract_text_content(body)

        if content and len(content) > 20:
            # Check if content looks like external HTML/text
            is_external = any(
                kw in content.lower()
                for kw in [
                    "<html",
                    "<body",
                    "<p>",
                    "<!doctype",
                    "http://",
                    "https://",
                ]
            )
            return {
                "returns_content": True,
                "filtered": False,  # Simple heuristic — real filtering detection is complex
                "content_type": "html" if is_external else "text",
                "preview": content[:500],
            }

        return {"returns_content": False}

    async def _test_llm_influence(
        self, client, server_url: str, tool: dict, chat_endpoints: list, host: str
    ) -> dict:
        """
        Test if tool result content can influence LLM behavior.

        This is a simplified version — full testing would require
        a multi-turn conversation with tool use enabled.
        """
        # For now, check if there's a chat endpoint that supports tool use
        # and report that the vector exists
        tool_name = tool.get("name", "")

        for endpoint in chat_endpoints:
            ep_url = endpoint if isinstance(endpoint, str) else endpoint.get("url", "")
            if not ep_url:
                continue

            # Check if endpoint supports tool use by looking at its capabilities
            # This is a structural analysis — we report the vector without
            # actually performing the injection
            return {
                "influenced": False,
                "type": "structural",
                "evidence": (
                    f"Tool '{tool_name}' returns unfiltered content. "
                    f"Chat endpoint '{ep_url}' exists. The injection vector "
                    "is architecturally present but was not actively exploited."
                ),
                "tool": tool_name,
                "chat_endpoint": ep_url,
            }

        return {"influenced": False}

    def _extract_text_content(self, body: str) -> str:
        """Extract text content from a JSON-RPC tool call response."""
        if not body:
            return ""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                result = data.get("result", data)
                if isinstance(result, dict) and "content" in result:
                    content = result["content"]
                    if isinstance(content, list) and content:
                        item = content[0]
                        if isinstance(item, dict):
                            return item.get("text", str(item))
                        return str(item)
                if isinstance(result, str):
                    return result
                return str(result)[:500]
        except (json.JSONDecodeError, TypeError):
            return body[:500]
        return ""
