"""
app/checks/mcp/tool_enumeration.py - MCP Tool Enumeration

Enumerate tools exposed by MCP servers and assess their risk level.

Requires mcp_discovery to have found MCP server endpoints.
Probes tools/list to enumerate available tools, then classifies
each tool by risk level based on its capabilities.

Risk classification:
- CRITICAL: Command execution, code evaluation, process spawning
- HIGH: File system access (read/write), network requests, database access
- MEDIUM: Environment access, configuration modification, user data access
- LOW: Read-only data access, formatting, computation
- INFO: Benign utilities (time, math, text processing)

**Probe/grade.** The probe walks the tools/list paths for
each server, records every request it sends, and hands them over as one
candidate per server — each server's observations carry that server's URL as
`target_url`, so it cannot be one candidate per service (§0.15). `grade()`
re-reads the recorded listing and emits one verdict per tool. `_listing_from()`
is the one parser both halves call (§0.12): the probe reads its `mcp_tools` /
`high_risk_tools` outputs off the exchange it just recorded, and it skips the
same 404/405/error answers the grader skips.

**Fixed**: every discriminator embeds a tool name
(`tool-<name>`), an unbounded set, so the contract declares no `observations:`
map and `grade()` places the tier. Confidence comes from *what* matched
(`_classify`): a tool-name pattern matched as a whole token is the author's own
declaration of capability; the same pattern inside a longer word (`cmd` in
`cmdb_lookup`) is a substring collision; a description phrase is weaker, and a
schema parameter name (`path`, `query`) says little about what the tool does
with it. Nothing here invokes a tool, so declared capability is never shown to
be reachable or unsandboxed.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/server/tools/
"""

import json
import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Tool name patterns mapped to risk levels
TOOL_RISK_PATTERNS = {
    "critical": [
        r"exec(ute)?(_|\s)?command",
        r"run(_|\s)?shell",
        r"shell(_|\s)?exec",
        r"spawn(_|\s)?process",
        r"eval(uate)?(_|\s)?code",
        r"run(_|\s)?code",
        r"system(_|\s)?command",
        r"bash",
        r"powershell",
        r"cmd",
        r"terminal",
    ],
    "high": [
        r"(read|write|delete|create)(_|\s)?file",
        r"file(_|\s)?(read|write|delete|create|system)",
        r"fs(_|\s)?(read|write)",
        r"(http|fetch|request|curl|wget)",
        r"(sql|database|db)(_|\s)?(query|execute)",
        r"send(_|\s)?(email|mail|message)",
        r"upload",
        r"download",
        r"ssh",
        r"ftp",
        r"s3",
        r"aws",
        r"gcp",
        r"azure",
    ],
    "medium": [
        r"env(ironment)?(_|\s)?(get|set|read)",
        r"config(uration)?(_|\s)?(get|set|read|write)",
        r"(get|read)(_|\s)?secret",
        r"credential",
        r"api(_|\s)?key",
        r"user(_|\s)?data",
        r"memory(_|\s)?(read|write|get|set)",
        r"state(_|\s)?(get|set)",
        r"browser",
        r"screenshot",
        r"clipboard",
    ],
    "low": [
        r"(get|read|list|search)(_|\s)?",
        r"format",
        r"parse",
        r"validate",
        r"convert",
        r"calculate",
        r"transform",
    ],
}

# Description patterns for additional context
DESC_RISK_PATTERNS = {
    "critical": [
        r"execut(e|es|ing) (command|code|script)",
        r"run(s|ning)? (shell|bash|command)",
        r"spawn(s|ing)? process",
        r"system command",
    ],
    "high": [
        r"(read|write|access)(es|ing)? file",
        r"file system",
        r"http request",
        r"network (access|request)",
        r"database (query|access)",
        r"send (email|message)",
    ],
    "medium": [
        r"environment variable",
        r"configuration",
        r"secret",
        r"credential",
        r"user data",
        r"sensitive",
    ],
}


class MCPToolEnumerationCheck(ServiceIteratingCheck):
    """
    Enumerate and classify tools exposed by MCP servers.

    Probes discovered MCP servers with tools/list to enumerate
    available tools, then classifies each by risk level based
    on name patterns and descriptions.
    """

    name = "mcp_tool_enumeration"
    description = "Enumerate tools exposed by MCP servers and assess risk levels"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_tools", "high_risk_tools"]
    service_types = ["ai", "api", "http"]

    reason = "MCP tools can execute commands, access files, and perform privileged operations. Enumerating tools reveals the attack surface for injection and abuse."
    references = [
        "MCP Specification - Tools - https://spec.modelcontextprotocol.io/specification/server/tools/",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = ["API enumeration", "capability mapping", "attack surface analysis"]

    # Paths to probe for tools/list
    TOOL_LIST_PATHS = [
        "/tools/list",
        "/mcp/tools/list",
        "/v1/mcp/tools/list",
        "/api/mcp/tools/list",
    ]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        """Check a service for MCP tools."""
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # Get MCP servers from context (from mcp_discovery)
        mcp_servers = context.get("mcp_servers", [])

        # Filter to servers on this service
        service_servers = [
            s for s in mcp_servers if s.get("service", {}).get("host") == service.host
        ]

        if not service_servers:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        all_tools = []
        high_risk_tools = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for server in service_servers:
                    server_url = server.get("url", service.url)
                    base_path = server.get("path", "")

                    exchanges = await self._enumerate_tools(client, service, base_path, scan_id)
                    listing = self._listing_from(exchanges)
                    if listing is None:
                        continue

                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"tools-{base_path or '/'}",
                        target=service,
                        target_url=server_url,
                    )
                    for exchange in exchanges:
                        candidate.attach(exchange)
                    result.candidates.append(candidate)

                    tools, _ = listing
                    for tool in tools:
                        tool_info = self._analyze_tool(tool, service.host, server_url)
                        all_tools.append(tool_info)
                        if tool_info["risk_level"] in ("critical", "high"):
                            high_risk_tools.append(tool_info)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if all_tools:
            result.outputs["mcp_tools"] = all_tools
        if high_risk_tools:
            result.outputs["high_risk_tools"] = high_risk_tools

        return result

    async def _enumerate_tools(
        self, client: AsyncHttpClient, service: Service, base_path: str, scan_id: str
    ) -> list[Exchange]:
        """Walk the tools/list paths, recording every request sent.

        Stops at the first answer `_listing_from` can read, so the recorded
        exchanges end with the one the grader will parse.
        """

        # Try direct path first
        paths_to_try = [f"{base_path.rstrip('/')}/tools/list"] if base_path else []
        paths_to_try.extend(self.TOOL_LIST_PATHS)

        exchanges: list[Exchange] = []
        for path in paths_to_try:
            url = service.with_path(path)

            # Try JSON-RPC style request
            payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            resp = await client.post(url, json=payload, headers=JSON_HEADERS)
            exchange = exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=service.host,
                method="POST",
                request_headers=JSON_HEADERS,
                request_json=payload,
            )
            exchanges.append(exchange)

            if not self._answered(exchange):
                # Try GET
                resp = await client.get(url)
                exchange = exchange_from_response(
                    resp, check_name=self.name, scan_id=scan_id, host=service.host
                )
                exchanges.append(exchange)
                if not self._answered(exchange):
                    continue

            if self._parse_tools_response(exchange) is not None:
                break

        return exchanges

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        listing = self._listing_from(list(evidence))
        if listing is None:
            return []
        tools, source = listing

        server_url = ctx.target_url or (ctx.target.url if ctx.target else "")
        verdicts: list[Verdict] = []
        for tool in tools:
            tool_info = self._analyze_tool(tool, ctx.host, server_url)
            _, basis, bounded = self._classify(
                tool_info["name"], tool_info["description"], tool_info["input_schema"]
            )
            confidence, why = self._confidence(tool_info["risk_level"], basis, bounded)
            verdicts.append(
                Verdict(
                    severity=self._risk_to_severity(tool_info["risk_level"]),
                    confidence=confidence,
                    discriminator=f"tool-{tool_info['name']}",
                    title=f"MCP tool: {tool_info['name']} ({tool_info['risk_level']} risk)",
                    description=self._build_tool_description(tool_info),
                    evidence=self._build_tool_evidence(tool_info),
                    reasoning=why,
                    signals={
                        "risk_level": tool_info["risk_level"],
                        "classified_by": basis,
                        "whole_token": bounded,
                    },
                    references=self.references,
                    raw_data=tool_info,
                    tier=ctx.tier,
                    evidence_ids=[source.id],
                )
            )
        return verdicts

    @staticmethod
    def _confidence(risk_level: str, basis: str, bounded: bool) -> tuple[float, str]:
        unproven = (
            "the listing is the server's own description of the tool and nothing was "
            "invoked, so the capability is declared, not shown reachable or unsandboxed"
        )
        if basis == "name" and bounded:
            return (
                0.7,
                f"the tool's name matches a {risk_level}-risk pattern as a whole token; {unproven}",
            )
        if basis == "name":
            return 0.5, (
                f"the {risk_level}-risk pattern matched inside a longer word of the tool name, "
                f"which is how `cmd` turns up in `cmdb_lookup`; {unproven}"
            )
        if basis == "description":
            return 0.6, (
                f"only the free-text description matched a {risk_level}-risk phrase, and "
                f"descriptions paraphrase loosely; {unproven}"
            )
        if basis == "schema":
            return 0.45, (
                f"only a parameter name placed this tool at {risk_level}; a `path` or `query` "
                f"parameter says little about what the tool does with it; {unproven}"
            )
        return 0.6, (
            "no name, description or parameter pattern matched; the absence is bounded by "
            "fixed pattern tables, so a dangerous tool with an unremarkable name reads as benign"
        )

    # ── The parser both halves share ─────────────────────────────────

    @staticmethod
    def _answered(exchange: Exchange) -> bool:
        return not (exchange.error or exchange.response_status in (404, 405))

    def _listing_from(self, exchanges: list[Exchange]) -> tuple[list[dict], Exchange] | None:
        """The first tool listing in recorded order, and the exchange it came from.

        Skips the answers the probe fell through on — an error, a 404 or a 405
        — and any answered body that does not parse as a listing.
        """
        for exchange in exchanges:
            if not self._answered(exchange):
                continue
            tools = self._parse_tools_response(exchange)
            if tools is not None:
                return tools, exchange
        return None

    def _parse_tools_response(self, exchange: Exchange) -> list[dict] | None:
        """Parse tools from MCP response."""
        if not exchange.response_body:
            return None

        try:
            data = json.loads(exchange.response_body)

            # JSON-RPC response
            if "result" in data:
                result = data["result"]
                if isinstance(result, dict) and "tools" in result:
                    return result["tools"]
                elif isinstance(result, list):
                    return result

            # Direct array response
            if isinstance(data, list):
                return data

            # Direct tools key
            if "tools" in data:
                return data["tools"]

        except json.JSONDecodeError:
            pass

        return None

    def _analyze_tool(self, tool: dict, host: str, server_url: str) -> dict:
        """Analyze a tool and classify its risk level."""
        name = tool.get("name", "unknown")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema", tool.get("input_schema", {}))

        # Determine risk level
        risk_level = self._classify_risk(name, description, input_schema)
        risk_indicators = self._get_risk_indicators(name, description)

        return {
            "name": name,
            "description": description,
            "input_schema": input_schema,
            "risk_level": risk_level,
            "risk_indicators": risk_indicators,
            "server_url": server_url,
            "service_host": host,
        }

    def _classify_risk(self, name: str, description: str, schema: dict) -> str:
        """Classify tool risk level based on name, description, and schema."""
        return self._classify(name, description, schema)[0]

    @staticmethod
    def _classify(name: str, description: str, schema: dict) -> tuple[str, str, bool]:
        """Risk level, what decided it (`name` / `description` / `schema` /
        `none`), and whether a name match covered a whole token."""
        name_lower = name.lower()
        desc_lower = description.lower()

        # Check name patterns (highest priority)
        for level in ("critical", "high", "medium", "low"):
            for pattern in TOOL_RISK_PATTERNS.get(level, []):
                match = re.search(pattern, name_lower, re.IGNORECASE)
                if match:
                    before = name_lower[match.start() - 1] if match.start() else ""
                    after = name_lower[match.end()] if match.end() < len(name_lower) else ""
                    bounded = not before.isalnum() and not after.isalnum()
                    return level, "name", bounded

        # Check description patterns
        for level in ("critical", "high", "medium"):
            for pattern in DESC_RISK_PATTERNS.get(level, []):
                if re.search(pattern, desc_lower, re.IGNORECASE):
                    return level, "description", False

        # Check schema for dangerous parameter names
        if schema:
            props = schema.get("properties", {})
            dangerous_params = [
                "command",
                "cmd",
                "shell",
                "code",
                "script",
                "path",
                "file",
                "url",
                "query",
            ]
            for param in dangerous_params:
                if param in [p.lower() for p in props]:
                    if param in ("command", "cmd", "shell", "code", "script"):
                        return "critical", "schema", False
                    elif param in ("path", "file"):
                        return "high", "schema", False
                    else:
                        return "medium", "schema", False

        return "info", "none", False

    def _get_risk_indicators(self, name: str, description: str) -> list[str]:
        """Get list of risk indicators that matched."""
        indicators = []
        name_lower = name.lower()
        desc_lower = description.lower()

        for _level, patterns in TOOL_RISK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, name_lower, re.IGNORECASE):
                    indicators.append(f"name:{pattern}")

        for _level, patterns in DESC_RISK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, desc_lower, re.IGNORECASE):
                    indicators.append(f"desc:{pattern}")

        return indicators

    def _risk_to_severity(self, risk_level: str) -> str:
        """Convert risk level to observation severity."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        return mapping.get(risk_level, "info")

    def _build_tool_description(self, tool_info: dict) -> str:
        """Build human-readable tool description."""
        parts = [f"MCP tool '{tool_info['name']}' discovered."]

        if tool_info.get("description"):
            parts.append(f"Description: {tool_info['description'][:200]}")

        parts.append(f"Risk level: {tool_info['risk_level'].upper()}")

        if tool_info["risk_level"] == "critical":
            parts.append("This tool may allow arbitrary command execution or code evaluation.")
        elif tool_info["risk_level"] == "high":
            parts.append(
                "This tool may allow file system access, network requests, or database operations."
            )

        return " ".join(parts)

    def _build_tool_evidence(self, tool_info: dict) -> str:
        """Build evidence string for tool observation."""
        lines = [
            f"Tool: {tool_info['name']}",
            f"Risk: {tool_info['risk_level']}",
        ]

        if tool_info.get("description"):
            lines.append(f"Description: {tool_info['description'][:100]}")

        if tool_info.get("risk_indicators"):
            lines.append(f"Indicators: {', '.join(tool_info['risk_indicators'][:5])}")

        if tool_info.get("input_schema"):
            schema = tool_info["input_schema"]
            if "properties" in schema:
                params = list(schema["properties"].keys())[:5]
                lines.append(f"Parameters: {', '.join(params)}")

        return "\n".join(lines)
