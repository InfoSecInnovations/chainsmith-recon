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

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/server/tools/
"""

import json
import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

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

    timeout_seconds = 60.0
    delay_between_targets = 0.3

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

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        """Check a service for MCP tools."""
        result = CheckResult(success=True)

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

                    tools = await self._enumerate_tools(client, service, base_path)

                    if tools is None:
                        continue

                    for tool in tools:
                        tool_info = self._analyze_tool(tool, service, server_url)
                        all_tools.append(tool_info)

                        # Generate findings based on risk level
                        severity = self._risk_to_severity(tool_info["risk_level"])

                        if tool_info["risk_level"] in ("critical", "high"):
                            high_risk_tools.append(tool_info)

                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=f"MCP tool: {tool_info['name']} ({tool_info['risk_level']} risk)",
                                description=self._build_tool_description(tool_info),
                                severity=severity,
                                evidence=self._build_tool_evidence(tool_info),
                                host=service.host,
                                discriminator=f"tool-{tool_info['name']}",
                                target=service,
                                target_url=server_url,
                                raw_data=tool_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if all_tools:
            result.outputs["mcp_tools"] = all_tools
        if high_risk_tools:
            result.outputs["high_risk_tools"] = high_risk_tools

        return result

    async def _enumerate_tools(
        self, client: AsyncHttpClient, service: Service, base_path: str
    ) -> list[dict] | None:
        """Enumerate tools via tools/list endpoint."""

        # Try direct path first
        paths_to_try = [f"{base_path.rstrip('/')}/tools/list"] if base_path else []
        paths_to_try.extend(self.TOOL_LIST_PATHS)

        for path in paths_to_try:
            url = service.with_path(path)

            # Try JSON-RPC style request
            resp = await client.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "id": 1,
                },
                headers={"Content-Type": "application/json"},
            )

            if resp.error or resp.status_code in (404, 405):
                # Try GET
                resp = await client.get(url)
                if resp.error or resp.status_code in (404, 405):
                    continue

            # Parse response
            tools = self._parse_tools_response(resp)
            if tools is not None:
                return tools

        return None

    def _parse_tools_response(self, resp) -> list[dict] | None:
        """Parse tools from MCP response."""
        if not resp.body:
            return None

        try:
            data = json.loads(resp.body)

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

    def _analyze_tool(self, tool: dict, service: Service, server_url: str) -> dict:
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
            "service_host": service.host,
        }

    def _classify_risk(self, name: str, description: str, schema: dict) -> str:
        """Classify tool risk level based on name, description, and schema."""
        name_lower = name.lower()
        desc_lower = description.lower()

        # Check name patterns (highest priority)
        for level in ("critical", "high", "medium", "low"):
            for pattern in TOOL_RISK_PATTERNS.get(level, []):
                if re.search(pattern, name_lower, re.IGNORECASE):
                    return level

        # Check description patterns
        for level in ("critical", "high", "medium"):
            for pattern in DESC_RISK_PATTERNS.get(level, []):
                if re.search(pattern, desc_lower, re.IGNORECASE):
                    return level

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
                        return "critical"
                    elif param in ("path", "file"):
                        return "high"
                    else:
                        return "medium"

        return "info"

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
        """Convert risk level to finding severity."""
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
        """Build evidence string for tool finding."""
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
