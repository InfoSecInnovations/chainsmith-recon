"""
app/checks/mcp/schema_leakage.py - Tool Schema Information Leakage

Analyzes MCP tool inputSchema definitions for sensitive information:
- Parameter names revealing internal structure
- Default values exposing configuration
- Enum values listing internal options
- Descriptions with internal details

Operates entirely on already-enumerated data — no HTTP requests.

References:
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
"""

import re
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding

# Patterns that indicate sensitive defaults
SENSITIVE_DEFAULT_PATTERNS = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?", "IP address"),
    (r"[a-zA-Z0-9_-]+\.internal(:\d+)?", "internal hostname"),
    (r"[a-zA-Z0-9_-]+\.local(:\d+)?", "local hostname"),
    (r"[a-zA-Z0-9_-]+\.corp(:\d+)?", "corporate hostname"),
    (r"localhost:\d+", "localhost endpoint"),
    (r"(postgres|mysql|mongo|redis)://", "database connection string"),
    (r"s3://[a-zA-Z0-9._-]+", "S3 bucket URI"),
    (r"https?://[a-zA-Z0-9._-]+\.internal", "internal URL"),
    (r"/opt/[a-zA-Z0-9/_-]+", "server path"),
    (r"/var/[a-zA-Z0-9/_-]+", "server path"),
    (r"/home/[a-zA-Z0-9/_-]+", "home directory path"),
    (r"/etc/[a-zA-Z0-9/_-]+", "system config path"),
    (r"[a-zA-Z0-9_-]+-prod", "production identifier"),
    (r"[a-zA-Z0-9_-]+-staging", "staging identifier"),
]

# Parameter names that reveal internal structure
SENSITIVE_PARAM_NAMES = {
    "table_name": "database table",
    "table": "database table",
    "database": "database name",
    "db_name": "database name",
    "db_host": "database host",
    "db_port": "database port",
    "db_password": "database password",
    "bucket_name": "S3 bucket",
    "bucket": "storage bucket",
    "collection": "database collection",
    "index_name": "search index",
    "index": "database index",
    "schema": "database schema",
    "namespace": "namespace",
    "region": "cloud region",
    "account_id": "account identifier",
    "tenant_id": "tenant identifier",
    "org_id": "organization identifier",
    "api_key": "API key",
    "secret_key": "secret key",
    "access_key": "access key",
    "password": "password",
    "token": "authentication token",
    "connection_string": "connection string",
    "endpoint": "service endpoint",
    "base_url": "base URL",
    "internal_url": "internal URL",
}

# Sensitive description keywords
SENSITIVE_DESC_PATTERNS = [
    (r"prod(uction)?\s+(database|server|instance|cluster)", "production infrastructure"),
    (r"internal\s+(api|service|endpoint|server)", "internal service"),
    (r"port\s+\d{4,5}", "port disclosure"),
    (r"\b(admin|root|superuser)\b", "privileged access hint"),
    (r"(postgres|mysql|mongo|redis|elasticsearch)\s+at\s+", "database location"),
    (r"aws\s+(account|region|arn)", "AWS infrastructure"),
    (r"gcp\s+(project|region)", "GCP infrastructure"),
    (r"azure\s+(subscription|resource)", "Azure infrastructure"),
]


class ToolSchemaLeakageCheck(BaseCheck):
    """
    Analyze MCP tool schemas for information leakage.

    Inspects inputSchema properties for parameter names, default values,
    enum values, and descriptions that reveal sensitive backend details.
    """

    name = "mcp_schema_leakage"
    description = "Analyze MCP tool schemas for sensitive information leakage"

    conditions = [CheckCondition("mcp_tools", "truthy")]
    produces = ["mcp_schema_leaks"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 30.0

    reason = "Tool schemas may reveal internal infrastructure details useful for targeted attacks"
    references = [
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
        "CWE-200 Exposure of Sensitive Information",
    ]
    techniques = ["schema analysis", "information disclosure", "reconnaissance"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])

        if not mcp_tools:
            return result

        all_leaks = []
        host = mcp_tools[0].get("service_host", "unknown")

        for tool in mcp_tools:
            tool_name = tool.get("name", "unknown")
            schema = tool.get("input_schema", {})
            description = tool.get("description", "")

            if not schema and not description:
                continue

            leaks = []

            # Check parameter names
            props = schema.get("properties", {})
            for param_name, param_def in props.items():
                param_lower = param_name.lower()
                if param_lower in SENSITIVE_PARAM_NAMES:
                    leaks.append(
                        {
                            "type": "sensitive_param",
                            "param": param_name,
                            "detail": SENSITIVE_PARAM_NAMES[param_lower],
                            "tool": tool_name,
                        }
                    )

                # Check default values
                default = param_def.get("default")
                if default and isinstance(default, str):
                    for pattern, desc in SENSITIVE_DEFAULT_PATTERNS:
                        if re.search(pattern, default):
                            leaks.append(
                                {
                                    "type": "sensitive_default",
                                    "param": param_name,
                                    "default": default,
                                    "detail": desc,
                                    "tool": tool_name,
                                }
                            )
                            break

                # Check enum values
                enum_values = param_def.get("enum", [])
                if enum_values and len(enum_values) > 1:
                    # Check if enum values look like internal structure
                    internal_hints = [
                        v
                        for v in enum_values
                        if isinstance(v, str)
                        and any(
                            kw in v.lower()
                            for kw in [
                                "prod",
                                "staging",
                                "internal",
                                "admin",
                                "users",
                                "transactions",
                                "api_keys",
                                "secrets",
                                "credentials",
                            ]
                        )
                    ]
                    if internal_hints:
                        leaks.append(
                            {
                                "type": "sensitive_enum",
                                "param": param_name,
                                "values": enum_values[:10],
                                "hints": internal_hints,
                                "tool": tool_name,
                            }
                        )

                # Check param descriptions
                param_desc = param_def.get("description", "")
                if param_desc:
                    for pattern, desc in SENSITIVE_DESC_PATTERNS:
                        if re.search(pattern, param_desc, re.IGNORECASE):
                            leaks.append(
                                {
                                    "type": "sensitive_param_desc",
                                    "param": param_name,
                                    "description": param_desc[:200],
                                    "detail": desc,
                                    "tool": tool_name,
                                }
                            )
                            break

            # Check tool description
            if description:
                for pattern, desc in SENSITIVE_DESC_PATTERNS:
                    if re.search(pattern, description, re.IGNORECASE):
                        leaks.append(
                            {
                                "type": "sensitive_tool_desc",
                                "description": description[:200],
                                "detail": desc,
                                "tool": tool_name,
                            }
                        )

            # Generate findings for this tool's leaks
            for leak in leaks:
                all_leaks.append(leak)
                severity, title, desc_text, evidence = self._leak_to_finding(leak)

                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title=title,
                        description=desc_text,
                        severity=severity,
                        evidence=evidence,
                        host=host,
                        discriminator=f"leak-{tool_name}-{leak['type']}-{leak.get('param', 'desc')}",
                        raw_data=leak,
                    )
                )

        if not all_leaks:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Tool schemas contain no sensitive information",
                    description="No information leakage detected in MCP tool schemas.",
                    severity="info",
                    evidence=f"Tools analyzed: {len(mcp_tools)}",
                    host=host,
                    discriminator="no-leaks",
                )
            )

        if all_leaks:
            result.outputs["mcp_schema_leaks"] = all_leaks

        return result

    def _leak_to_finding(self, leak: dict) -> tuple[str, str, str, str]:
        """Convert a leak dict to (severity, title, description, evidence)."""
        tool = leak["tool"]
        leak_type = leak["type"]

        if leak_type == "sensitive_default":
            return (
                "medium",
                f"Tool schema reveals {leak['detail']}: parameter '{leak['param']}' "
                f"default value '{leak['default']}'",
                f"The inputSchema for tool '{tool}' exposes a {leak['detail']} "
                f"as the default value for parameter '{leak['param']}'.",
                f"Tool: {tool}\nParameter: {leak['param']}\nDefault: {leak['default']}",
            )

        if leak_type == "sensitive_enum":
            return (
                "medium",
                f"Tool schema reveals internal values: parameter '{leak['param']}' "
                f"enum contains {', '.join(leak['hints'][:3])}",
                f"The inputSchema for tool '{tool}' exposes internal values "
                f"via enum options for parameter '{leak['param']}'.",
                f"Tool: {tool}\nParameter: {leak['param']}\nEnum: {', '.join(str(v) for v in leak['values'][:10])}",
            )

        if leak_type == "sensitive_param":
            return (
                "low",
                f"Tool schema reveals {leak['detail']}: parameter '{leak['param']}'",
                f"The inputSchema for tool '{tool}' has a parameter named "
                f"'{leak['param']}' which reveals {leak['detail']} in the backend.",
                f"Tool: {tool}\nParameter: {leak['param']}\nIndicates: {leak['detail']}",
            )

        if leak_type in ("sensitive_param_desc", "sensitive_tool_desc"):
            desc = leak.get("description", "")
            return (
                "low",
                f"Tool descriptions contain {leak['detail']}: '{desc[:60]}...'",
                f"The description for tool '{tool}' contains references to "
                f"{leak['detail']}, revealing internal infrastructure details.",
                f"Tool: {tool}\nDescription: {desc[:200]}",
            )

        return ("info", f"Schema leak in {tool}", str(leak), str(leak))
