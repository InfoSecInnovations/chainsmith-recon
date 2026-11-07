"""
app/checks/mcp/schema_leakage.py - Tool Schema Information Leakage

Analyzes MCP tool inputSchema definitions for sensitive information:
- Parameter names revealing internal structure
- Default values exposing configuration
- Enum values listing internal options
- Descriptions with internal details

Operates entirely on already-enumerated data — no HTTP requests.

**Probe/grade.** There is no request to record, so `run()`
records the one thing its verdicts are derived from: the `mcp_tools` it was
handed, as a `local` exchange (the `network_geoip` precedent, §0.12). A grader
reads evidence and nothing else, and a re-grade of a stored corpus has no scan
context to fetch `mcp_tools` from — so the analysed schemas go on the record.
Only the fields the analysis reads are kept (`_ANALYSED_FIELDS`). `_tools_from()`
reads them back and `_leaks_from()` is the one analysis both halves call: the
probe for its `mcp_schema_leaks` output, `grade()` for one verdict per leak.

**Fixed**: every leak discriminator embeds a tool and
parameter name, an unbounded set, so the contract declares no `observations:`
map. Confidence is where the split pays: a parameter *named* `token` or `region`
is the ordinary shape of an API, not a leak, while a default *value* of
`prod-db.internal:5432` is the disclosure itself.

References:
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
"""

import json
import re
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict

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

# The tool fields the analysis reads — all that goes on the record.
_ANALYSED_FIELDS = ("name", "description", "input_schema", "service_host")

# Defaults that name the server's own host rather than internal topology.
_SELF_ADDRESSES = ("127.", "0.0.0.0", "localhost")


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

    reason = "Tool schemas may reveal internal infrastructure details useful for targeted attacks"
    references = [
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
        "CWE-200 Exposure of Sensitive Information",
    ]
    techniques = ["schema analysis", "information disclosure", "reconnaissance"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])

        if not mcp_tools:
            return result

        host = mcp_tools[0].get("service_host", "unknown")
        analysed = [{k: tool[k] for k in _ANALYSED_FIELDS if k in tool} for tool in mcp_tools]

        exchange = capture.record_exchange(
            "local",
            host,
            request_body="mcp_schema_leakage mcp_tools",
            request_headers={"source": "mcp_tools"},
            response_body=json.dumps(analysed, default=str),
        )
        candidate = self.create_candidate(host=host)
        candidate.attach(exchange)
        result.candidates.append(candidate)

        tools = self._tools_from(exchange)
        all_leaks = self._leaks_from(tools) if tools is not None else []
        if all_leaks:
            result.outputs["mcp_schema_leaks"] = all_leaks

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        for exchange in evidence:
            tools = self._tools_from(exchange)
            if tools is None:
                continue

            leaks = self._leaks_from(tools)
            if not leaks:
                return [
                    Verdict(
                        severity="info",
                        confidence=0.6,
                        discriminator="no-leaks",
                        title="Tool schemas contain no sensitive information",
                        description="No information leakage detected in MCP tool schemas.",
                        evidence=f"Tools analyzed: {len(tools)}",
                        reasoning=(
                            "no parameter name, default, enum or description matched; the "
                            "absence is bounded by fixed name tables and patterns, so a leak "
                            "phrased any other way reads as clean"
                        ),
                        tier=ctx.tier,
                        evidence_ids=[exchange.id],
                    )
                ]

            verdicts: list[Verdict] = []
            for leak in leaks:
                severity, title, desc_text, evidence_text = self._leak_to_observation(leak)
                confidence, why = self._confidence(leak)
                verdicts.append(
                    Verdict(
                        severity=severity,
                        confidence=confidence,
                        discriminator=f"leak-{leak['tool']}-{leak['type']}-{leak.get('param', 'desc')}",
                        title=title,
                        description=desc_text,
                        evidence=evidence_text,
                        reasoning=why,
                        signals={"leak_type": leak["type"], "detail": leak.get("detail")},
                        raw_data=leak,
                        tier=ctx.tier,
                        evidence_ids=[exchange.id],
                    )
                )
            return verdicts
        return []

    @staticmethod
    def _confidence(leak: dict) -> tuple[float, str]:
        leak_type = leak["type"]
        if leak_type == "sensitive_default":
            default = str(leak.get("default", ""))
            if default.startswith(_SELF_ADDRESSES):
                return 0.35, (
                    f"the default '{default}' matched the {leak['detail']} pattern, but a "
                    "loopback or unspecified address describes the server's own host, not "
                    "internal topology"
                )
            return 0.7, (
                f"a concrete value the server published as a default matched the "
                f"{leak['detail']} pattern, so the disclosure is in the bytes; a placeholder "
                "or example default matches the same pattern"
            )
        if leak_type == "sensitive_enum":
            return 0.5, (
                f"enum options contain internal-sounding keywords ({', '.join(leak['hints'][:3])}); "
                "an enum is an interface the tool deliberately offers, so naming a table it "
                "exposes discloses little beyond the tool's own purpose"
            )
        if leak_type == "sensitive_param":
            return 0.4, (
                f"a parameter is named '{leak['param']}'; that is the ordinary shape of an API "
                "and names a concept, not a value"
            )
        if leak.get("detail") == "privileged access hint":
            return 0.4, (
                "a description contains the bare word admin/root/superuser, which reads the "
                "same in 'requires admin rights' as in a disclosure"
            )
        return 0.6, (
            f"a description matched the {leak.get('detail')} phrase pattern; free text "
            "paraphrases, so a generic mention and a real infrastructure detail look alike"
        )

    # ── The analysis both halves share ───────────────────────────────

    @staticmethod
    def _tools_from(exchange: Exchange) -> list[dict] | None:
        """The analysed tools, read back off the recorded `local` exchange."""
        if exchange.protocol != "local" or not exchange.response_body:
            return None
        try:
            tools = json.loads(exchange.response_body)
        except json.JSONDecodeError:
            return None
        return tools if isinstance(tools, list) else None

    @staticmethod
    def _leaks_from(mcp_tools: list[dict]) -> list[dict]:
        """Every leak across the tool set, in the order the original loop found them."""
        all_leaks = []

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

            all_leaks.extend(leaks)

        return all_leaks

    def _leak_to_observation(self, leak: dict) -> tuple[str, str, str, str]:
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
