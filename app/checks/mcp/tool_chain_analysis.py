"""
app/checks/mcp/tool_chain_analysis.py - Tool Chain Category Analysis

Analyzes discovered MCP tools for dangerous capability combinations.
Instead of mapping all permutations, checks if the tool set can form
known dangerous chain categories (data exfil, RCE + persistence, etc.).

Operates entirely on already-enumerated tool data — no HTTP requests.

References:
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
  MITRE ATLAS - AML.T0051 LLM Plugin Compromise
"""

import re
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.observations import build_observation

# ── Capability tags ─────────────────────────────────────────────────
# Maps tool name/description patterns to capability tags.

CAPABILITY_PATTERNS: dict[str, list[str]] = {
    "file_read": [
        r"read(_|\s)?file",
        r"file(_|\s)?read",
        r"fs(_|\s)?read",
        r"cat\b",
        r"get(_|\s)?file",
        r"load(_|\s)?file",
        r"open(_|\s)?file",
        r"view(_|\s)?file",
    ],
    "file_write": [
        r"write(_|\s)?file",
        r"file(_|\s)?write",
        r"create(_|\s)?file",
        r"save(_|\s)?file",
        r"put(_|\s)?file",
        r"fs(_|\s)?write",
    ],
    "command_exec": [
        r"exec(ute)?(_|\s)?command",
        r"run(_|\s)?shell",
        r"shell(_|\s)?exec",
        r"spawn(_|\s)?process",
        r"eval(uate)?(_|\s)?code",
        r"run(_|\s)?code",
        r"system(_|\s)?command",
        r"bash",
        r"powershell",
        r"cmd\b",
        r"terminal",
    ],
    "network_request": [
        r"http(_|\s)?(fetch|request|get|post)",
        r"fetch(_|\s)?url",
        r"curl",
        r"wget",
        r"request\b",
        r"browse",
    ],
    "data_exfil": [
        r"send(_|\s)?(email|mail|message|notification)",
        r"upload",
        r"post(_|\s)?data",
        r"webhook",
        r"slack",
        r"discord",
        r"telegram",
    ],
    "database_access": [
        r"(sql|database|db)(_|\s)?(query|execute|read|write)",
        r"select\b.*from",
        r"insert\b.*into",
    ],
    "credential_access": [
        r"(get|read)(_|\s)?secret",
        r"env(ironment)?(_|\s)?(get|read)",
        r"config(_|\s)?(get|read)",
        r"credential",
        r"api(_|\s)?key",
        r"password",
        r"vault",
    ],
    "remote_access": [
        r"ssh",
        r"ftp",
        r"rdp",
        r"vnc",
        r"telnet",
        r"remote(_|\s)?(exec|connect|access)",
    ],
    "scheduling": [
        r"schedule",
        r"cron",
        r"timer",
        r"at\b.*job",
        r"task(_|\s)?schedule",
        r"periodic",
    ],
    "search_recon": [
        r"list(_|\s)?file",
        r"search",
        r"find\b",
        r"directory(_|\s)?list",
        r"glob",
        r"ls\b",
        r"dir\b",
    ],
    "browser": [
        r"browser",
        r"screenshot",
        r"navigate",
        r"scrape",
        r"headless",
        r"puppeteer",
        r"playwright",
        r"selenium",
    ],
}

# ── Dangerous chain categories ──────────────────────────────────────
# Each category: (name, severity, required_caps, description)

DANGEROUS_CHAINS: list[tuple[str, str, list[list[str]], str]] = [
    (
        "Data Read + Exfiltration",
        "critical",
        [
            ["file_read", "database_access", "search_recon"],  # source (any)
            ["data_exfil", "network_request"],
        ],  # sink (any)
        "Data can be read via {source_tools} and exfiltrated via {sink_tools}",
    ),
    (
        "Credential Access + Network",
        "critical",
        [
            ["credential_access"],  # source (any)
            ["network_request", "remote_access", "data_exfil"],
        ],  # sink (any)
        "Credentials can be extracted via {source_tools} and used/exfiltrated via {sink_tools}",
    ),
    (
        "File Access + Code Execution",
        "critical",
        [
            ["file_read", "file_write"],  # file (any)
            ["command_exec"],
        ],  # exec (any)
        "Files accessible via {source_tools}, code execution via {sink_tools} enables arbitrary payload deployment",
    ),
    (
        "Write + Persistence",
        "critical",
        [
            ["file_write"],  # write (any)
            ["command_exec", "scheduling"],
        ],  # persist (any)
        "File write via {source_tools} combined with {sink_tools} enables persistent backdoor installation",
    ),
    (
        "Recon + Lateral Movement",
        "high",
        [
            ["search_recon", "browser"],  # recon (any)
            ["remote_access", "network_request", "data_exfil"],
        ],  # move (any)
        "Reconnaissance via {source_tools} enables targeted lateral movement via {sink_tools}",
    ),
    (
        "Database + Exfiltration",
        "critical",
        [
            ["database_access"],  # db (any)
            ["data_exfil", "network_request"],
        ],  # exfil (any)
        "Database access via {source_tools} with exfiltration via {sink_tools}",
    ),
]


class ToolChainAnalysisCheck(BaseCheck):
    """
    Analyze discovered MCP tools for dangerous capability chain categories.

    Maps each tool to capability tags, then checks if the full tool set
    satisfies any dangerous chain category. This is a set intersection
    problem, not a permutation analysis.
    """

    name = "mcp_tool_chain_analysis"
    description = "Analyze MCP tools for dangerous capability combinations"

    conditions = [CheckCondition("mcp_tools", "truthy")]
    produces = ["mcp_dangerous_chains"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 30.0

    reason = "Individual tools may be low risk, but combinations can enable full attack chains (read + exfil = data breach)"
    references = [
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = ["capability mapping", "attack chain analysis", "risk assessment"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])

        if not mcp_tools:
            return result

        # Step 1: Tag each tool with capabilities
        tool_capabilities: dict[str, list[str]] = {}
        capability_to_tools: dict[str, list[str]] = {}

        for tool in mcp_tools:
            name = tool.get("name", "unknown")
            description = tool.get("description", "")
            caps = self._tag_capabilities(name, description)
            tool_capabilities[name] = caps

            for cap in caps:
                capability_to_tools.setdefault(cap, []).append(name)

        # Step 2: Check each dangerous chain category
        all_caps = set()
        for caps in tool_capabilities.values():
            all_caps.update(caps)

        detected_chains = []
        host = mcp_tools[0].get("service_host", "unknown") if mcp_tools else "unknown"

        for chain_name, severity, required_groups, desc_template in DANGEROUS_CHAINS:
            # Each group is a list of alternative capabilities (OR).
            # All groups must have at least one match (AND across groups).
            group_matches = []
            all_groups_satisfied = True

            for group in required_groups:
                matched_caps = [c for c in group if c in all_caps]
                if not matched_caps:
                    all_groups_satisfied = False
                    break
                # Collect the tools that provide these capabilities
                matched_tools = []
                for cap in matched_caps:
                    matched_tools.extend(capability_to_tools.get(cap, []))
                group_matches.append(list(set(matched_tools)))

            if all_groups_satisfied and len(group_matches) >= 2:
                source_tools = ", ".join(group_matches[0][:3])
                sink_tools = ", ".join(group_matches[1][:3])
                description = desc_template.format(source_tools=source_tools, sink_tools=sink_tools)

                chain_info = {
                    "chain_name": chain_name,
                    "severity": severity,
                    "source_tools": group_matches[0],
                    "sink_tools": group_matches[1],
                }
                detected_chains.append(chain_info)

                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Dangerous tool chain: {chain_name}",
                        description=description,
                        severity=severity,
                        evidence=self._build_chain_evidence(chain_info, tool_capabilities),
                        host=host,
                        discriminator=f"chain-{chain_name.lower().replace(' ', '-').replace('+', '')}",
                        raw_data=chain_info,
                    )
                )

        if not detected_chains:
            # Check for partial chains
            partial = self._check_partial_chains(all_caps, capability_to_tools, host)
            if partial:
                for observation in partial:
                    result.observations.append(observation)
            else:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="No dangerous tool chain categories detected",
                        description="The discovered tool set does not form any known dangerous capability combinations.",
                        severity="info",
                        evidence=f"Tools analyzed: {len(mcp_tools)}\nCapabilities: {', '.join(sorted(all_caps)) or 'none'}",
                        host=host,
                        discriminator="no-chains",
                    )
                )

        if detected_chains:
            result.outputs["mcp_dangerous_chains"] = detected_chains

        return result

    def _tag_capabilities(self, name: str, description: str) -> list[str]:
        """Map a tool to capability tags based on name and description patterns."""
        combined = f"{name} {description}".lower()
        caps = []

        for capability, patterns in CAPABILITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    caps.append(capability)
                    break

        return caps

    def _check_partial_chains(self, all_caps: set, capability_to_tools: dict, host: str) -> list:
        """Check for partial dangerous chains (source present but no sink, or vice versa)."""
        observations = []

        # Check for dangerous source capabilities without exfil vector
        source_caps = {"file_read", "database_access", "credential_access"}
        has_source = source_caps & all_caps
        sink_caps = {"data_exfil", "network_request", "remote_access"}
        has_sink = sink_caps & all_caps

        if has_source and not has_sink:
            source_tools = []
            for cap in has_source:
                source_tools.extend(capability_to_tools.get(cap, []))
            source_tools = list(set(source_tools))

            observations.append(
                build_observation(
                    check_name=self.name,
                    title="Partial dangerous chain: data access tools present but no exfiltration vector",
                    description=(
                        f"Tools with data access capabilities ({', '.join(source_tools[:5])}) "
                        "are present but no exfiltration or network request tools were found. "
                        "The chain is incomplete but could be enabled by additional tool registration."
                    ),
                    severity="medium",
                    evidence=f"Source capabilities: {', '.join(has_source)}\nTools: {', '.join(source_tools[:5])}",
                    host=host,
                    discriminator="partial-chain-source",
                    raw_data={"source_caps": list(has_source), "tools": source_tools},
                )
            )

        return observations

    def _build_chain_evidence(self, chain_info: dict, tool_capabilities: dict) -> str:
        """Build evidence string for a detected chain."""
        lines = [
            f"Chain: {chain_info['chain_name']}",
            f"Source tools: {', '.join(chain_info['source_tools'][:5])}",
            f"Sink tools: {', '.join(chain_info['sink_tools'][:5])}",
        ]

        # Show capability tags for involved tools
        all_tools = set(chain_info["source_tools"] + chain_info["sink_tools"])
        for tool_name in list(all_tools)[:5]:
            caps = tool_capabilities.get(tool_name, [])
            if caps:
                lines.append(f"  {tool_name}: [{', '.join(caps)}]")

        return "\n".join(lines)
