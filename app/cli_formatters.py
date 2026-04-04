"""
app/cli_formatters.py - Terminal formatting for CLI output

All presentation logic extracted from cli.py.
Functions accept plain dicts (from API JSON responses) rather than domain objects.
"""

import json
from datetime import datetime

import click

SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}

SUITE_COLORS = {
    "network": "blue",
    "web": "green",
    "ai": "magenta",
    "mcp": "yellow",
    "agent": "cyan",
    "rag": "red",
    "cag": "white",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Formatters
# ═══════════════════════════════════════════════════════════════════════════════


def format_finding_terminal(finding: dict, verbose: bool = False, no_color: bool = False) -> str:
    """Format a finding dict for terminal output."""
    sev = finding.get("severity", "info").upper()
    color = SEVERITY_COLORS.get(finding.get("severity", "info"), "white")

    if no_color:
        header = f"[{sev}] {finding.get('title', '')}"
    else:
        header = click.style(f"[{sev}]", fg=color, bold=True) + f" {finding.get('title', '')}"

    lines = [header]

    if verbose:
        desc = finding.get("description", "")
        if desc:
            if len(desc) > 80:
                desc = desc[:77] + "..."
            lines.append(f"    {desc}")
        target_url = finding.get("target_url")
        if target_url:
            lines.append(f"    Target: {target_url}")
        evidence = finding.get("evidence", "")
        if evidence:
            evidence = evidence.replace("\n", " ").strip()
            if len(evidence) > 80:
                evidence = evidence[:77] + "..."
            lines.append(f"    Evidence: {evidence}")
        check_name = finding.get("check_name")
        if check_name:
            lines.append(f"    Check: {check_name}")
        refs = finding.get("references", [])
        if refs:
            lines.append(f"    Refs: {', '.join(refs[:2])}")

    return "\n".join(lines)


def findings_to_json(findings: list[dict]) -> str:
    """Convert finding dicts to JSON string."""
    return json.dumps(findings, indent=2)


def findings_to_yaml(findings: list[dict], target: str) -> str:
    """Convert finding dicts to YAML string."""
    import yaml

    data = {
        "report": {
            "tool": "chainsmith-recon",
            "version": "1.3.0",
            "target": target,
            "generated": datetime.utcnow().isoformat() + "Z",
            "findings_count": len(findings),
        },
        "findings": findings,
        "summary": {
            "by_severity": _count_by_severity(findings),
        },
    }

    return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)


def findings_to_markdown(findings: list[dict], target: str) -> str:
    """Convert finding dicts to Markdown report."""
    lines = [
        "# Chainsmith Recon Report",
        "",
        f"**Target:** {target}",
        f"**Generated:** {datetime.utcnow().isoformat()}Z",
        f"**Findings:** {len(findings)}",
        "",
        "---",
        "",
    ]

    by_severity: dict[str, list[dict]] = {}
    for f in findings:
        sev = f.get("severity", "info")
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f)

    severity_order = ["critical", "high", "medium", "low", "info"]

    for sev in severity_order:
        if sev not in by_severity:
            continue

        lines.append(f"## {sev.upper()} ({len(by_severity[sev])})")
        lines.append("")

        for f in by_severity[sev]:
            lines.append(f"### {f.get('title', '')}")
            lines.append("")
            if f.get("description"):
                lines.append(f"{f['description']}")
                lines.append("")
            if f.get("target_url"):
                lines.append(f"**Target:** `{f['target_url']}`")
            if f.get("evidence"):
                lines.append(f"**Evidence:** {f['evidence']}")
            if f.get("check_name"):
                lines.append(f"**Check:** {f['check_name']}")
            if f.get("references"):
                lines.append(f"**References:** {', '.join(f['references'])}")
            lines.append("")

    return "\n".join(lines)


def findings_to_sarif(findings: list[dict], target: str) -> str:
    """Convert finding dicts to SARIF format."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Chainsmith Recon",
                        "version": "1.3.0",
                        "informationUri": "https://github.com/infosecinnovations/chainsmith-recon",
                        "rules": _sarif_rules(findings),
                    }
                },
                "results": _sarif_results(findings, target),
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_rules(findings: list[dict]) -> list[dict]:
    """Generate SARIF rules from finding dicts."""
    seen = set()
    rules = []
    for f in findings:
        rule_id = f.get("check_name") or f.get("id", "")
        if rule_id in seen:
            continue
        seen.add(rule_id)
        rules.append(
            {
                "id": rule_id,
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description") or f.get("title", "")},
            }
        )
    return rules


def _sarif_results(findings: list[dict], target: str) -> list[dict]:
    """Generate SARIF results from finding dicts."""
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.get("check_name") or f.get("id", ""),
                "level": severity_map.get(f.get("severity", "info"), "note"),
                "message": {"text": f.get("title", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("target_url") or target},
                        }
                    }
                ],
            }
        )
    return results


def _count_by_severity(findings: list[dict]) -> dict:
    """Count findings by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# ═══════════════════════════════════════════════════════════════════════════════
# Check / Plan Formatters
# ═══════════════════════════════════════════════════════════════════════════════


def print_checks_list(
    checks: list[dict], suites: list[str], verbose: bool = False, deps: bool = False
):
    """Print checks grouped by suite."""
    click.echo(click.style("\nChainsmith Checks", fg="cyan", bold=True))
    click.echo(f"Total: {len(checks)} checks in {len(suites)} suites\n")

    for suite_name in suites:
        suite_checks = [c for c in checks if c.get("suite") == suite_name]
        if not suite_checks:
            continue

        color = SUITE_COLORS.get(suite_name, "white")

        click.echo(
            click.style(f"[{suite_name.upper()}]", fg=color, bold=True)
            + f" ({len(suite_checks)} checks)"
        )

        for check in suite_checks:
            line = f"  {check['name']}"

            desc = check.get("description", "")
            if desc and not verbose:
                short_desc = desc.split(".")[0][:50]
                line += click.style(f" - {short_desc}", fg="white")

            click.echo(line)

            if verbose:
                if desc:
                    click.echo(f"      {desc}")
                reason = check.get("reason", "")
                if reason:
                    click.echo(click.style(f"      Why: {reason}", fg="cyan"))

            if deps or verbose:
                conditions = check.get("conditions", [])
                produces = check.get("produces", [])

                if conditions:
                    cond_str = ", ".join(str(c) for c in conditions)
                    click.echo(click.style(f"      Requires: {cond_str}", fg="yellow"))
                if produces:
                    click.echo(click.style(f"      Produces: {', '.join(produces)}", fg="green"))

        click.echo()


def print_execution_plan(checks: list[dict]):
    """Print scan execution plan from API check list."""
    click.echo(click.style("\n=== Execution Plan ===\n", fg="cyan", bold=True))

    suites_seen = []
    for c in checks:
        s = c.get("suite", "other")
        if s not in suites_seen:
            suites_seen.append(s)

    click.echo(f"Suite order: {' → '.join(suites_seen)}")
    click.echo(f"Total checks: {len(checks)}")
    click.echo()

    for suite_name in suites_seen:
        suite_checks = [c for c in checks if c.get("suite") == suite_name]
        color = SUITE_COLORS.get(suite_name, "white")

        click.echo(click.style(f"[{suite_name.upper()}]", fg=color, bold=True))

        for check in suite_checks:
            line = f"  • {check['name']}"
            conditions = check.get("conditions", [])
            produces = check.get("produces", [])

            if conditions:
                line += click.style(f" ← {conditions}", fg="yellow")
            if produces:
                line += click.style(f" → {produces}", fg="green")

            click.echo(line)

        click.echo()


def print_preferences_dict(d: dict, indent: int = 2):
    """Print a preferences dict with color formatting."""
    prefix = " " * indent
    for section, values in d.items():
        click.echo(f"{prefix}{click.style(section, fg='cyan')}:")
        if isinstance(values, dict):
            for key, value in values.items():
                if isinstance(value, bool):
                    val_str = click.style(str(value).lower(), fg="green" if value else "red")
                elif value is None:
                    val_str = click.style("null", fg="yellow")
                else:
                    val_str = str(value)
                click.echo(f"{prefix}  {key}: {val_str}")
        else:
            click.echo(f"{prefix}  {values}")


def format_chain_summary(chains_data: dict, no_color: bool = False) -> str:
    """
    Format chain analysis summary for CLI output, including LLM error context.

    Example outputs:
        "5 chains (3 rule, 2 LLM, 0 both)"
        "3 chains (3 rule, 0 LLM, 0 both) [LLM: content filter rejection]"
        "0 chains [LLM failed: rate limit after 3 attempts]"
    """
    chains = chains_data.get("chains", [])
    rule_count = chains_data.get("rule_based_count", 0)
    llm_count = chains_data.get("llm_count", 0)
    both_count = len([c for c in chains if c.get("source") == "both"])

    base = f"{len(chains)} chains ({rule_count} rule, {llm_count} LLM, {both_count} both)"

    llm_analysis = chains_data.get("llm_analysis")
    if not llm_analysis or llm_analysis.get("status") in ("success", "not_configured", None):
        return base

    error_type = (llm_analysis.get("error_type", "unknown") or "unknown").replace("_", " ")
    attempts = llm_analysis.get("attempts", 1)

    if llm_analysis.get("auto_mitigated"):
        suffix = f"[LLM: {error_type} — retried with sanitized prompt, succeeded]"
    elif len(chains) > 0:
        suffix = f"[LLM: {error_type}]"
    else:
        suffix = f"[LLM failed: {error_type} after {attempts} attempt(s)]"

    return f"{base} {suffix}"


def output_findings(
    findings: list[dict],
    target: str,
    fmt: str,
    output: str | None,
    verbose: bool,
    quiet: bool,
    no_color: bool = False,
):
    """Output findings in the requested format, optionally to file."""
    if fmt == "text":
        if not findings:
            if not quiet:
                click.echo(_style("No findings.", no_color, fg="yellow"))
            return

        for f in findings:
            click.echo(format_finding_terminal(f, verbose=verbose, no_color=no_color))
            click.echo()

    elif fmt == "json":
        result = findings_to_json(findings)
        _write_or_echo(result, output, quiet)

    elif fmt == "yaml":
        result = findings_to_yaml(findings, target)
        _write_or_echo(result, output, quiet)

    elif fmt == "md":
        result = findings_to_markdown(findings, target)
        _write_or_echo(result, output, quiet)

    elif fmt == "sarif":
        result = findings_to_sarif(findings, target)
        _write_or_echo(result, output, quiet)


def _write_or_echo(result: str, output: str | None, quiet: bool):
    """Write result to file or echo to stdout."""
    from pathlib import Path

    if output:
        Path(output).write_text(result)
        if not quiet:
            click.echo(f"Written to {output}")
    else:
        click.echo(result)


def _style(text: str, no_color: bool, **kwargs) -> str:
    if no_color:
        return text
    return click.style(text, **kwargs)
