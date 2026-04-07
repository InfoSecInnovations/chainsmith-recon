"""
app/reports.py - Report generation from historical scan data.

Generates Technical, Delta, Executive, Compliance, and Trend reports
in Markdown, JSON, HTML, and PDF formats.
All data is pulled from the database via repositories.
"""

import html as html_lib
import json
import logging
from datetime import UTC, datetime

from app.db.repositories import (
    SEVERITY_WEIGHTS,
    ChainRepository,
    CheckLogRepository,
    ComparisonRepository,
    EngagementRepository,
    FindingOverrideRepository,
    FindingRepository,
    ScanRepository,
    TrendRepository,
)

logger = logging.getLogger(__name__)

_scan_repo = ScanRepository()
_finding_repo = FindingRepository()
_chain_repo = ChainRepository()
_check_log_repo = CheckLogRepository()
_comparison_repo = ComparisonRepository()
_override_repo = FindingOverrideRepository()
_engagement_repo = EngagementRepository()
_trend_repo = TrendRepository()

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# ─── SARIF Constants ────────────────────────────────────────────────────────

_SARIF_SEV_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_SEV_RANK = {
    "critical": 1.0,
    "high": 3.0,
    "medium": 5.0,
    "low": 7.0,
    "info": 9.0,
}


def _count_by_severity(findings: list[dict]) -> dict:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _risk_score(severity_counts: dict) -> int:
    return sum(SEVERITY_WEIGHTS.get(s, 0) * c for s, c in severity_counts.items())


def _check_coverage(log_entries: list[dict]) -> dict:
    completed = sum(1 for e in log_entries if e.get("event") == "completed")
    failed = sum(1 for e in log_entries if e.get("event") == "failed")
    skipped = sum(1 for e in log_entries if e.get("event") == "skipped")
    started = sum(1 for e in log_entries if e.get("event") == "started")
    return {
        "total": started,
        "completed": completed,
        "failed": failed,
        "skipped": skipped,
    }


# ─── Technical Report ────────────────────────────────────────────────────────


async def generate_technical_report(scan_id: str, fmt: str = "md") -> dict:
    """
    Generate a technical report for a historical scan.

    Returns {"content": str, "filename": str, "format": str}.
    Raises ValueError if scan not found.
    """
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Scan '{scan_id}' not found")

    findings = await _finding_repo.get_findings(scan_id)
    chains = await _chain_repo.get_chains(scan_id)
    log_entries = await _check_log_repo.get_log(scan_id)
    overrides = await _override_repo.list_overrides()
    override_map = {o["fingerprint"]: o for o in overrides.get("overrides", [])}

    # Annotate findings with override info
    for f in findings:
        fp = f.get("fingerprint")
        if fp and fp in override_map:
            f["override"] = override_map[fp]

    severity_counts = _count_by_severity(findings)
    risk = _risk_score(severity_counts)
    coverage = _check_coverage(log_entries)

    if fmt == "json":
        content = _technical_json(scan, findings, chains, severity_counts, risk, coverage)
    elif fmt == "sarif":
        content = _technical_sarif(scan, findings, chains, severity_counts, risk, coverage)
    elif fmt in ("html", "pdf"):
        content = _technical_html(scan, findings, chains, severity_counts, risk, coverage)
        if fmt == "pdf":
            content = _html_to_pdf(content)
    else:
        content = _technical_markdown(scan, findings, chains, severity_counts, risk, coverage)

    target = scan.get("target_domain", "unknown")
    ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif.json"}.get(fmt, "md")
    filename = f"technical-{target}-{scan_id[:8]}.{ext}"

    return {"content": content, "filename": filename, "format": fmt}


def _technical_markdown(scan, findings, chains, severity_counts, risk, coverage) -> str:
    target = scan.get("target_domain", "unknown")
    date = scan.get("started_at", "N/A")
    duration_ms = scan.get("duration_ms")
    duration = f"{duration_ms}ms" if duration_ms else "N/A"

    total = sum(severity_counts.values())
    sev_summary = ", ".join(f"{c} {s}" for s, c in severity_counts.items() if c > 0)

    lines = [
        "# Technical Security Report",
        "",
        f"**Target:** {target}",
        f"**Scan ID:** {scan['id']}",
        f"**Date:** {date}",
        f"**Duration:** {duration}",
        f"**Findings:** {total} ({sev_summary})" if sev_summary else f"**Findings:** {total}",
        f"**Risk Score:** {risk}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev.capitalize()} | {severity_counts[sev]} |")

    lines.extend(["", f"**Risk Score:** {risk}", ""])

    # Findings by severity
    lines.append("## Findings")
    lines.append("")

    by_severity: dict[str, list[dict]] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, []).append(f)

    for sev in SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue

        lines.append(f"### {sev.upper()} ({len(group)})")
        lines.append("")

        for f in group:
            override_note = ""
            if f.get("override"):
                ov = f["override"]
                override_note = f" *[{ov['status'].upper()}]*"

            severity_note = ""
            original_sev = f.get("original_severity")
            if not original_sev:
                raw = f.get("raw_data") or {}
                original_sev = raw.get("original_severity")
            if original_sev:
                reason = f.get("severity_override_reason") or ""
                reason_text = f" — {reason}" if reason else ""
                severity_note = f" *(was {original_sev.upper()}{reason_text})*"

            lines.append(f"#### {f.get('title', 'Untitled')}{override_note}{severity_note}")
            lines.append("")
            if f.get("description"):
                lines.append(f"{f['description']}")
                lines.append("")
            if f.get("check_name"):
                lines.append(f"- **Check:** {f['check_name']}")
            if f.get("host"):
                lines.append(f"- **Host:** {f['host']}")
            if f.get("target_url"):
                lines.append(f"- **URL:** `{f['target_url']}`")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** {f['evidence']}")
            if f.get("references"):
                refs = f["references"]
                if isinstance(refs, list):
                    lines.append(f"- **References:** {', '.join(refs)}")
            if f.get("fingerprint"):
                lines.append(f"- **Fingerprint:** `{f['fingerprint']}`")
            lines.append("")

    # Attack chains
    if chains:
        lines.append(f"## Attack Chains ({len(chains)})")
        lines.append("")
        for c in chains:
            lines.append(f"### {c.get('title', 'Untitled Chain')}")
            lines.append("")
            lines.append(f"- **Severity:** {c.get('severity', 'N/A')}")
            lines.append(f"- **Source:** {c.get('source', 'N/A')}")
            if c.get("description"):
                lines.append(f"- **Description:** {c['description']}")
            if c.get("finding_ids"):
                ids = c["finding_ids"]
                if isinstance(ids, list):
                    lines.append(f"- **Findings:** {', '.join(str(fid) for fid in ids)}")
            lines.append("")

    # Check coverage
    lines.append("## Check Coverage")
    lines.append("")
    lines.append(
        f"Completed: {coverage['completed']}/{coverage['total']} | "
        f"Failed: {coverage['failed']} | Skipped: {coverage['skipped']}"
    )
    lines.append("")

    return "\n".join(lines)


def _technical_json(scan, findings, chains, severity_counts, risk, coverage) -> str:
    report = {
        "report_type": "technical",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan": scan,
        "summary": {
            "by_severity": severity_counts,
            "risk_score": risk,
            "total_findings": sum(severity_counts.values()),
        },
        "findings": findings,
        "chains": chains,
        "check_coverage": coverage,
    }
    return json.dumps(report, indent=2)


# ─── Delta Report ────────────────────────────────────────────────────────────


async def generate_delta_report(scan_a_id: str, scan_b_id: str, fmt: str = "md") -> dict:
    """
    Generate a delta (comparison) report between two scans.

    Returns {"content": str, "filename": str, "format": str}.
    Raises ValueError if either scan not found.
    """
    scan_a = await _scan_repo.get_scan(scan_a_id)
    if scan_a is None:
        raise ValueError(f"Scan '{scan_a_id}' not found")
    scan_b = await _scan_repo.get_scan(scan_b_id)
    if scan_b is None:
        raise ValueError(f"Scan '{scan_b_id}' not found")

    comparison = await _comparison_repo.compare_scans(scan_a_id, scan_b_id)

    # Get full findings for risk score calculation
    findings_a = await _finding_repo.get_findings(scan_a_id)
    findings_b = await _finding_repo.get_findings(scan_b_id)

    sev_a = _count_by_severity(findings_a)
    sev_b = _count_by_severity(findings_b)
    risk_a = _risk_score(sev_a)
    risk_b = _risk_score(sev_b)

    if fmt == "json":
        content = _delta_json(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b)
    elif fmt == "sarif":
        content = _delta_sarif(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b)
    elif fmt in ("html", "pdf"):
        content = _delta_html(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b)
        if fmt == "pdf":
            content = _html_to_pdf(content)
    else:
        content = _delta_markdown(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b)

    target = scan_b.get("target_domain", "unknown")
    ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif.json"}.get(fmt, "md")
    filename = f"delta-{target}-{scan_a_id[:8]}-vs-{scan_b_id[:8]}.{ext}"

    return {"content": content, "filename": filename, "format": fmt}


def _delta_markdown(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b) -> str:
    target = scan_b.get("target_domain", scan_a.get("target_domain", "unknown"))
    new_count = comparison.get("new_count", 0)
    resolved_count = comparison.get("resolved_count", 0)
    recurring_count = comparison.get("recurring_count", 0)
    net_change = new_count - resolved_count

    lines = [
        "# Delta Report",
        "",
        f"**Scan A:** {scan_a['id']} ({scan_a.get('started_at', 'N/A')})",
        f"**Scan B:** {scan_b['id']} ({scan_b.get('started_at', 'N/A')})",
        f"**Target:** {target}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| New | +{new_count} |",
        f"| Resolved | -{resolved_count} |",
        f"| Recurring | {recurring_count} |",
        f"| Net Change | {'+' if net_change >= 0 else ''}{net_change} |",
        "",
        f"**Risk Score:** {risk_a} -> {risk_b} "
        f"({'increased' if risk_b > risk_a else 'decreased' if risk_b < risk_a else 'unchanged'})",
        "",
        "## Severity Comparison",
        "",
        "| Severity | Scan A | Scan B | Change |",
        "|----------|--------|--------|--------|",
    ]

    for sev in SEVERITY_ORDER:
        a = sev_a.get(sev, 0)
        b = sev_b.get(sev, 0)
        diff = b - a
        diff_str = f"+{diff}" if diff > 0 else str(diff)
        lines.append(f"| {sev.capitalize()} | {a} | {b} | {diff_str} |")

    lines.append("")

    # New findings
    new_findings = comparison.get("new_findings", [])
    if new_findings:
        lines.append(f"## New Findings ({len(new_findings)})")
        lines.append("")
        for f in new_findings:
            sev = f.get("severity", "info").upper()
            lines.append(f"- **[{sev}]** {f.get('title', 'Untitled')}")
        lines.append("")

    # Resolved findings
    resolved_findings = comparison.get("resolved_findings", [])
    if resolved_findings:
        lines.append(f"## Resolved Findings ({len(resolved_findings)})")
        lines.append("")
        for f in resolved_findings:
            sev = f.get("severity", "info").upper()
            lines.append(f"- ~~[{sev}] {f.get('title', 'Untitled')}~~")
        lines.append("")

    if not new_findings and not resolved_findings:
        lines.append("*No changes between scans.*")
        lines.append("")

    return "\n".join(lines)


def _delta_json(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b) -> str:
    report = {
        "report_type": "delta",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_a": scan_a,
        "scan_b": scan_b,
        "summary": {
            "new_count": comparison.get("new_count", 0),
            "resolved_count": comparison.get("resolved_count", 0),
            "recurring_count": comparison.get("recurring_count", 0),
            "net_change": comparison.get("new_count", 0) - comparison.get("resolved_count", 0),
            "risk_a": risk_a,
            "risk_b": risk_b,
            "severity_a": sev_a,
            "severity_b": sev_b,
        },
        "new_findings": comparison.get("new_findings", []),
        "resolved_findings": comparison.get("resolved_findings", []),
    }
    return json.dumps(report, indent=2)


# ─── HTML Template Infrastructure ───────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --border: #2d3040;
    --text: #e1e4ed; --muted: #8b90a0; --accent: #6c8aff;
    --critical: #ff4d6a; --high: #ff8c42; --medium: #ffd166;
    --low: #6ec6ff; --info: #8b90a0;
    --green: #4ecdc4; --red: #ff4d6a;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 960px; margin: 0 auto; }}
  h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ color: var(--accent); font-size: 1.3rem; margin-top: 2rem; margin-bottom: 0.75rem;
        border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }}
  h3 {{ font-size: 1.1rem; margin-top: 1.2rem; margin-bottom: 0.5rem; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .meta span {{ margin-right: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; font-weight: 600; }}
  .badge-critical {{ background: var(--critical); color: #fff; }}
  .badge-high {{ background: var(--high); color: #000; }}
  .badge-medium {{ background: var(--medium); color: #000; }}
  .badge-low {{ background: var(--low); color: #000; }}
  .badge-info {{ background: var(--info); color: #fff; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin: 0.75rem 0; }}
  .card-title {{ font-weight: 600; margin-bottom: 0.3rem; }}
  .card-detail {{ color: var(--muted); font-size: 0.9rem; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin: 1rem 0; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; text-align: center; }}
  .stat-value {{ font-size: 1.8rem; font-weight: 700; }}
  .stat-label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }}
  .trend-up {{ color: var(--red); }} .trend-down {{ color: var(--green); }} .trend-flat {{ color: var(--muted); }}
  .override {{ opacity: 0.6; text-decoration: line-through; }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; }}
  code {{ background: var(--surface); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.9rem; }}
  .bar {{ display: inline-block; height: 18px; border-radius: 2px; }}
</style>
</head>
<body>
{body}
<div class="footer">Generated by Chainsmith Recon &middot; {timestamp}</div>
</body>
</html>"""


def _esc(text) -> str:
    """HTML-escape a value."""
    return html_lib.escape(str(text)) if text else ""


def _severity_badge(severity: str) -> str:
    s = (severity or "info").lower()
    return f'<span class="badge badge-{s}">{s.upper()}</span>'


def _wrap_html(title: str, body: str) -> str:
    return _HTML_TEMPLATE.format(
        title=_esc(title),
        body=body,
        timestamp=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )


_PRINT_CSS = """
<style>
  @page {
    size: A4;
    margin: 20mm 15mm 25mm 15mm;
  }
  body {
    background: #fff; color: #1a1a2e; font-size: 10pt;
    padding: 0; max-width: none;
    font-family: Helvetica, Arial, sans-serif;
  }
  h1 {
    color: #2563eb; font-size: 18pt; margin-bottom: 4pt;
  }
  h2 {
    color: #2563eb; font-size: 13pt;
    border-bottom: 1px solid #d1d5db;
    margin-top: 14pt;
  }
  .card { background: #f5f5f7; border: 1px solid #d1d5db; padding: 8pt; margin: 6pt 0; }
  .card-title { font-weight: bold; margin-bottom: 3pt; }
  .card-detail { color: #6b7280; font-size: 9pt; }
  .meta { color: #6b7280; font-size: 9pt; margin-bottom: 10pt; }
  .meta span { margin-right: 12pt; }
  table { width: 100%; border-collapse: collapse; margin: 8pt 0; }
  th, td { padding: 4pt 6pt; text-align: left; border-bottom: 1px solid #d1d5db; }
  th { color: #6b7280; font-size: 8pt; text-transform: uppercase; }
  .badge { display: inline; padding: 2pt 5pt; font-size: 8pt; font-weight: bold; }
  .badge-critical { background: #dc2626; color: #fff; }
  .badge-high { background: #ea580c; color: #fff; }
  .badge-medium { background: #d97706; color: #000; }
  .badge-low { background: #2563eb; color: #fff; }
  .badge-info { background: #6b7280; color: #fff; }
  .stat-grid { margin: 8pt 0; }
  .stat-grid table { border: none; }
  .stat-grid td { border: 1px solid #d1d5db; background: #f5f5f7; text-align: center;
                  padding: 8pt 6pt; width: 25%; }
  .stat-value { font-size: 16pt; font-weight: bold; }
  .stat-label { color: #6b7280; font-size: 7pt; text-transform: uppercase; }
  .trend-up { color: #dc2626; }
  .trend-down { color: #059669; }
  .trend-flat { color: #6b7280; }
  .override { opacity: 0.6; text-decoration: line-through; }
  .footer { display: none; }
  .bar { display: inline-block; height: 14px; background: #2563eb; }
  code { background: #f5f5f7; padding: 1pt 3pt; font-size: 9pt; }
</style>
"""


def _pdf_rewrite_stat_grids(html_content: str) -> str:
    """Convert stat-grid divs to table layout for xhtml2pdf compatibility."""
    import re

    def _grid_to_table(match):
        inner = match.group(1)
        # Extract each stat div
        stats = re.findall(
            r'<div class="stat">(.*?)</div>\s*(?=<div class="stat">|$)',
            inner,
            re.DOTALL,
        )
        if not stats:
            # Fallback: try to capture stat blocks with nested divs
            stats = re.findall(
                r'<div class="stat"><div class="stat-value[^"]*">(.*?)</div>'
                r'<div class="stat-label">(.*?)</div></div>',
                inner,
                re.DOTALL,
            )
            if stats:
                cells = "".join(
                    f'<td><div class="stat-value">{v}</div><div class="stat-label">{label}</div></td>'
                    for v, label in stats
                )
                return f'<div class="stat-grid"><table><tr>{cells}</tr></table></div>'
        # If we got raw inner content for each stat, keep it
        if stats:
            cells = "".join(f"<td>{s}</td>" for s in stats)
            return f'<div class="stat-grid"><table><tr>{cells}</tr></table></div>'
        return match.group(0)

    return re.sub(
        r'<div class="stat-grid">(.*?)</div>\s*(?=<h[123]|<div class="(?!stat)|<table|$|</body)',
        _grid_to_table,
        html_content,
        flags=re.DOTALL,
    )


def _pdf_resolve_css_vars(html_content: str) -> str:
    """Replace CSS var() references with literal color values for xhtml2pdf."""
    import re

    var_map = {
        "--bg": "#ffffff",
        "--surface": "#f5f5f7",
        "--border": "#d1d5db",
        "--text": "#1a1a2e",
        "--muted": "#6b7280",
        "--accent": "#2563eb",
        "--critical": "#dc2626",
        "--high": "#ea580c",
        "--medium": "#d97706",
        "--low": "#2563eb",
        "--info": "#6b7280",
        "--green": "#059669",
        "--red": "#dc2626",
    }

    def _replace_var(m):
        name = m.group(1).strip()
        return var_map.get(name, "#000000")

    return re.sub(r"var\(\s*(--[\w-]+)\s*\)", _replace_var, html_content)


def _html_to_pdf(html_content: str) -> bytes:
    """Convert HTML report to PDF with print-optimised light theme."""
    import io

    try:
        from xhtml2pdf import pisa
    except ImportError as err:
        raise RuntimeError(
            "xhtml2pdf is required for PDF output. Install it with: pip install xhtml2pdf"
        ) from err
    # Inject print CSS (replaces the dark-theme screen styles)
    pdf_html = html_content.replace("</head>", _PRINT_CSS + "</head>")
    # Resolve any remaining CSS variable references
    pdf_html = _pdf_resolve_css_vars(pdf_html)
    # Convert stat-grid divs to tables
    pdf_html = _pdf_rewrite_stat_grids(pdf_html)

    buf = io.BytesIO()
    pisa.CreatePDF(io.StringIO(pdf_html), dest=buf)
    return buf.getvalue()


def _trend_arrow(old: int, new: int) -> str:
    if new > old:
        return f'<span class="trend-up">&#9650; +{new - old}</span>'
    elif new < old:
        return f'<span class="trend-down">&#9660; {new - old}</span>'
    return '<span class="trend-flat">&#9644; 0</span>'


# ─── HTML renderers for existing report types ────────────────────────────────


def _technical_html(scan, findings, chains, severity_counts, risk, coverage) -> str:
    target = _esc(scan.get("target_domain", "unknown"))
    date = _esc(scan.get("started_at", "N/A"))
    duration_ms = scan.get("duration_ms")
    duration = f"{duration_ms}ms" if duration_ms else "N/A"
    total = sum(severity_counts.values())

    parts = [
        "<h1>Technical Security Report</h1>",
        f'<div class="meta"><span>Target: <strong>{target}</strong></span>'
        f"<span>Scan: <code>{_esc(scan['id'])}</code></span>"
        f"<span>Date: {date}</span><span>Duration: {duration}</span></div>",
        '<div class="stat-grid">',
    ]
    for sev in SEVERITY_ORDER:
        c = severity_counts[sev]
        parts.append(
            f'<div class="stat"><div class="stat-value">{c}</div>'
            f'<div class="stat-label">{sev}</div></div>'
        )
    parts.append(
        f'<div class="stat"><div class="stat-value">{risk}</div>'
        f'<div class="stat-label">Risk Score</div></div>'
    )
    parts.append("</div>")

    # Findings
    parts.append(f"<h2>Findings ({total})</h2>")
    by_severity: dict[str, list[dict]] = {}
    for f in findings:
        by_severity.setdefault(f.get("severity", "info"), []).append(f)

    for sev in SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue
        parts.append(f"<h3>{sev.upper()} ({len(group)})</h3>")
        for f in group:
            override_cls = " override" if f.get("override") else ""
            override_tag = ""
            if f.get("override"):
                override_tag = (
                    f' <span class="badge badge-info">{_esc(f["override"]["status"])}</span>'
                )
            parts.append(f'<div class="card{override_cls}">')
            parts.append(
                f'<div class="card-title">{_severity_badge(sev)} {_esc(f.get("title", "Untitled"))}{override_tag}</div>'
            )
            if f.get("description"):
                parts.append(f'<div class="card-detail">{_esc(f["description"])}</div>')
            details = []
            if f.get("check_name"):
                details.append(f"Check: {_esc(f['check_name'])}")
            if f.get("host"):
                details.append(f"Host: {_esc(f['host'])}")
            if f.get("target_url"):
                details.append(f"URL: <code>{_esc(f['target_url'])}</code>")
            if f.get("evidence"):
                details.append(f"Evidence: {_esc(f['evidence'])}")
            if details:
                parts.append(f'<div class="card-detail">{" &middot; ".join(details)}</div>')
            parts.append("</div>")

    # Chains
    if chains:
        parts.append(f"<h2>Attack Chains ({len(chains)})</h2>")
        for c in chains:
            parts.append(
                f'<div class="card"><div class="card-title">'
                f"{_severity_badge(c.get('severity', 'info'))} {_esc(c.get('title', 'Untitled'))}</div>"
                f'<div class="card-detail">Source: {_esc(c.get("source", "N/A"))}</div>'
            )
            if c.get("description"):
                parts.append(f'<div class="card-detail">{_esc(c["description"])}</div>')
            parts.append("</div>")

    # Coverage
    parts.append("<h2>Check Coverage</h2>")
    parts.append(
        f"<p>Completed: {coverage['completed']}/{coverage['total']} &middot; "
        f"Failed: {coverage['failed']} &middot; Skipped: {coverage['skipped']}</p>"
    )

    return _wrap_html(f"Technical Report — {target}", "\n".join(parts))


def _delta_html(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b) -> str:
    target = _esc(scan_b.get("target_domain", scan_a.get("target_domain", "unknown")))
    new_count = comparison.get("new_count", 0)
    resolved_count = comparison.get("resolved_count", 0)
    recurring_count = comparison.get("recurring_count", 0)
    net_change = new_count - resolved_count

    parts = [
        "<h1>Delta Report</h1>",
        f'<div class="meta"><span>Scan A: <code>{_esc(scan_a["id"])}</code></span>'
        f"<span>Scan B: <code>{_esc(scan_b['id'])}</code></span>"
        f"<span>Target: <strong>{target}</strong></span></div>",
        '<div class="stat-grid">',
        f'<div class="stat"><div class="stat-value trend-up">+{new_count}</div><div class="stat-label">New</div></div>',
        f'<div class="stat"><div class="stat-value trend-down">-{resolved_count}</div><div class="stat-label">Resolved</div></div>',
        f'<div class="stat"><div class="stat-value">{recurring_count}</div><div class="stat-label">Recurring</div></div>',
        f'<div class="stat"><div class="stat-value">{"+" if net_change >= 0 else ""}{net_change}</div><div class="stat-label">Net Change</div></div>',
        "</div>",
        f"<p><strong>Risk Score:</strong> {risk_a} &rarr; {risk_b} {_trend_arrow(risk_a, risk_b)}</p>",
    ]

    # Severity comparison table
    parts.append("<h2>Severity Comparison</h2>")
    parts.append("<table><tr><th>Severity</th><th>Scan A</th><th>Scan B</th><th>Change</th></tr>")
    for sev in SEVERITY_ORDER:
        a, b = sev_a.get(sev, 0), sev_b.get(sev, 0)
        diff = b - a
        diff_str = f"+{diff}" if diff > 0 else str(diff)
        parts.append(
            f"<tr><td>{_severity_badge(sev)}</td><td>{a}</td><td>{b}</td><td>{diff_str}</td></tr>"
        )
    parts.append("</table>")

    # New findings
    new_findings = comparison.get("new_findings", [])
    if new_findings:
        parts.append(f"<h2>New Findings ({len(new_findings)})</h2>")
        for f in new_findings:
            parts.append(
                f'<div class="card"><div class="card-title">'
                f"{_severity_badge(f.get('severity', 'info'))} {_esc(f.get('title', 'Untitled'))}</div></div>"
            )

    resolved_findings = comparison.get("resolved_findings", [])
    if resolved_findings:
        parts.append(f"<h2>Resolved Findings ({len(resolved_findings)})</h2>")
        for f in resolved_findings:
            parts.append(
                f'<div class="card override"><div class="card-title">'
                f"{_severity_badge(f.get('severity', 'info'))} {_esc(f.get('title', 'Untitled'))}</div></div>"
            )

    if not new_findings and not resolved_findings:
        parts.append("<p><em>No changes between scans.</em></p>")

    return _wrap_html(f"Delta Report — {target}", "\n".join(parts))


# ─── Executive Report ───────────────────────────────────────────────────────


async def generate_executive_report(
    scan_id: str,
    fmt: str = "md",
    engagement_id: str | None = None,
) -> dict:
    """
    Generate an executive summary report for a scan.

    Includes risk score with trend (if previous scan exists), top findings,
    and remediation progress. Designed for leadership briefings.

    Returns {"content": str, "filename": str, "format": str}.
    """
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Scan '{scan_id}' not found")

    findings = await _finding_repo.get_findings(scan_id)
    overrides = await _override_repo.list_overrides()
    override_map = {o["fingerprint"]: o for o in overrides.get("overrides", [])}

    severity_counts = _count_by_severity(findings)
    risk = _risk_score(severity_counts)

    # Top 5 findings by severity weight
    def _sev_weight(f):
        return SEVERITY_WEIGHTS.get(f.get("severity", "info").lower(), 0)

    active_findings = [f for f in findings if f.get("fingerprint") not in override_map]
    top_findings = sorted(active_findings, key=_sev_weight, reverse=True)[:5]

    # Previous scan for trend (same target, completed before this one)
    # list_scans returns newest-first (desc), so previous scan is at i+1
    prev_scan = None
    prev_risk = None
    prev_severity = None
    target = scan.get("target_domain", "unknown")
    all_scans = await _scan_repo.list_scans(target=target, status="complete", limit=200)
    scans_list = all_scans.get("scans", [])
    for i, s in enumerate(scans_list):
        if s["id"] == scan_id and i + 1 < len(scans_list):
            prev_scan = scans_list[i + 1]
            break
    if prev_scan:
        prev_findings = await _finding_repo.get_findings(prev_scan["id"])
        prev_severity = _count_by_severity(prev_findings)
        prev_risk = _risk_score(prev_severity)

    # Remediation: count overridden findings that appear in this scan
    overridden_count = sum(1 for f in findings if f.get("fingerprint") in override_map)

    data = {
        "scan": scan,
        "target": target,
        "severity_counts": severity_counts,
        "risk": risk,
        "top_findings": top_findings,
        "prev_scan": prev_scan,
        "prev_risk": prev_risk,
        "prev_severity": prev_severity,
        "overridden_count": overridden_count,
        "total_active": len(active_findings),
    }

    if fmt == "json":
        content = _executive_json(data)
    elif fmt == "sarif":
        content = _executive_sarif(data)
    elif fmt in ("html", "pdf"):
        content = _executive_html(data)
        if fmt == "pdf":
            content = _html_to_pdf(content)
    else:
        content = _executive_markdown(data)

    ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif.json"}.get(fmt, "md")
    filename = f"executive-{target}-{scan_id[:8]}.{ext}"
    return {"content": content, "filename": filename, "format": fmt}


def _executive_markdown(d: dict) -> str:
    scan = d["scan"]
    target = d["target"]
    sev = d["severity_counts"]
    risk = d["risk"]
    total_active = d["total_active"]

    lines = [
        "# Executive Summary",
        "",
        f"**Target:** {target}",
        f"**Scan:** {scan['id']}",
        f"**Date:** {scan.get('started_at', 'N/A')}",
        "",
        "---",
        "",
        "## Risk Overview",
        "",
    ]

    # Risk with trend
    if d["prev_risk"] is not None:
        direction = (
            "improved"
            if risk < d["prev_risk"]
            else "worsened"
            if risk > d["prev_risk"]
            else "unchanged"
        )
        lines.append(f"**Risk Score:** {risk} (previously {d['prev_risk']} — {direction})")
    else:
        lines.append(f"**Risk Score:** {risk}")

    lines.extend(
        [
            f"**Active Findings:** {total_active}",
            f"**Overridden (accepted/false positive):** {d['overridden_count']}",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
    )
    for s in SEVERITY_ORDER:
        lines.append(f"| {s.capitalize()} | {sev[s]} |")

    # Severity change vs previous
    if d["prev_severity"]:
        lines.extend(["", "**Change from previous scan:**", ""])
        for s in SEVERITY_ORDER:
            diff = sev[s] - d["prev_severity"].get(s, 0)
            if diff != 0:
                sign = "+" if diff > 0 else ""
                lines.append(f"- {s.capitalize()}: {sign}{diff}")

    lines.extend(["", "## Top Findings", ""])
    for i, f in enumerate(d["top_findings"], 1):
        s = f.get("severity", "info").upper()
        lines.append(f"{i}. **[{s}]** {f.get('title', 'Untitled')}")
        if f.get("description"):
            lines.append(f"   {f['description']}")
    if not d["top_findings"]:
        lines.append("*No active findings.*")

    lines.append("")
    return "\n".join(lines)


def _executive_json(d: dict) -> str:
    report = {
        "report_type": "executive",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan": d["scan"],
        "target": d["target"],
        "summary": {
            "risk_score": d["risk"],
            "previous_risk_score": d["prev_risk"],
            "by_severity": d["severity_counts"],
            "active_findings": d["total_active"],
            "overridden_count": d["overridden_count"],
        },
        "top_findings": d["top_findings"],
    }
    return json.dumps(report, indent=2)


def _executive_html(d: dict) -> str:
    scan = d["scan"]
    target = _esc(d["target"])
    sev = d["severity_counts"]
    risk = d["risk"]

    parts = [
        "<h1>Executive Summary</h1>",
        f'<div class="meta"><span>Target: <strong>{target}</strong></span>'
        f"<span>Scan: <code>{_esc(scan['id'])}</code></span>"
        f"<span>Date: {_esc(scan.get('started_at', 'N/A'))}</span></div>",
        '<div class="stat-grid">',
    ]
    # Risk stat with trend
    if d["prev_risk"] is not None:
        parts.append(
            f'<div class="stat"><div class="stat-value">{risk}</div>'
            f'<div class="stat-label">Risk Score {_trend_arrow(d["prev_risk"], risk)}</div></div>'
        )
    else:
        parts.append(
            f'<div class="stat"><div class="stat-value">{risk}</div>'
            f'<div class="stat-label">Risk Score</div></div>'
        )
    parts.append(
        f'<div class="stat"><div class="stat-value">{d["total_active"]}</div>'
        f'<div class="stat-label">Active Findings</div></div>'
    )
    for s in ["critical", "high"]:
        parts.append(
            f'<div class="stat"><div class="stat-value">{sev[s]}</div>'
            f'<div class="stat-label">{s}</div></div>'
        )
    parts.append(
        f'<div class="stat"><div class="stat-value">{d["overridden_count"]}</div>'
        f'<div class="stat-label">Overridden</div></div>'
    )
    parts.append("</div>")

    # Severity table
    parts.append("<h2>Severity Breakdown</h2>")
    parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
    for s in SEVERITY_ORDER:
        parts.append(f"<tr><td>{_severity_badge(s)}</td><td>{sev[s]}</td></tr>")
    parts.append("</table>")

    # Top findings
    parts.append("<h2>Top Findings</h2>")
    if d["top_findings"]:
        for f in d["top_findings"]:
            parts.append(
                f'<div class="card"><div class="card-title">'
                f"{_severity_badge(f.get('severity', 'info'))} {_esc(f.get('title', 'Untitled'))}</div>"
            )
            if f.get("description"):
                parts.append(f'<div class="card-detail">{_esc(f["description"])}</div>')
            parts.append("</div>")
    else:
        parts.append("<p><em>No active findings.</em></p>")

    return _wrap_html(f"Executive Summary — {target}", "\n".join(parts))


# ─── Compliance Report ──────────────────────────────────────────────────────


async def generate_compliance_report(
    scan_id: str,
    fmt: str = "md",
    engagement_id: str | None = None,
) -> dict:
    """
    Generate a compliance report for a scan (optionally within an engagement).

    Covers engagement scope, scan window, check coverage, finding remediation
    status, and override audit trail. Suitable for audit/compliance teams.

    Returns {"content": str, "filename": str, "format": str}.
    """
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Scan '{scan_id}' not found")

    findings = await _finding_repo.get_findings(scan_id)
    log_entries = await _check_log_repo.get_log(scan_id)
    overrides = await _override_repo.list_overrides()
    override_map = {o["fingerprint"]: o for o in overrides.get("overrides", [])}
    coverage = _check_coverage(log_entries)

    # Engagement info if available
    engagement = None
    eid = engagement_id or scan.get("engagement_id")
    if eid:
        engagement = await _engagement_repo.get_engagement(eid)

    severity_counts = _count_by_severity(findings)

    # Build override audit trail for findings in this scan
    override_audit = []
    for f in findings:
        fp = f.get("fingerprint")
        if fp and fp in override_map:
            ov = override_map[fp]
            override_audit.append(
                {
                    "finding_title": f.get("title", "Untitled"),
                    "fingerprint": fp,
                    "status": ov["status"],
                    "reason": ov.get("reason", ""),
                    "overridden_at": ov.get("overridden_at", ""),
                }
            )

    # Check execution details from log
    checks_run = []
    for entry in log_entries:
        if entry.get("event") == "started":
            checks_run.append(
                {
                    "check": entry.get("check", "unknown"),
                    "suite": entry.get("suite", "unknown"),
                }
            )

    data = {
        "scan": scan,
        "engagement": engagement,
        "target": scan.get("target_domain", "unknown"),
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "coverage": coverage,
        "override_audit": override_audit,
        "checks_run": checks_run,
        "overridden_count": len(override_audit),
    }

    if fmt == "json":
        content = _compliance_json(data)
    elif fmt == "sarif":
        content = _compliance_sarif(data)
    elif fmt in ("html", "pdf"):
        content = _compliance_html(data)
        if fmt == "pdf":
            content = _html_to_pdf(content)
    else:
        content = _compliance_markdown(data)

    ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif.json"}.get(fmt, "md")
    target = data["target"]
    filename = f"compliance-{target}-{scan_id[:8]}.{ext}"
    return {"content": content, "filename": filename, "format": fmt}


def _compliance_markdown(d: dict) -> str:
    scan = d["scan"]
    target = d["target"]
    engagement = d["engagement"]
    cov = d["coverage"]

    lines = [
        "# Compliance Report",
        "",
        f"**Target:** {target}",
        f"**Scan ID:** {scan['id']}",
        f"**Started:** {scan.get('started_at', 'N/A')}",
        f"**Completed:** {scan.get('completed_at', 'N/A')}",
        f"**Status:** {scan.get('status', 'N/A')}",
    ]

    if engagement:
        lines.extend(
            [
                "",
                "## Engagement",
                "",
                f"**Name:** {engagement.get('name', 'N/A')}",
                f"**Client:** {engagement.get('client_name', 'N/A')}",
                f"**Status:** {engagement.get('status', 'N/A')}",
            ]
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Scope and Coverage",
            "",
            f"**Checks Executed:** {cov['total']}",
            f"**Completed:** {cov['completed']}",
            f"**Failed:** {cov['failed']}",
            f"**Skipped:** {cov['skipped']}",
            "",
        ]
    )

    if d["checks_run"]:
        lines.append("### Checks Performed")
        lines.append("")
        lines.append("| Check | Suite |")
        lines.append("|-------|-------|")
        for c in d["checks_run"]:
            lines.append(f"| {c['check']} | {c['suite']} |")
        lines.append("")

    lines.extend(
        [
            "## Finding Summary",
            "",
            f"**Total Findings:** {d['total_findings']}",
            f"**Overridden:** {d['overridden_count']}",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
    )
    for s in SEVERITY_ORDER:
        lines.append(f"| {s.capitalize()} | {d['severity_counts'][s]} |")

    if d["override_audit"]:
        lines.extend(
            [
                "",
                "## Override Audit Trail",
                "",
                "| Finding | Status | Reason | Date |",
                "|---------|--------|--------|------|",
            ]
        )
        for ov in d["override_audit"]:
            lines.append(
                f"| {ov['finding_title']} | {ov['status']} | "
                f"{ov['reason'] or 'N/A'} | {ov['overridden_at'] or 'N/A'} |"
            )

    lines.append("")
    return "\n".join(lines)


def _compliance_json(d: dict) -> str:
    report = {
        "report_type": "compliance",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan": d["scan"],
        "engagement": d["engagement"],
        "target": d["target"],
        "scope": {
            "checks_executed": d["coverage"]["total"],
            "completed": d["coverage"]["completed"],
            "failed": d["coverage"]["failed"],
            "skipped": d["coverage"]["skipped"],
            "checks_run": d["checks_run"],
        },
        "findings": {
            "total": d["total_findings"],
            "by_severity": d["severity_counts"],
            "overridden_count": d["overridden_count"],
        },
        "override_audit": d["override_audit"],
    }
    return json.dumps(report, indent=2)


def _compliance_html(d: dict) -> str:
    scan = d["scan"]
    target = _esc(d["target"])
    cov = d["coverage"]
    engagement = d["engagement"]

    parts = [
        "<h1>Compliance Report</h1>",
        f'<div class="meta"><span>Target: <strong>{target}</strong></span>'
        f"<span>Scan: <code>{_esc(scan['id'])}</code></span>"
        f"<span>Started: {_esc(scan.get('started_at', 'N/A'))}</span>"
        f"<span>Status: {_esc(scan.get('status', 'N/A'))}</span></div>",
    ]

    if engagement:
        parts.append(
            f'<div class="card"><div class="card-title">Engagement: {_esc(engagement.get("name", "N/A"))}</div>'
            f'<div class="card-detail">Client: {_esc(engagement.get("client_name", "N/A"))} &middot; '
            f"Status: {_esc(engagement.get('status', 'N/A'))}</div></div>"
        )

    # Coverage stats
    parts.append("<h2>Scope and Coverage</h2>")
    parts.append('<div class="stat-grid">')
    parts.append(
        f'<div class="stat"><div class="stat-value">{cov["total"]}</div><div class="stat-label">Checks Executed</div></div>'
    )
    parts.append(
        f'<div class="stat"><div class="stat-value">{cov["completed"]}</div><div class="stat-label">Completed</div></div>'
    )
    parts.append(
        f'<div class="stat"><div class="stat-value">{cov["failed"]}</div><div class="stat-label">Failed</div></div>'
    )
    parts.append(
        f'<div class="stat"><div class="stat-value">{cov["skipped"]}</div><div class="stat-label">Skipped</div></div>'
    )
    parts.append("</div>")

    if d["checks_run"]:
        parts.append("<h3>Checks Performed</h3>")
        parts.append("<table><tr><th>Check</th><th>Suite</th></tr>")
        for c in d["checks_run"]:
            parts.append(f"<tr><td>{_esc(c['check'])}</td><td>{_esc(c['suite'])}</td></tr>")
        parts.append("</table>")

    # Finding summary
    parts.append("<h2>Finding Summary</h2>")
    parts.append('<div class="stat-grid">')
    parts.append(
        f'<div class="stat"><div class="stat-value">{d["total_findings"]}</div><div class="stat-label">Total</div></div>'
    )
    for s in SEVERITY_ORDER:
        parts.append(
            f'<div class="stat"><div class="stat-value">{d["severity_counts"][s]}</div><div class="stat-label">{s}</div></div>'
        )
    parts.append("</div>")

    # Override audit
    if d["override_audit"]:
        parts.append("<h2>Override Audit Trail</h2>")
        parts.append("<table><tr><th>Finding</th><th>Status</th><th>Reason</th><th>Date</th></tr>")
        for ov in d["override_audit"]:
            parts.append(
                f"<tr><td>{_esc(ov['finding_title'])}</td><td>{_esc(ov['status'])}</td>"
                f"<td>{_esc(ov['reason'] or 'N/A')}</td><td>{_esc(ov['overridden_at'] or 'N/A')}</td></tr>"
            )
        parts.append("</table>")

    return _wrap_html(f"Compliance Report — {target}", "\n".join(parts))


# ─── Trend Report ───────────────────────────────────────────────────────────


async def generate_trend_report(
    fmt: str = "md",
    engagement_id: str | None = None,
    target: str | None = None,
) -> dict:
    """
    Generate a trend report across multiple scans.

    Either engagement_id or target must be provided.
    Includes risk score over time, severity breakdown, and suite-level trends.

    Returns {"content": str, "filename": str, "format": str}.
    """
    if not engagement_id and not target:
        raise ValueError("Either engagement_id or target must be provided")

    if engagement_id:
        engagement = await _engagement_repo.get_engagement(engagement_id)
        if engagement is None:
            raise ValueError(f"Engagement '{engagement_id}' not found")
        trend_data = await _trend_repo.get_engagement_trend(engagement_id)
        label = engagement.get("name", engagement_id)
        scope = f"engagement-{engagement_id[:8]}"
    else:
        trend_data = await _trend_repo.get_target_trend(target)
        label = target
        scope = f"target-{target}"
        engagement = None

    data_points = trend_data.get("data_points", [])
    averages = trend_data.get("averages", {})

    data = {
        "label": label,
        "scope": scope,
        "engagement": engagement,
        "target": target,
        "data_points": data_points,
        "averages": averages,
    }

    if fmt == "json":
        content = _trend_json(data)
    elif fmt == "sarif":
        content = _trend_sarif(data)
    elif fmt in ("html", "pdf"):
        content = _trend_html(data)
        if fmt == "pdf":
            content = _html_to_pdf(content)
    else:
        content = _trend_markdown(data)

    ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif.json"}.get(fmt, "md")
    filename = f"trend-{scope}.{ext}"
    return {"content": content, "filename": filename, "format": fmt}


def _trend_markdown(d: dict) -> str:
    label = d["label"]
    data_points = d["data_points"]
    averages = d["averages"]

    lines = [
        "# Trend Report",
        "",
        f"**Scope:** {label}",
        f"**Scans:** {len(data_points)}",
        "",
        "---",
        "",
    ]

    if not data_points:
        lines.append("*No completed scans found for trend analysis.*")
        lines.append("")
        return "\n".join(lines)

    # Risk score trend
    lines.append("## Risk Score Trend")
    lines.append("")
    lines.append("| Scan | Date | Risk Score | Total | Critical | High | Medium | Low |")
    lines.append("|------|------|------------|-------|----------|------|--------|-----|")
    for dp in data_points:
        lines.append(
            f"| {dp['scan_id'][:8]} | {dp.get('date', 'N/A')} | {dp['risk_score']} | "
            f"{dp['total']} | {dp.get('critical', 0)} | {dp.get('high', 0)} | "
            f"{dp.get('medium', 0)} | {dp.get('low', 0)} |"
        )

    # Overall trend direction
    if len(data_points) >= 2:
        first_risk = data_points[0]["risk_score"]
        last_risk = data_points[-1]["risk_score"]
        direction = (
            "improving"
            if last_risk < first_risk
            else "worsening"
            if last_risk > first_risk
            else "stable"
        )
        lines.extend(
            [
                "",
                f"**Overall trend:** {direction} ({first_risk} → {last_risk})",
            ]
        )

    # Suite breakdown
    suite_totals: dict[str, int] = {}
    for dp in data_points:
        for suite, count in dp.get("by_suite", {}).items():
            suite_totals[suite] = suite_totals.get(suite, 0) + count
    if suite_totals:
        lines.extend(["", "## Suite Breakdown (cumulative)", ""])
        lines.append("| Suite | Total Findings |")
        lines.append("|-------|----------------|")
        for suite, count in sorted(suite_totals.items(), key=lambda x: -x[1]):
            lines.append(f"| {suite} | {count} |")

    # Averages
    this_target_avg = averages.get("this_target", {})
    if this_target_avg:
        lines.extend(["", "## Averages (this scope)", ""])
        lines.append(f"- Risk Score: {this_target_avg.get('risk_score', 'N/A')}")
        lines.append(f"- Total: {this_target_avg.get('total', 'N/A')}")

    lines.append("")
    return "\n".join(lines)


def _trend_json(d: dict) -> str:
    report = {
        "report_type": "trend",
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": d["label"],
        "engagement": d["engagement"],
        "target": d["target"],
        "scan_count": len(d["data_points"]),
        "data_points": d["data_points"],
        "averages": d["averages"],
    }
    return json.dumps(report, indent=2)


def _trend_html(d: dict) -> str:
    label = _esc(d["label"])
    data_points = d["data_points"]
    d["averages"]

    parts = [
        "<h1>Trend Report</h1>",
        f'<div class="meta"><span>Scope: <strong>{label}</strong></span>'
        f"<span>Scans: {len(data_points)}</span></div>",
    ]

    if not data_points:
        parts.append("<p><em>No completed scans found for trend analysis.</em></p>")
        return _wrap_html(f"Trend Report — {label}", "\n".join(parts))

    # Overall stats
    if len(data_points) >= 2:
        first_risk = data_points[0]["risk_score"]
        last_risk = data_points[-1]["risk_score"]
        parts.append('<div class="stat-grid">')
        parts.append(
            f'<div class="stat"><div class="stat-value">{first_risk}</div><div class="stat-label">First Risk</div></div>'
        )
        parts.append(
            f'<div class="stat"><div class="stat-value">{last_risk}</div><div class="stat-label">Latest Risk</div></div>'
        )
        parts.append(
            f'<div class="stat"><div class="stat-value">{_trend_arrow(first_risk, last_risk)}</div><div class="stat-label">Trend</div></div>'
        )
        parts.append(
            f'<div class="stat"><div class="stat-value">{len(data_points)}</div><div class="stat-label">Scans</div></div>'
        )
        parts.append("</div>")

    # Visual risk trend (bar chart using CSS)
    parts.append("<h2>Risk Score Trend</h2>")
    max_risk = max((dp["risk_score"] for dp in data_points), default=1) or 1
    for dp in data_points:
        pct = int(dp["risk_score"] / max_risk * 100)
        scan_label = _esc(dp["scan_id"][:8])
        date_label = _esc(dp.get("date", "")[:10])
        parts.append(
            f'<div style="margin:0.3rem 0;">'
            f'<span style="display:inline-block;width:160px;font-size:0.85rem;">{scan_label} {date_label}</span>'
            f'<span class="bar" style="width:{pct}%;background:var(--accent);">&nbsp;</span>'
            f' <span style="font-size:0.85rem;">{dp["risk_score"]}</span></div>'
        )

    # Data table
    parts.append("<h2>Scan Details</h2>")
    parts.append(
        "<table><tr><th>Scan</th><th>Date</th><th>Risk</th>"
        "<th>Total</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th></tr>"
    )
    for dp in data_points:
        parts.append(
            f"<tr><td><code>{_esc(dp['scan_id'][:8])}</code></td>"
            f"<td>{_esc(dp.get('date', 'N/A'))}</td>"
            f"<td>{dp['risk_score']}</td><td>{dp['total']}</td>"
            f"<td>{dp.get('critical', 0)}</td><td>{dp.get('high', 0)}</td>"
            f"<td>{dp.get('medium', 0)}</td><td>{dp.get('low', 0)}</td></tr>"
        )
    parts.append("</table>")

    # Suite breakdown
    suite_totals: dict[str, int] = {}
    for dp in data_points:
        for suite, count in dp.get("by_suite", {}).items():
            suite_totals[suite] = suite_totals.get(suite, 0) + count
    if suite_totals:
        parts.append("<h2>Suite Breakdown</h2>")
        max_suite = max(suite_totals.values()) or 1
        for suite, count in sorted(suite_totals.items(), key=lambda x: -x[1]):
            pct = int(count / max_suite * 100)
            parts.append(
                f'<div style="margin:0.3rem 0;">'
                f'<span style="display:inline-block;width:100px;font-size:0.85rem;">{_esc(suite)}</span>'
                f'<span class="bar" style="width:{pct}%;background:var(--medium);">&nbsp;</span>'
                f' <span style="font-size:0.85rem;">{count}</span></div>'
            )

    return _wrap_html(f"Trend Report — {label}", "\n".join(parts))


# ─── SARIF Output ───────────────────────────────────────────────────────────


def _finding_to_sarif_result(f: dict) -> dict:
    """Convert a single Chainsmith finding to a SARIF result object."""
    sev = (f.get("severity") or "info").lower()
    result = {
        "ruleId": f.get("check_name", "unknown"),
        "level": _SARIF_SEV_MAP.get(sev, "note"),
        "message": {"text": f.get("description") or f.get("title", "No description")},
        "properties": {
            "severity": sev,
        },
    }

    # Rank (SARIF numeric severity, lower = more severe)
    if sev in _SARIF_SEV_RANK:
        result["rank"] = _SARIF_SEV_RANK[sev]

    # Location
    uri = f.get("target_url") or f.get("host")
    if uri:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                },
            }
        ]

    # Fingerprint
    if f.get("fingerprint"):
        result["fingerprints"] = {"chainsmith/v1": f["fingerprint"]}

    # Evidence as attachment
    if f.get("evidence"):
        result["attachments"] = [
            {
                "description": {"text": "Evidence"},
                "contents": {"text": f["evidence"]},
            }
        ]

    # Override annotation
    if f.get("override"):
        ov = f["override"]
        result["suppressions"] = [
            {
                "kind": "inSource",
                "status": "accepted" if ov["status"] == "accepted" else "rejected",
                "justification": ov.get("reason", ""),
            }
        ]

    return result


def _build_sarif_rules(findings: list[dict]) -> list[dict]:
    """Build SARIF rule descriptors from findings."""
    seen = {}
    for f in findings:
        rule_id = f.get("check_name", "unknown")
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_id.replace("_", " ").title()},
            }
            refs = f.get("references")
            if refs and isinstance(refs, list):
                seen[rule_id]["helpUri"] = refs[0]
    return list(seen.values())


def _sarif_envelope(
    results: list[dict],
    rules: list[dict],
    invocation_props: dict | None = None,
) -> str:
    """Wrap SARIF results in a complete SARIF v2.1.0 document."""
    invocation = {
        "executionSuccessful": True,
    }
    if invocation_props:
        invocation["properties"] = invocation_props

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Chainsmith Recon",
                        "version": "1.3.0",
                        "informationUri": "https://github.com/chainsmith/recon",
                        "rules": rules,
                    },
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _technical_sarif(scan, findings, chains, severity_counts, risk, coverage) -> str:
    """SARIF output for a technical report."""
    results = [_finding_to_sarif_result(f) for f in findings]
    rules = _build_sarif_rules(findings)
    return _sarif_envelope(
        results,
        rules,
        invocation_props={
            "reportType": "technical",
            "scanId": scan["id"],
            "target": scan.get("target_domain", "unknown"),
            "riskScore": risk,
            "severityCounts": severity_counts,
            "checkCoverage": coverage,
            "chainCount": len(chains),
        },
    )


def _delta_sarif(scan_a, scan_b, comparison, sev_a, sev_b, risk_a, risk_b) -> str:
    """SARIF output for a delta report — new findings only."""
    new_findings = comparison.get("new_findings", [])
    results = [_finding_to_sarif_result(f) for f in new_findings]
    rules = _build_sarif_rules(new_findings)
    return _sarif_envelope(
        results,
        rules,
        invocation_props={
            "reportType": "delta",
            "scanA": scan_a["id"],
            "scanB": scan_b["id"],
            "target": scan_b.get("target_domain", scan_a.get("target_domain", "unknown")),
            "newCount": comparison.get("new_count", 0),
            "resolvedCount": comparison.get("resolved_count", 0),
            "recurringCount": comparison.get("recurring_count", 0),
            "riskA": risk_a,
            "riskB": risk_b,
        },
    )


def _executive_sarif(data: dict) -> str:
    """SARIF output for an executive report — top findings only."""
    top = data.get("top_findings", [])
    results = [_finding_to_sarif_result(f) for f in top]
    rules = _build_sarif_rules(top)
    props = {
        "reportType": "executive",
        "scanId": data["scan"]["id"],
        "target": data["target"],
        "riskScore": data["risk"],
        "activeFindings": data["total_active"],
        "overriddenCount": data["overridden_count"],
    }
    if data.get("prev_risk") is not None:
        props["previousRiskScore"] = data["prev_risk"]
    return _sarif_envelope(results, rules, invocation_props=props)


def _compliance_sarif(data: dict) -> str:
    """SARIF output for a compliance report — override audit as suppressions."""
    results = []
    for ov in data.get("override_audit", []):
        results.append(
            {
                "ruleId": "finding_override",
                "level": "note",
                "message": {"text": f"Override: {ov['finding_title']}"},
                "fingerprints": {"chainsmith/v1": ov["fingerprint"]},
                "suppressions": [
                    {
                        "kind": "inSource",
                        "status": "accepted" if ov["status"] == "accepted" else "rejected",
                        "justification": ov.get("reason", ""),
                    }
                ],
            }
        )
    rules = (
        [{"id": "finding_override", "shortDescription": {"text": "Finding Override Audit Entry"}}]
        if results
        else []
    )
    return _sarif_envelope(
        results,
        rules,
        invocation_props={
            "reportType": "compliance",
            "scanId": data["scan"]["id"],
            "target": data["target"],
            "totalFindings": data["total_findings"],
            "checkCoverage": data["coverage"],
            "checksRun": len(data["checks_run"]),
            "overrideCount": data["overridden_count"],
            "engagement": data.get("engagement"),
        },
    )


def _trend_sarif(data: dict) -> str:
    """SARIF output for a trend report — one result per data point."""
    results = []
    for dp in data.get("data_points", []):
        results.append(
            {
                "ruleId": "trend_data_point",
                "level": "note",
                "message": {
                    "text": f"Scan {dp['scan_id'][:8]} on {dp.get('date', 'N/A')}: "
                    f"risk={dp['risk_score']}, total={dp['total']}",
                },
                "properties": {
                    "scanId": dp["scan_id"],
                    "date": dp.get("date"),
                    "riskScore": dp["risk_score"],
                    "total": dp["total"],
                    "bySeverity": {s: dp.get(s, 0) for s in SEVERITY_ORDER},
                    "bySuite": dp.get("by_suite", {}),
                    "new": dp.get("new", 0),
                    "resolved": dp.get("resolved", 0),
                },
            }
        )
    rules = (
        [{"id": "trend_data_point", "shortDescription": {"text": "Trend Data Point"}}]
        if results
        else []
    )
    return _sarif_envelope(
        results,
        rules,
        invocation_props={
            "reportType": "trend",
            "scope": data["label"],
            "scanCount": len(data["data_points"]),
            "averages": data.get("averages", {}),
        },
    )


# ─── Targeted Export ────────────────────────────────────────────────────────


async def generate_targeted_export(
    fingerprints: list[str],
    fmt: str = "md",
    title: str | None = None,
    db=None,
) -> dict:
    """
    Generate a report from a curated set of findings identified by fingerprint.

    Searches all scans to find the most recent instance of each fingerprint.
    Returns {"content": str, "filename": str, "format": str}.

    Args:
        db: Optional Database instance. Falls back to global get_session() if None.
    """
    from sqlalchemy import select

    from app.db.engine import get_session
    from app.db.models import Finding

    # Look up findings by fingerprint (most recent instance of each)
    findings = []
    _session = db.session() if db is not None else get_session()
    async with _session as session:
        for fp in fingerprints:
            result = await session.execute(
                select(Finding)
                .where(Finding.fingerprint == fp)
                .order_by(Finding.id.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            if row:
                findings.append(
                    {
                        "title": row.title,
                        "severity": row.severity,
                        "check_name": row.check_name,
                        "host": row.host,
                        "suite": row.suite,
                        "target_url": row.target_url,
                        "evidence": row.evidence,
                        "description": row.description,
                        "fingerprint": row.fingerprint,
                        "references": (
                            json.loads(row.references)
                            if isinstance(row.references, str)
                            else row.references
                        )
                        if row.references
                        else [],
                    }
                )

    if not findings:
        raise ValueError("No findings found for the provided fingerprints")

    report_title = title or "Targeted Export"
    severity_counts = _count_by_severity(findings)
    risk = _risk_score(severity_counts)

    if fmt == "json":
        content = json.dumps(
            {
                "report_type": "targeted",
                "generated_at": datetime.now(UTC).isoformat(),
                "title": report_title,
                "summary": {
                    "by_severity": severity_counts,
                    "risk_score": risk,
                    "total_findings": len(findings),
                },
                "findings": findings,
            },
            indent=2,
        )
    elif fmt == "sarif":
        results = [_finding_to_sarif_result(f) for f in findings]
        rules = _build_sarif_rules(findings)
        content = _sarif_envelope(
            results,
            rules,
            invocation_props={
                "reportType": "targeted",
                "title": report_title,
                "riskScore": risk,
            },
        )
    elif fmt in ("html", "pdf"):
        parts = [
            f"<h1>{_esc(report_title)}</h1>",
            f'<div class="meta"><span>{len(findings)} selected findings</span>'
            f"<span>Risk Score: {risk}</span></div>",
            '<div class="stat-grid">',
        ]
        for sev in SEVERITY_ORDER:
            c = severity_counts[sev]
            if c:
                parts.append(
                    f'<div class="stat"><div class="stat-value">{c}</div>'
                    f'<div class="stat-label">{sev}</div></div>'
                )
        parts.append(
            f'<div class="stat"><div class="stat-value">{risk}</div>'
            f'<div class="stat-label">Risk Score</div></div>'
        )
        parts.append("</div>")

        parts.append(f"<h2>Findings ({len(findings)})</h2>")
        for f in findings:
            sev = f.get("severity", "info")
            parts.append('<div class="card">')
            parts.append(
                f'<div class="card-title">{_severity_badge(sev)} {_esc(f.get("title", "Untitled"))}</div>'
            )
            if f.get("description"):
                parts.append(f'<div class="card-detail">{_esc(f["description"])}</div>')
            details = []
            if f.get("host"):
                details.append(f"Host: {_esc(f['host'])}")
            if f.get("check_name"):
                details.append(f"Check: {_esc(f['check_name'])}")
            if f.get("target_url"):
                details.append(f"URL: <code>{_esc(f['target_url'])}</code>")
            if details:
                parts.append(
                    f'<div class="card-detail" style="margin-top:4px">{" | ".join(details)}</div>'
                )
            if f.get("evidence"):
                parts.append(
                    f'<div class="card-detail" style="margin-top:4px;font-family:monospace">'
                    f"{_esc(f['evidence'])}</div>"
                )
            parts.append("</div>")

        content = _wrap_html(report_title, "\n".join(parts))
        if fmt == "pdf":
            content = _html_to_pdf(content)
    else:
        lines = [
            f"# {report_title}",
            "",
            f"**Findings:** {len(findings)}",
            f"**Risk Score:** {risk}",
            "",
            "---",
            "",
        ]
        for f in findings:
            sev = (f.get("severity") or "info").upper()
            lines.append(f"### [{sev}] {f.get('title', 'Untitled')}")
            lines.append("")
            if f.get("description"):
                lines.append(f"{f['description']}")
                lines.append("")
            if f.get("check_name"):
                lines.append(f"- **Check:** {f['check_name']}")
            if f.get("host"):
                lines.append(f"- **Host:** {f['host']}")
            if f.get("target_url"):
                lines.append(f"- **URL:** `{f['target_url']}`")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** {f['evidence']}")
            if f.get("fingerprint"):
                lines.append(f"- **Fingerprint:** `{f['fingerprint']}`")
            lines.append("")
        content = "\n".join(lines)

    ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif.json"}.get(fmt, "md")
    filename = f"targeted-export-{len(findings)}findings.{ext}"

    return {"content": content, "filename": filename, "format": fmt}
