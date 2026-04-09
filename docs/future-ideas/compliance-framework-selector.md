Compliance Report -- Framework Selector
=======================================
Captured 2026-04-08.

Status: Ready to implement (co-implement with compliance-framework-badges.md)

Problem
-------
The compliance report currently shows a flat view of all findings
without filtering by specific compliance frameworks. Users who need
to demonstrate compliance with a particular standard (e.g. OWASP Top
10, NIST 800-53, MITRE ATT&CK) cannot easily isolate what is and
isn't in compliance for that framework.

Proposed Change
---------------
Expand the compliance report to let users select one or more compliance
frameworks, then display only the checks and findings relevant to those
frameworks. The report should clearly show:

- Which controls/requirements are covered by the scan.
- Which are passing (in compliance).
- Which are failing (out of compliance).
- Which are not assessed (no check mapped to that control).

Prerequisites
-------------
Requires the data-driven framework plugin system described in
compliance-framework-badges.md. Specifically:

- Framework definitions loaded from app/checks/frameworks/definitions/
- parse_all() to map check references to FrameworkTags
- Optional controls files for gap analysis (frameworks that provide a
  controls_file can show "not assessed" gaps; those without can only
  show pass/fail for observed mappings)

Implementation
--------------

### API changes

POST /api/v1/reports/compliance -- add optional parameter:

    frameworks: list[str]   # e.g. ["OWASP LLM Top 10", "MITRE ATLAS"]

When provided, the report filters checks_run and observations to only
those whose references match the selected frameworks (via parse_all).

GET /api/v1/frameworks -- new endpoint returning loaded framework
metadata for the UI to populate the selector:

    [
      {
        "name": "OWASP LLM Top 10",
        "short_label": "LLM",
        "badge_color": "#dc2626",
        "has_controls": true,
        "control_count": 10
      },
      ...
    ]

### Report generation changes (app/reports.py)

generate_compliance_report() accepts optional frameworks parameter.
When set:

1. Filter checks_run to those mapping to selected frameworks.
2. Filter observations to those from matching checks.
3. For each selected framework that has a controls file:
   - Group results by control ID.
   - Mark each control as: passing, failing, or not assessed.
   - Compute compliance score (passing / total controls).
4. For frameworks without a controls file:
   - Show matched observations grouped by tag ID.
   - No gap analysis (no way to know what's missing).

All formatters (_compliance_markdown, _compliance_html, _compliance_json,
_compliance_sarif) receive the framework-grouped data and render
per-framework sections.

### UI changes (static/reports.html)

When "Compliance" report type is selected, show a framework picker:

- Multi-select pills populated from GET /api/v1/frameworks.
- Pill color matches badge_color from the framework definition.
- "All frameworks" default when none selected (current behavior).
- Selected frameworks passed as parameter to report generation POST.

### Report output structure (per framework section)

    ## OWASP LLM Top 10                        Score: 7/10 (70%)

    | Control  | Status       | Observations  |
    |----------|------------- |---------------|
    | LLM01    | FAIL         | 3 findings    |
    | LLM02    | PASS         | 0 findings    |
    | LLM03    | NOT ASSESSED | --            |
    | ...      |              |               |

Deferrable Items
----------------
These can ship in a follow-up without blocking the core feature:

- CSV/PDF export of the filtered compliance report.
- Compliance score trend over time (needs historical data).
- Custom framework definitions uploaded via UI (vs dropping YAML).
- Mapping suggestions: auto-suggest framework tags for checks that
  have no references yet, based on check description / techniques.

Files touched:
- app/reports.py -- framework filtering + per-framework sections
- app/routes/scan_history.py -- accept frameworks param
- app/routes/compliance.py or new route -- GET /api/v1/frameworks
- static/reports.html -- framework picker UI
- static/css/reports.css -- pill selector styling

Considerations
--------------
- Multi-select: user may want "OWASP LLM + MITRE ATLAS" in one view.
  Each gets its own section in the report.
- Gap analysis only works for frameworks with a controls_file.
  The UI should indicate which frameworks support it (e.g. a small
  "gap analysis" indicator on the pill).
- Performance: parse_all() runs once per report generation against
  the checks_run list. With ~114 checks and ~5 framework regexes
  this is negligible.
