CSV Export Option
=================
Captured 2026-04-08.

Status: Complete (2026-04-08)

Problem
-------
There is currently no way to export scan results or report data as CSV.
Users who need to import findings into spreadsheets, SIEMs, or other
tools have no machine-friendly export path.

Proposed Change
---------------
Add a CSV export option to the reporting UI. Users should be able to
export the full findings table (or a filtered subset) as a downloadable
.csv file.

Considerations
--------------
- Define columns: check name, suite, severity, status, description,
  compliance mappings, timestamps, etc.
- Handle multi-value fields (e.g. multiple compliance tags) gracefully
  in CSV format.
- Offer export from both the web UI (download button) and the CLI
  (--format csv flag).
- Consider additional formats later (JSON, PDF) but start with CSV.

Implementation
--------------
### CSV columns
title, severity, check_name, suite, host, target_url, description,
evidence, verification_status, confidence, references, created_at.

Multi-value fields (references) are joined with "; ".

### CLI
- `chainsmith scan` accepts `--format csv`
- `chainsmith export` accepts `--format csv`
- All `chainsmith report` subcommands (technical, delta, executive,
  compliance, trend) accept `--format csv`

### API
- `GET /api/v1/observations/export/csv` — active scan CSV download
- `GET /api/v1/scans/{scan_id}/observations/export/csv` — historical scan
- All report generation endpoints (`/api/v1/reports/*`) accept `csv` format

### Web UI
- "Export CSV" button added to sidebar on index, scan, and observations pages
- CSV format button added to reports page format selector
- CSV format button added to trend page export panel

### Files changed
- `app/cli_formatters.py` — `observations_to_csv()`, CSV_COLUMNS, csv case in `output_observations()`
- `app/cli.py` — csv added to format choices for scan, export, and report commands
- `app/reports.py` — `_observations_csv()` helper, `_trend_csv()`, csv handling in all generators
- `app/routes/observations.py` — `/api/v1/observations/export/csv` endpoint
- `app/routes/scan_history.py` — `/api/v1/scans/{id}/observations/export/csv`, VALID_FORMATS updated
- `static/js/api.js` — `exportObservationsCsv()` method, btn-export-csv handler
- `static/index.html` — Export CSV button
- `static/scan.html` — Export CSV button
- `static/observations.html` — Export CSV button
- `static/reports.html` — CSV format button, text/csv mime type
- `static/trend.html` — CSV format button, text/csv mime type
