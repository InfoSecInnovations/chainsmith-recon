CSV Export Option
=================
Captured 2026-04-08.

Status: Pending

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
