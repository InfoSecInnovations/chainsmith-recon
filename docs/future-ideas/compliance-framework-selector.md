Compliance Report — Framework Selector
=======================================
Captured 2026-04-08.

Status: Pending

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

Considerations
--------------
- Requires the check-to-framework mapping from the badges feature
  (compliance-framework-badges.md) as a prerequisite.
- Support multi-select: a user may want "OWASP + NIST" in one view.
- Consider a compliance score or percentage per framework.
- Gap analysis: highlight controls that have no corresponding check
  so users know where coverage is missing.
- Export the filtered compliance report as CSV/PDF.
