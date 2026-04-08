OWASP / MITRE / NIST Badges on Check Modals
=============================================
Captured 2026-04-08.

Status: Pending

Problem
-------
Check detail modals do not indicate which compliance frameworks or
threat taxonomies a check maps to. Users have no quick visual cue
linking a check to OWASP, MITRE ATT&CK, or NIST controls.

Proposed Change
---------------
Add small badges (e.g. "OWASP A01", "MITRE T1595", "NIST SC-7") to
each check's modal dialog. Badges should be clickable, linking to the
relevant framework reference page.

Considerations
--------------
- Define the mapping data: which checks map to which framework IDs.
- Store mappings in check metadata so they stay coupled to the check
  definition.
- Badge color/style should distinguish frameworks at a glance.
- Consider a tooltip on each badge with a short description of the
  control or technique.
