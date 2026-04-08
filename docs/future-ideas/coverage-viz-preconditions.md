Coverage Visualization — Precondition-Based Labels
===================================================
Captured 2026-04-08.

Status: Pending

Problem
-------
The coverage visualization currently labels checks that did not run in
a way that doesn't explain *why* they were skipped. Users see a generic
"not run" state with no indication of whether the check was skipped
because a precondition wasn't met or because the relevant suite wasn't
found on the target.

Proposed Change
---------------
Replace the generic "not run" label with context-aware messages:

- "Preconditions not met" — when the check's prerequisites were not
  satisfied (e.g. required service not detected).
- "MCP not found on this host" — when the entire MCP suite was not
  applicable to the target.
- Similar messages for other suites/precondition categories.

The label should reflect the actual reason the check was skipped so
users understand coverage gaps at a glance.

Considerations
--------------
- Checks need to report *why* they were skipped, not just *that* they
  were skipped. This may require enriching the skip metadata.
- Group by reason in the coverage view so users can see "12 checks
  skipped: MCP not found" rather than 12 individual labels.
- Keep labels concise but informative.
