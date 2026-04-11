# Future: Engagement Window Enforcement

## Context

`EngagementWindow` in `proof_of_scope.py` tracks whether the current
time falls within a configured engagement window (start/end datetime).
Currently it is informational only — the `is_within_window()` check is
exposed via the API but does not block scans.

## Enhancement

Enforce the engagement window as a pre-scan gate. If the operator tries
to start a scan outside the configured window, the scan should be
blocked unless explicitly acknowledged.

### Proposed behavior

1. `POST /api/v1/scan` checks `state.proof_settings.engagement_window`.
2. If a window is configured and `is_within_window()` returns False:
   - If `outside_window_acknowledged` is True, allow the scan and log
     the override to the violation logger.
   - Otherwise, return 409 with a message explaining the window
     constraint and how to acknowledge.
3. The UI should display the window status and provide an acknowledge
   button.

### Integration with proof-of-scope logging

- Window violations should be recorded by `ViolationLogger` for the
  compliance report.
- The `ComplianceReport` already includes `engagement_window` and
  `outside_window_acknowledged` fields.

## When to revisit

When the proof-of-scope / compliance reporting features are actively
used by operators who need enforceable engagement windows.
