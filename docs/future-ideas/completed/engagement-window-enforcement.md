# Future: Engagement Window Enforcement

## Context

`ScanWindow` in `proof_of_scope.py` tracks whether the current
time falls within a configured engagement window (start/end datetime).
Currently it is informational only — the `is_within_window()` check is
exposed via the API but does not block scans.

## Enhancement

Enforce the engagement window as a pre-scan gate. If the operator tries
to start a scan outside the configured window, the scan should be
blocked unless explicitly acknowledged.

### Enforcement site: Guardian

This gate is implemented in `app/guardian.py`, not inline in the scan
route. Guardian is the single chokepoint for all scan allow/block
decisions, so pre-scan preconditions (scope, engagement window, and
future compliance gates) all live there for consistency and
discoverability.

**Applies to all check invocations**, regardless of dispatch path:
manual `POST /api/v1/scan`, scheduled/cron scans, and swarm-dispatched
checks. Remote swarm agents currently build a local scope validator
from task-payload domains/ports (see `app/swarm/agent.py`) and have no
Guardian instance. They need a local Guardian built from the task
payload's scope + engagement window so enforcement is symmetric
coordinator-side and agent-side.

### Per-scan acknowledgment (not persistent)

`ProofOfScopeSettings.outside_window_acknowledged` stays as a record
on the compliance report, but the *gate input* must come from the scan
request body (e.g. `ScanRequest.acknowledge_outside_window: bool`). A
persistent sticky flag would silently carry acknowledgment across
scans, which is unsafe. Guardian records the per-scan acknowledgment
through `ViolationLogger` so the compliance report reflects it.

### Prerequisite: Phase 50 (UTC datetime hygiene)

`ScanWindow.is_within_window()` currently compares naive
`datetime.utcnow()` against a parsed datetime whose timezone offset
has been stripped — a silent bug that produces wrong results for any
non-UTC stored window. Enforcement work assumes
`phase50-utc-datetime-hygiene.md` has been completed so the comparison
is correct.

### Proposed behavior

1. `POST /api/v1/scan` delegates to Guardian, which consults
   `state.proof_settings.scan_window`.
2. If a window is configured and `is_within_window()` returns False:
   - If `outside_window_acknowledged` is True, Guardian allows the scan
     and logs the override to the violation logger.
   - Otherwise, Guardian blocks the scan; the route returns 409 with a
     message explaining the window constraint and how to acknowledge.
3. The UI should display the window status and provide an acknowledge
   button.

### Integration with proof-of-scope logging

- Window violations should be recorded by `ViolationLogger` for the
  compliance report.
- The `ComplianceReport` already includes `scan_window` and
  `outside_window_acknowledged` fields.

## When to revisit

When the proof-of-scope / compliance reporting features are actively
used by operators who need enforceable engagement windows.
