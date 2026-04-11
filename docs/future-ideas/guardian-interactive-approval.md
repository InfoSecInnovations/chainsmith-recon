# Future: Guardian Interactive Approval Flow

## Context

Phase 42 wired Guardian into the scan pipeline as a hard gate. When a
check targets an out-of-scope URL or is a forbidden technique, it is
silently skipped and logged as `scope_blocked`.

## Enhancement

Add an interactive operator approval flow so that scope violations can
pause the scan and prompt the operator rather than silently skipping.

### Proposed behavior

1. Guardian detects a scope violation (URL or technique).
2. Instead of skipping immediately, the scan pauses for that check.
3. A `SCOPE_VIOLATION` event is emitted through the SSE stream with
   `requires_approval: true`.
4. The UI displays the violation with Approve / Deny buttons.
5. The operator's decision is sent to `POST /api/v1/guardian/approve`
   or `POST /api/v1/guardian/deny`.
6. Guardian resolves the pending future, and the check either runs
   or is skipped.

### Implementation notes

- Guardian already has `approve_url()` / `deny_url()` methods.
- The `pending_approvals` dict with `asyncio.Future` was removed in
  Phase 42 to keep things simple. Re-add it when implementing this.
- Consider timeout behavior: if no operator response within N seconds,
  default to deny (safe default).
- Guided Mode (Phase 36) could surface violations as proactive coach
  messages.

## When to revisit

When the UI supports interactive prompts during scan execution and
there is a real use case for operator-approved out-of-scope checks.
