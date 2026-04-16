# Phase 50 — UTC Datetime Hygiene

## Goal

Standardize all datetime handling in Chainsmith on timezone-aware UTC
internally. Local-time rendering happens only at display boundaries
(reports, UI, logs that operators read).

## Motivation

`ScanWindow.is_within_window()` in `app/proof_of_scope.py` has a
silent timezone bug: it calls `datetime.utcnow()` (naive), then strips
the `+00:00` / `Z` suffix from stored ISO strings before parsing. A
stored window like `"2026-04-14T18:00:00-05:00"` ends up compared as if
it were UTC, producing a 5-hour error with no warning. This blocks
Phase-49-adjacent Guardian engagement-window enforcement (see
`engagement-window-enforcement.md`), because the gate's correctness
depends on the comparison being right.

Rather than patch only the one call site, audit and fix the whole
codebase so this class of bug cannot recur.

## Rules

1. **Internal storage and comparison:** always timezone-aware UTC.
   - Use `datetime.now(timezone.utc)`, never `datetime.utcnow()` (which
     is naive and deprecated in 3.12+).
   - Parse ISO strings without stripping offsets. `datetime.fromisoformat`
     in 3.11+ handles `Z` natively; for older callers, replace `Z` with
     `+00:00` and keep the offset.
   - When a datetime must be serialized, emit ISO 8601 with explicit
     offset (`...+00:00` or `...Z`).
2. **Input normalization:** datetimes entering the system (API request
   bodies, config files, UI form values) are converted to UTC at the
   boundary. If an incoming value is naive, reject it or assume UTC
   explicitly — never silently.
3. **Display:** reports and UI convert UTC → operator-local at render
   time. The stored value stays UTC.
4. **Tests:** datetime-sensitive tests use fixed UTC instants, not
   `now()`. Freeze time rather than sleeping.

## Scope of audit

Full codebase sweep. Representative hotspots to check first:

- `app/proof_of_scope.py` — `ScanWindow.is_within_window()`, any
  `timestamp` fields on `ScopeViolation`, `ComplianceReport`.
- `app/guardian.py` — violation timestamps (currently none, but the
  Phase-49 enforcement will add them).
- `app/models.py` — `AgentEvent.timestamp`, any scan/session
  timestamps, persisted datetime fields.
- `app/state.py`, `app/db/models.py` — persistence schema: confirm
  stored datetimes are UTC and columns are timezone-aware where the DB
  supports it.
- `app/engine/scanner.py`, `app/check_launcher.py` — scan start/end
  times, check execution timestamps.
- `app/swarm/*` — task dispatch/heartbeat timestamps, especially
  anything that crosses the coordinator ↔ remote agent boundary
  (different host clocks make naive comparisons especially dangerous).
- `app/routes/*` — API response serialization of datetimes.
- `app/preferences.py` — any datetime-typed preferences.
- `static/**/*.{html,js}` — confirm UI parses UTC and renders local.
- `scenarios/**/*.py` — simulation/fixture timestamps.
- `tests/**/*.py` — any `datetime.utcnow()` or naive `datetime.now()`.

For each file: grep for `datetime.utcnow`, `datetime.now(` without a tz
argument, `fromisoformat` with string-stripping, `strptime` without tz,
and any `.replace(tzinfo=None)`.

## Deliverables

1. Audit report enumerating every offender with file:line and category
   (naive construction / stripped parse / missing boundary conversion /
   display without localization).
2. Fixes applied per the rules above.
3. A lint rule or test that fails on `datetime.utcnow()` and on naive
   `datetime.now()` in `app/` and `tests/`.
4. Brief note in `docs/vocabulary.md` (or equivalent) stating the UTC-
   internal / local-at-display rule so future contributors follow it.

## Relationship to other phases

- **Unblocks** the Guardian engagement-window enforcement
  (`engagement-window-enforcement.md`): that gate's correctness depends
  on `is_within_window()` doing a real timezone-aware comparison.
- **Supports** swarm correctness: coordinator and remote agents run on
  different hosts, so any naive datetime crossing the wire is a latent
  bug.

## When to do this

Before implementing Guardian engagement-window enforcement. The
enforcement work should assume this phase is complete rather than
patching the one call site in isolation.
