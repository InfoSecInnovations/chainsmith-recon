# Phase 39 — Steward Route & Architecture Cleanup

## Problem

`app/routes/steward.py` instantiates `ChainsmithAgent()` directly inside
every route handler (7 times). Every other agent-facing route follows a
consistent pattern:

1. Route handler calls an **engine module** (e.g. `app/engine/adjudication`,
   `app/engine/chains`, `app/engine/chat`).
2. Engine module orchestrates the agent, manages `state`, and persists
   results through a **repository**.
3. Route handler reads results back from the repository or returns the
   engine's response.

The steward routes skip both layers — no engine, no repository, no state
tracking. This means:

- No persistence of validation results across requests (each call
  re-instantiates the agent and re-validates from scratch).
- No status tracking via `state` (can't poll for progress on long
  validations).
- No consistency with how the rest of the codebase works — a contributor
  reading adjudication routes would be surprised by steward routes.
- The manifest file (`app/checks/custom/steward_manifest.json`) acts as
  an ad-hoc persistence layer instead of the database.

## Current state

```
steward.py route handlers
    └── ChainsmithAgent() instantiated per-request (7 times)
        └── reads/writes steward_manifest.json directly
```

## Target state

```
steward.py route handlers
    └── app/engine/steward.py (orchestration + state)
        ├── ChainsmithAgent (validation, scaffolding, diff)
        └── StewardRepository (DB persistence)
            └── steward_manifest.json (custom check metadata only)
```

## What to build

### 1. Engine module: `app/engine/steward.py`

Orchestration layer matching the pattern in `app/engine/adjudication.py`
and `app/engine/chains.py`:

- `run_validation(state)` — run full validation, update state, persist
  results.
- `run_upstream_diff(state)` — check for community check drift.
- `scaffold_check(...)` — preview a custom check.
- `create_check(...)` — scaffold, write, register.
- `get_disable_impact(check_names)` — impact analysis.

Manages `state.steward_status` (idle / validating / complete / error)
so the UI can poll.

### 2. Repository: `app/db/repositories/steward.py`

Persist validation results in the database rather than relying solely on
the manifest file:

- `save_validation(scan_id, result)` — store `ValidationResult`.
- `get_validation(scan_id)` — retrieve last validation for a scan.
- `get_custom_checks()` — list registered custom checks.
- `save_custom_check(check_metadata)` — record a new custom check.

The manifest file should remain for custom check metadata that the
steward needs at import time, but validation results and history belong
in the database.

### 3. State fields

Add to `app/state.py`:

- `steward_status: str = "idle"` — idle / validating / complete / error
- `steward_error: str | None = None`
- `last_validation_result: dict | None = None`

### 4. Route refactor

Rewrite `app/routes/steward.py` to:

- Remove all direct `ChainsmithAgent()` instantiation.
- Call engine functions instead.
- Read results from the repository for GET endpoints.
- Return 202 + poll pattern for long-running operations (validation,
  upstream diff) matching adjudication/chains routes.

### 5. Async status for validation

Full validation (graph + patterns + optional content analysis) can be
slow. Follow the chains/adjudication pattern:

```
POST /api/v1/steward/validate  →  202 Accepted
GET  /api/v1/steward/status    →  { status, result, error }
```

## Out of scope

- Changing ChainsmithAgent's internal logic — this phase is about the
  route/engine/repository wiring, not the agent itself.
- Splitting Chainsmith's steward role into a separate class — that is a
  separate architectural decision.
- Adding new steward capabilities.

## Dependencies

- None hard. Can be done independently.
- Should be done before any UI work that polls steward status, since the
  current routes have no status tracking.
