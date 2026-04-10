# Phase 39 — Remove Steward, Consolidate into Chainsmith Agent

## Goal

Eliminate the "steward" identity from the project entirely. The
check-ecosystem management capabilities (validation, custom check
scaffolding, upstream drift detection, disable-impact analysis) already
live inside `ChainsmithAgent`. The steward name is just a routing and
naming layer on top. This phase removes that layer and wires the
chainsmith agent into the standard engine/repository architecture under
its own name.

## Current state

Steward exists as a thin naming layer across several files:

| File | What it contributes |
|------|-------------------|
| `app/routes/steward.py` | 7 endpoints under `/api/v1/steward/*`, each instantiating `ChainsmithAgent()` directly |
| `app/models.py` | 6 `STEWARD_*` event types |
| `app/engine/prompt_router.py` | Keyword block mentioning "steward" (already routes to `CHAINSMITH`) |
| `app/routes/__init__.py` | Exports `steward_router` |
| `app/main.py` | Registers `steward_router` |
| `app/agents/chainsmith.py` | Docstrings, comments, and manifest path referencing "steward" |
| `app/checks/custom/steward_manifest.json` | Flat-file persistence for validation results and custom check registry |

The routes skip the engine and repository layers. No state guards, no
DB persistence, no async polling. Every request re-instantiates the
agent and re-validates from scratch.

## Target state

```
app/routes/chainsmith.py
    └── app/engine/chainsmith.py (orchestration + state guards)
        ├── ChainsmithAgent (validation, scaffolding, diff, impact)
        └── ChainsmithRepository (DB persistence)
```

- No file, route, event, or comment in the project references "steward"
- Validation results and custom check registry live in the database
- Long-running operations use the 202/poll pattern
- State tracks `chainsmith_status` for concurrency guards

## What to build

### 1. Rename routes: `app/routes/steward.py` -> `app/routes/chainsmith.py`

Rename the file and all endpoints from `/api/v1/steward/*` to
`/api/v1/chainsmith/*`:

| Old | New |
|-----|-----|
| `GET  /api/v1/steward/validate` | `GET  /api/v1/chainsmith/validate` |
| `GET  /api/v1/steward/health` | `GET  /api/v1/chainsmith/health` |
| `POST /api/v1/steward/disable-impact` | `POST /api/v1/chainsmith/disable-impact` |
| `GET  /api/v1/steward/upstream-diff` | `GET  /api/v1/chainsmith/upstream-diff` |
| `POST /api/v1/steward/scaffold` | `POST /api/v1/chainsmith/scaffold` |
| `POST /api/v1/steward/create-check` | `POST /api/v1/chainsmith/create-check` |
| `GET  /api/v1/steward/custom-checks` | `GET  /api/v1/chainsmith/custom-checks` |

Remove direct `ChainsmithAgent()` instantiation from route handlers.
Routes call engine functions instead (see step 3).

### 2. Rename events in `app/models.py`

| Old | New |
|-----|-----|
| `STEWARD_VALIDATION_START` | `CHAINSMITH_VALIDATION_START` |
| `STEWARD_VALIDATION_COMPLETE` | `CHAINSMITH_VALIDATION_COMPLETE` |
| `STEWARD_ISSUE_FOUND` | `CHAINSMITH_ISSUE_FOUND` |
| `STEWARD_FIX_APPLIED` | `CHAINSMITH_FIX_APPLIED` |
| `STEWARD_CUSTOM_CHECK_CREATED` | `CHAINSMITH_CUSTOM_CHECK_CREATED` |
| `STEWARD_UPSTREAM_DIFF` | `CHAINSMITH_UPSTREAM_DIFF` |

Update all references in `app/agents/chainsmith.py` to emit the
renamed events.

### 3. Engine module: `app/engine/chainsmith.py`

Orchestration layer following the pattern in `app/engine/adjudication.py`
and `app/engine/chains.py`:

- **`run_validation(scan_id)`** — guard against concurrent runs via
  `state.chainsmith_status`, load context from DB, run
  `ChainsmithAgent.validate()`, persist results via repository, update
  status.
- **`run_upstream_diff(scan_id)`** — check for community check drift,
  persist result.
- **`scaffold_check(...)`** — preview a custom check (synchronous, no
  background task needed).
- **`create_check(...)`** — scaffold, write, register, persist metadata.
- **`get_disable_impact(check_names)`** — impact analysis (synchronous).

The engine owns the `ChainsmithAgent` lifecycle — routes never
instantiate the agent directly.

### 4. Repository methods

Add chainsmith persistence to `app/db/repositories.py` (or a new class
within it), following the existing repository pattern:

- **`save_validation(scan_id, result)`** — store validation results.
- **`get_validation(scan_id)`** — retrieve last validation for a scan.
- **`save_custom_check(metadata)`** — register a custom check.
- **`get_custom_checks()`** — list registered custom checks.
- **`save_upstream_diff(scan_id, diff)`** — store diff results.

This replaces `steward_manifest.json` as the persistence layer.

### 5. State field

Add to `app/state.py` `reset()`:

```python
self.chainsmith_status: str = "idle"  # idle, validating, complete, error
```

Follows the same pattern as `chain_status`, `adjudication_status`, and
`triage_status`.

### 6. Async polling for validation

Full validation (graph + patterns + optional content analysis) can be
slow. Follow the existing pattern:

```
POST /api/v1/chainsmith/validate  ->  202 Accepted
GET  /api/v1/chainsmith/status    ->  { status, result, error }
```

Note: `validate` changes from GET to POST since it triggers work.

### 7. Remove manifest file

Delete `app/checks/custom/steward_manifest.json`. Remove
`_load_manifest()` and `_save_manifest()` from `ChainsmithAgent`.
The community check hash can be stored in the DB alongside validation
results.

### 8. Clean up references

- `app/routes/__init__.py` — export `chainsmith_router` instead of
  `steward_router`
- `app/main.py` — register `chainsmith_router`
- `app/engine/prompt_router.py` — remove "steward" from keywords and
  docstring (keep the functional keywords like "validate checks",
  "check graph", etc.)
- `app/agents/chainsmith.py` — update module docstring, class docstring,
  help text, comments, and `MANIFEST_PATH` constant

## File change summary

| Action | File |
|--------|------|
| Delete | `app/routes/steward.py` |
| Delete | `app/checks/custom/steward_manifest.json` |
| Create | `app/routes/chainsmith.py` |
| Create | `app/engine/chainsmith.py` |
| Modify | `app/agents/chainsmith.py` — remove manifest methods, rename events, update docstrings |
| Modify | `app/models.py` — rename 6 event types |
| Modify | `app/state.py` — add `chainsmith_status` |
| Modify | `app/db/repositories.py` — add chainsmith persistence methods |
| Modify | `app/routes/__init__.py` — swap router export |
| Modify | `app/main.py` — swap router registration |
| Modify | `app/engine/prompt_router.py` — remove "steward" keyword |
| Modify | `docs/pipeline.md` — remove steward references |
| Modify | `docs/future-ideas/completed/phase23-chainsmith-agent-steward.md` — add deprecation note |
| Modify | `docs/future-ideas/completed/phase26-model-review.md` — update steward mentions |
| Modify | `docs/future-ideas/completed/phase34-prompt-router.md` — update steward mentions |

## Order of operations

1. Rename events in `models.py` and update references in
   `chainsmith.py` — this is a safe find-and-replace with no behavior
   change.
2. Add `chainsmith_status` to `state.py`.
3. Add repository methods to `repositories.py`.
4. Build `app/engine/chainsmith.py` engine module.
5. Create `app/routes/chainsmith.py` with new endpoints calling the
   engine.
6. Swap router registration in `__init__.py` and `main.py`.
7. Remove `app/routes/steward.py`.
8. Remove manifest file and manifest methods from the agent.
9. Clean up remaining "steward" references in docstrings, comments, and
   prompt router.
10. Update documentation — remove or reword "steward" references in:
    - `docs/pipeline.md` — update architecture description
    - `docs/future-ideas/completed/phase23-chainsmith-agent-steward.md` —
      add a note at the top that steward was folded into chainsmith in
      Phase 39 (keep the original text as historical record)
    - `docs/future-ideas/completed/phase26-model-review.md` — update
      any steward mentions
    - `docs/future-ideas/completed/phase34-prompt-router.md` — update
      any steward mentions

## Out of scope

- Changing ChainsmithAgent's internal validation logic (graph analysis,
  pattern validation, etc.) — this phase is about removing the steward
  identity and adding proper wiring.
- Adding new chainsmith capabilities.
- UI changes (the frontend will need endpoint URL updates, but that is
  a separate concern).

## Dependencies

- None hard. Can be done independently.
- Should be done before any UI work that polls chainsmith status.
