# Phase 42: Code Hygiene and Guardian Wiring

## Overview

A consolidation phase addressing accumulated drift from iterative
development. Three workstreams:

1. **Guardian wiring** — connect the existing Guardian scope enforcer
   into the scan pipeline so checks are blocked when scope conditions
   are violated
2. **Database schema consolidation** — resolve the Finding→Observation
   rename drift between Alembic migrations and ORM models, and decide
   on a single schema authority
3. **Dead model cleanup** — remove vestigial Pydantic models and the
   stale `AgentType` alias

## Motivation

A code review surfaced several categories of drift that are natural
in a multi-phase project but are now at a point where they create
real risk:

- **Guardian is built but unwired.** The `Guardian` class
  (`app/guardian.py`) implements scope enforcement — URL validation,
  technique blocking, approval/denial tracking — but nothing in the
  pipeline calls it. This is a key selling point: checks should be
  blocked from running when scope conditions are violated. Wiring it
  up is the highest-priority item in this phase.

- **Two competing schema management systems.** Alembic migrations
  (001–005) define one schema. The ORM models define a different one.
  `engine.py` bridges the gap at runtime with `_sync_add_missing_columns()`
  and `create_all()`. This means running `alembic upgrade head` on a
  fresh database produces a schema that doesn't match what the app
  expects, and the app silently patches it at startup. Eight tables
  have no migration at all.

- **The Finding→Observation rename is half-applied.** The ORM models
  use `observations`, `observation_ids`, `observations_count`,
  `observation_id`. The migrations still create `findings`,
  `finding_ids`, `findings_count`, `finding_id`. Both columns can end
  up in the same table.

- **Vestigial models accumulating.** `LaunchRequest` (empty),
  `DirectiveRequest`/`DirectiveResponse` (unused), and the
  `AgentType = ComponentType` alias marked "temporary — remove after
  migration" are still in `app/models.py`.

## Workstream A — Guardian Wiring

### Current state

`app/guardian.py` implements:
- `Guardian.__init__(scope)` — takes a `ScopeDefinition`
- `check_url(url)` → `(bool, reason)` — checks URL against in-scope
  and out-of-scope domain lists, supports wildcards
- `check_technique(technique)` → `(bool, reason)` — checks against
  `scope.forbidden_techniques`
- `validate_request(url, technique)` → `(bool, reason)` — combined
  check with approval/denial caching
- `approve_url(url)` / `deny_url(url)` — operator overrides
- `create_violation_event(url, reason)` → `AgentEvent`

`ComponentType.GUARDIAN` and `EventType.SCOPE_VIOLATION` already exist
in `app/models.py`.

### Open questions

These need discussion before implementation:

1. **Where in the pipeline does Guardian intercept?**
   - Option A: In `CheckRunner` — Guardian validates each check's
     target URL before `check.run()` is called. Checks that target
     out-of-scope URLs are skipped with a `SCOPE_VIOLATION` log entry.
   - Option B: In `CheckLauncher` — Guardian validates at the launch
     level, before checks are even queued.
   - Option C: Both — launcher-level pre-filter plus runner-level
     enforcement as a safety net.

2. **What constitutes the "technique" for a check?**
   - Is it the check's suite name (`web`, `ai`, `network`)?
   - Is it a more granular tag (e.g., `active_scan`, `passive_recon`)?
   - Does `forbidden_techniques` in `ScopeDefinition` need expansion
     to support this?

3. **Operator override flow for scope violations.**
   - Guardian already has `approve_url()` / `deny_url()` and
     `pending_approvals` with `asyncio.Future`. How should this
     integrate with the UI?
   - Should violations pause the scan and prompt the operator, or
     should they be logged and the check skipped silently?
   - Guided Mode (Phase 36) implications — does the coach surface
     Guardian violations as proactive messages?

4. **Guardian as gate vs. advisor distinction.**
   - Phase 41 doc notes: "Not a replacement for Guardian. Guardian
     enforces scope at runtime. ScanPlannerAdvisor advises on scope
     quality before scanning."
   - This distinction should be preserved. Guardian is a hard gate,
     not a suggestion engine.

5. **Relationship to proof-of-scope.**
   - Does Guardian also enforce proof-of-scope (e.g., DNS TXT record
     verification) as a pre-scan gate, or is that strictly
     `CheckProofAdvisor` territory?

6. **Event bus integration.**
   - `create_violation_event()` produces an `AgentEvent`. How does
     this flow to the UI? Through the existing SSE event stream?
     Through a dedicated violations endpoint?

### Proposed implementation (pending discussion)

```
ScopeDefinition
     |
     v
  Guardian  <-- instantiated at scan start
     |
     +-- CheckLauncher calls guardian.validate_request(url, technique)
     |     before queuing each check
     |
     +-- Violations logged to check_log with event="scope_blocked"
     |
     +-- AgentEvent emitted via event bus for UI display
     |
     +-- Operator can approve/deny via API endpoint
```

### Sub-items

- [ ] Decide interception point(s) (question 1)
- [ ] Define technique taxonomy for `forbidden_techniques` (question 2)
- [ ] Design operator override UX (question 3)
- [ ] Instantiate Guardian at scan start with current ScopeDefinition
- [ ] Wire into CheckLauncher and/or CheckRunner
- [ ] Add `scope_blocked` event type to CheckLog
- [ ] Add API endpoint for operator approve/deny of violations
- [ ] Surface violations in UI (scan page, event stream)
- [ ] Tests: scope enforcement, wildcard matching, approve/deny flow
- [ ] Update docs: vocabulary.md, pipeline.md

## Workstream B — Database Schema Consolidation

### Current state

Two schema management systems run in parallel:

1. **Alembic migrations** (001–005): create tables and add columns
   using pre-rename names (`findings`, `finding_ids`, etc.)
2. **Runtime auto-migration** (`engine.py`):
   - `_sync_add_missing_columns()` — adds ORM columns missing from
     existing tables via `ALTER TABLE ADD COLUMN`
   - `Base.metadata.create_all()` — creates tables that don't exist

This means a database can accumulate both old and new column names
in the same table (e.g., both `findings_count` and
`observations_count` in `scans`).

### Rename drift inventory

| Context | Migration name | ORM model name |
|---------|---------------|----------------|
| Main table | `findings` | `observations` |
| Scans column | `findings_count` | `observations_count` |
| Chains column | `finding_ids` | `observation_ids` |
| CheckLog column | `findings_count` | `observations_count` |
| Adjudication column | `finding_id` | `observation_id` |
| Adjudication index | `idx_adjudication_finding_id` | `idx_adjudication_observation_id` |
| Status history table | `finding_status_history` | `observation_status_history` |
| ScanComparisons column | `new_findings` | `new_observations` |

### Tables with no migration

These eight tables are created only by `create_all()`:

1. `observation_overrides`
2. `triage_plans`
3. `research_enrichments`
4. `proof_guidance`
5. `chat_messages`
6. `chainsmith_validations`
7. `chainsmith_custom_checks`
8. `triage_actions`

Plus two columns on `scans`: `triage_status`, `triage_error`.

### Open questions

1. **Single authority: Alembic or create_all?**
   - Option A: Keep Alembic as the authority. Consolidate all
     migrations into a single `001_initial_schema.py` that matches
     the current ORM models. Remove `_sync_add_missing_columns()`.
     Future schema changes go through Alembic.
   - Option B: Drop Alembic entirely. `create_all()` is the authority.
     Remove `app/db/migrations/`, `alembic.ini`. Accept that schema
     evolution is implicit.
   - Option C: Keep both but synchronize them. Alembic for explicit
     upgrades, `_sync_add_missing_columns` as a safety net for
     development velocity.

2. **Existing databases.**
   - Are there production or long-lived databases that would need an
     actual rename migration (`ALTER TABLE RENAME`)?
   - Or can we assume all databases can be recreated from scratch?

3. **Should `_sync_add_missing_columns` stay as a dev convenience?**
   - It's useful during rapid iteration (add a column to the model,
     restart the app, column appears). But it masks drift.
   - If kept, should it log a warning rather than silently patching?

### Proposed approach (pending discussion)

If databases can be recreated from scratch:
- Consolidate into a single `001_initial_schema.py` matching current
  models
- Remove migrations 002–005
- Remove `_sync_add_missing_columns()` (or keep with warnings)
- Document that Alembic is the schema authority going forward

## Workstream C — Dead Model Cleanup

These are straightforward removals with no open questions:

| Item | Location | Reason |
|------|----------|--------|
| `LaunchRequest` | `app/models.py:502-505` | Empty model, never imported |
| `DirectiveRequest` | `app/models.py:516-521` | Never used in routes or engines |
| `DirectiveResponse` | `app/models.py:523+` | Never used in routes or engines |
| `AgentType = ComponentType` | `app/models.py:33` | Alias marked "temporary", migration complete — only used in models.py itself |

### Sub-items

- [ ] Remove `LaunchRequest`, `DirectiveRequest`, `DirectiveResponse`
- [ ] Remove `AgentType` alias and comment
- [ ] Verify no imports reference these (grep confirmed: none)
- [ ] Run tests to confirm no breakage

## Dependencies

- Phase 41 (Scan Advisor Split) — establishes the Guardian vs.
  ScanPlannerAdvisor boundary [DONE]
- Phase 36 (Guided Mode) — Guardian violations may surface through
  Coach proactive triggers [DONE]
- Phase 30 (Finding→Observation rename) — the source of the migration
  drift [DONE, but incompletely applied to migrations]

## Sub-Phase ordering

```
C (dead model cleanup)     — independent, can go first
B (schema consolidation)   — needs decision on authority model
A (Guardian wiring)        — largest scope, needs design discussion
```

C is mechanical and risk-free. B requires a decision but is bounded.
A has the most open questions and the highest impact.

## What This Is NOT

- **Not a refactor of checks or agents.** No changes to check
  implementations, agent logic, or the pipeline beyond Guardian
  integration.
- **Not a new feature.** Guardian already exists. This phase wires
  it into the pipeline and cleans up accumulated drift.
- **Not a migration to PostgreSQL.** Schema consolidation applies
  to whichever backend is in use.
