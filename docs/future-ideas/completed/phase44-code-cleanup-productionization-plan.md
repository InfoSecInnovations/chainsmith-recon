# Phase 44: Code Cleanup & Productionization Plan

> Deep code review of ~121K lines across 7 systems.
> ~180 distinct issues found, clustered into 10 numbered sub-phases.
> Goal: reliability through tight, clean code.

**Database strategy**: Greenfield. No migrations. Change schemas directly in `app/db/models.py`, delete old DB, let `create_all()` rebuild.

---

## Sub-Phase 1: Foundation — Type Safety & Mutable Defaults

**Why first**: These are latent bugs that corrupt state silently. Every other fix builds on clean foundations.

### 1.1 Fix mutable class-level defaults in `app/checks/base.py`

`conditions`, `produces`, `service_types`, `references`, `techniques` are shared lists across all subclass instances. If any check mutates these at runtime, all checks are affected.

**Files**: `app/checks/base.py` (lines ~215, 218, 231, 238-239)

### 1.2 Fix mutable defaults in `app/api_models.py`

10+ Pydantic models use `= []` or `= {}` instead of `Field(default_factory=list)`.

**Affected models**: `ScopeInput`, `ExtendedScopeInput`, `ScanStartInput`, `ScanSettings`, `CheckInfo`, `ProfileCreateInput`, `PreRunSeverityOverridesInput`

**Files**: `app/api_models.py` (lines ~16-17, 59-60, 72-73, 86, 111-112, 167, 204-205)

### 1.3 Consolidate the dual Observation type

- `app/checks/base.Observation` (dataclass, `raw_data: dict`)
- `app/models.Observation` (Pydantic, `raw_evidence: RawEvidence`)

Create explicit conversion functions. Document which is used where.

**Files**: `app/checks/base.py`, `app/models.py`, likely a new conversion utility

### 1.4 Consolidate the dual Severity enum

- `base.Severity` (Enum)
- `models.ObservationSeverity` (StrEnum)

Pick one, use everywhere.

**Files**: `app/checks/base.py`, `app/models.py`, all consumers

### 1.5 Fix variable shadowing in `app/config.py`

`sc` reused for `ScopeConfig` (line ~222) and `StorageConfig` (line ~264) in the same function. Rename to `scope_cfg` and `storage_cfg`.

**Files**: `app/config.py`

**Estimated files touched**: ~15
**Risk**: Low — type/default changes, no logic changes

---

## Sub-Phase 2: Complete the Finding → Observation Rename

**Why**: Half-done rename creates confusion and data mapping bugs.

### 2.1 Rename fields in ProofGuidance model

`app/models.py:397-398`: `finding_id` → `observation_id`, `finding_title` → `observation_title`

### 2.2 Rename DB column

`app/db/models.py:274`: `ProofGuidanceRecord.finding_title` → `observation_title`

### 2.3 Update repository code

`app/db/repositories.py:1842-1870`: All references to `finding_id`, `finding_title`

### 2.4 Update advisor code

`app/advisors/check_proof.py:78-79, 247-248`: Dict construction and model instantiation

### 2.5 Update display code

`app/engine/chat.py:784`: Formatting references

### 2.6 Update scenario configs

- `scenarios/fakobanko/config.py:345-348`: `is_finding_active()` → `is_observation_active()`
- `scenarios/demo-domain/demo_domain/config.py:167-170`: Same rename

### 2.7 Rename loop variables

All loop variables named `f` (from old "finding") in `repositories.py` and `cli_formatters.py` → rename to `obs`

**Estimated files touched**: ~10
**Risk**: Medium — DB column rename requires DB rebuild (greenfield, so just delete and recreate)

---

## Sub-Phase 3: Error Handling Tightening

**Why**: 55+ bare `except Exception` clauses across 30 files. Silent failures make debugging impossible.

### 3.1 Replace bare `except Exception` with specific exceptions

Priority files (highest impact):

| File | Count | Why it matters |
|------|-------|----------------|
| `app/db/persist.py` | 6 | Callers can't distinguish "persistence off" from "persistence crashed" |
| `app/cli.py` | 4 | User sees generic errors with no diagnostic info |
| `app/db/writers.py` | 3 | Permanently switches to scratch mode on first error |
| `app/agents/chainsmith.py` | 3 | Orchestrator failures silently swallowed |
| `app/check_launcher.py` | 2 | Check execution loses all diagnostic info |
| `app/agents/verifier.py` | 2 | Verification verdicts silently lost |
| `app/agents/triage.py` | 2 | Triage actions silently dropped |
| `app/agents/researcher.py` | 2 | Enrichment loop can spin with no progress |
| `app/config.py` | 1 | Malformed YAML silently returns empty dict |

### 3.2 Add error classification to LLM calls

`app/lib/llm.py` `_classify_error()` misses connection resets, DNS failures, certificate errors.

### 3.3 Make ObservationWriter recoverable

Currently permanently switches to scratch mode on first DB error. Add retry with backoff; allow recovery if DB comes back.

**Files**: `app/db/writers.py`

### 3.4 Add proper error propagation in persist.py

Callers need to know when persistence fails, not just get `None`.

**Files**: `app/db/persist.py`

**Estimated files touched**: ~35
**Risk**: Low-Medium — narrowing catch clauses is safe if done carefully

---

## Sub-Phase 4: State Management & Concurrency

**Why**: Race conditions in scan startup, global state mutations without locks, state never reset on errors.

### 4.1 Add async locks to route-level state mutations

- `app/routes/scan.py` — two concurrent POST requests can both start scans (check-then-set race)
- `app/routes/chains.py` — same pattern
- `app/routes/adjudication.py` — same pattern

Add `asyncio.Lock()` for check-and-set operations on `state.status`, `state.chain_status`, `state.adjudication_status`.

### 4.2 Add state reset on error

If `run_scan()` crashes, `state.status` remains "running" forever. Add try/finally in all async tasks launched by routes.

**Files**: `app/routes/scan.py`, `app/routes/chains.py`, `app/routes/adjudication.py`

### 4.3 Fix CheckLauncher timeout bypass

`app/check_launcher.py` calls `check.run()` directly instead of `check.execute()`, bypassing the timeout wrapper in `BaseCheck`. A stuck check hangs the entire scan.

**Files**: `app/check_launcher.py`

### 4.4 Protect parallel check context

`app/checks/runner.py` runs checks in parallel via `asyncio.gather()` but `self.context` is shared and mutable. Add copy-on-read or locking.

**Files**: `app/checks/runner.py`

### 4.5 Fix SSE connection leak

`app/engine/chat.py` `connect()` uses a list, not a dict keyed by connection ID. Duplicate connections or out-of-order disconnects can corrupt the list.

**Files**: `app/engine/chat.py`

### 4.6 Add atomic session file writes for scenario services

`_save_session()` in `app/scenario_services/common/config.py` has no atomic write (temp file + rename) and no file lock for multi-container scenarios.

**Files**: `app/scenario_services/common/config.py`

**Estimated files touched**: ~12
**Risk**: Medium — concurrency changes need careful testing

---

## Sub-Phase 5: Database Integrity

**Why**: No foreign keys, no constraints, no optimistic locking. Partial writes, orphaned records, silent data corruption possible.

**Strategy**: Greenfield — all changes go directly into `app/db/models.py`. Delete old DB, let `create_all()` rebuild.

### 5.1 Add foreign key constraints

All `*_id` columns referencing other tables need proper FK constraints with CASCADE DELETE:

| Column | Table | References |
|--------|-------|------------|
| `scan_id` | `ObservationRecord` | `Scan.id` |
| `scan_id` | `Chain` | `Scan.id` |
| `scan_id` | `CheckLog` | `Scan.id` |
| `scan_id` | `AdjudicationResult` | `Scan.id` |
| `observation_id` | `AdjudicationResult` | `ObservationRecord.id` |
| `scan_id` | `ResearchEnrichmentRecord` | `Scan.id` |
| `observation_id` | `ResearchEnrichmentRecord` | `ObservationRecord.id` |
| `scan_id` | `ProofGuidanceRecord` | `Scan.id` |
| `scan_id` | `TriagePlanRecord` | `Scan.id` |
| `plan_id` | `TriageActionRecord` | `TriagePlanRecord.id` |
| `session_id` | `ChatMessage` | — |
| `engagement_id` | `ChatMessage` | `Engagement.id` |

### 5.2 Add composite indexes

- `(scan_id, severity)` on `ObservationRecord` — most common query filter
- `(scan_id, check_name)` on `CheckLog` — used in comparison queries

### 5.3 Fix Boolean columns

Replace `Integer` with `Boolean` for:
- `TriagePlanRecord.team_context_available`
- `TriagePlanRecord.offline_mode`
- `ChatMessage.cleared`

Remove manual `int()` / `bool()` conversions in repositories.

### 5.4 Add optimistic locking

Add `version` column to `Scan` table. Increment on update, reject stale writes.

### 5.5 Fix N+1 queries in trend computation

`_build_data_points()` does 3 queries per scan. Replace with batched JOINs.

**Files**: `app/db/repositories.py` (lines ~1143-1232)

### 5.6 Add CHECK constraints on status fields

Prevent invalid values at DB level for `Scan.status`, `Scan.adjudication_status`, `Scan.chain_status`, `Scan.triage_status`, `ObservationRecord.verification_status`.

### 5.7 Configure connection pool

Add `pool_size`, `max_overflow`, `pool_pre_ping`, `pool_recycle` to `create_async_engine()`.

**Files**: `app/db/engine.py`

### 5.8 Simplify manual cascade delete

Once FK constraints with CASCADE are in place, `delete_scan()` in repositories.py can be simplified — the DB handles cascading.

**Estimated files touched**: ~5
**Risk**: Low (greenfield — just rebuild DB)

---

## Sub-Phase 6: Input Validation & API Hardening

**Why**: Missing validation on path parameters, no CORS, unauthenticated swarm endpoints.

### 6.1 Add authentication to swarm key creation

`app/routes/swarm.py:156-189` allows unauthenticated API key generation. Add `Depends(require_swarm_auth)`.

### 6.2 Validate path and query parameters

`check_name`, `scan_id`, `engagement_id`, `title` should be validated against format patterns (alphanumeric + hyphens) before reaching DB.

**Files**: `app/routes/customizations.py`, `app/routes/scan_history.py`, `app/routes/engagements.py`

### 6.3 Add CORS middleware

`app/main.py` has no CORS config. Add `CORSMiddleware` with explicit allowed origins.

### 6.4 Sanitize export filenames

`scan_id` in Content-Disposition headers is user-controlled. Strip non-alphanumeric characters.

**Files**: `app/routes/scan_history.py`

### 6.5 Add file size limits to CLI input

CLI `--input` reads files without size checks. Cap at reasonable limit (e.g. 100MB).

**Files**: `app/cli.py`

### 6.6 Standardize error responses

Define a standard error response schema (`error_code`, `message`, `details`). Apply consistently across all routes.

### 6.7 Validate `port_profile` against known values

Accepted as free string throughout, never validated. Add enum validation in `ScanStartInput` and config loading.

**Files**: `app/api_models.py`, `app/config.py`

**Estimated files touched**: ~15
**Risk**: Low — additive validation

---

## Sub-Phase 7: LLM Integration Reliability

**Why**: No retries, no backoff, no circuit breaker. Single LLM failure kills entire agent run.

### 7.1 Add retry with exponential backoff to all LLM calls

Adjudicator, triage, researcher, verifier all fail on first error. Add configurable retry (default 3 attempts with jitter).

### 7.2 Add circuit breaker pattern

If LLM fails N times consecutively, switch to fallback behavior instead of hammering the endpoint.

**Files**: `app/lib/llm.py`

### 7.3 Add request batching for adjudicator

Currently makes 1 LLM call per observation. 1000 observations = 1000 sequential calls. Batch where possible.

**Files**: `app/agents/adjudicator.py`

### 7.4 Validate LLM JSON responses with schema

Replace regex-based `_clean_json()` with Pydantic schema validation for all LLM response parsing.

**Files**: `app/agents/adjudicator.py`, `app/agents/triage.py`, `app/agents/researcher.py`

### 7.5 Add bounds checking on LLM response arrays

`response.choices[0].message` accessed without bounds check in verifier. Add safe access.

**Files**: `app/agents/verifier.py`

### 7.6 Invalidate cached LLM client on credential change

`_cached_client` in `app/lib/llm.py` never invalidated if credentials rotate at runtime.

### 7.7 Sanitize observation data before prompt injection

All agents interpolate observation data (title, description, evidence_summary) directly into prompts without escaping. Use structured data serialization (JSON blocks) instead of string interpolation.

**Files**: `app/agents/adjudicator.py`, `app/agents/triage.py`, `app/agents/researcher.py`, `app/agents/coach.py`

**Estimated files touched**: ~10
**Risk**: Medium — LLM behavior changes need careful testing

---

## Sub-Phase 8: Code Deduplication & Architecture Cleanup

**Why**: Duplicated logic across files causes bugs when one copy is updated but not the other.

### 8.1 Consolidate suite inference

Exists in both `app/check_resolver.py` (lines ~489-561) and `app/checks/chain.py` (lines ~163-227) with slightly different patterns. Extract to shared utility.

### 8.2 Consolidate service merging

`app/checks/runner.py` (lines ~185-211) and `app/checks/chain.py` (lines ~482-500) have different merge strategies. Unify into one function.

### 8.3 Extract chain patterns to data

`app/checks/chain.py` has 700+ lines of hardcoded chain detection rules. Move to YAML/JSON loaded at runtime so patterns can be updated without code changes.

### 8.4 Remove legacy PathsConfig

`app/config.py` has `paths.db_path` (legacy) and `storage.db_path` (new) that must be manually synced. Remove `PathsConfig` entirely.

### 8.5 Remove duplicate observation export endpoint

`/api/v1/observations/export/csv` and `/api/v1/scans/{scan_id}/observations/export/csv` do the same thing. Keep one.

### 8.6 Remove dead code

- `app/state.py`: `_last_scan_id` — no references in codebase
- `app/scenario_services/ai/rag.py`: `get_all_customer_data()` — never called
- Scenario config module-level caching with no invalidation mechanism

### 8.7 Flatten preferences `on_critical_*` fields

7 nearly-identical fields (`on_critical_network`, `on_critical_web`, `on_critical_ai`, `on_critical_mcp`, `on_critical_agent`, `on_critical_rag`, `on_critical_cag`) that differ only by suite name. Replace with `on_critical_overrides: dict[str, str | None]`.

**Estimated files touched**: ~20
**Risk**: Medium — structural changes need comprehensive testing

---

## Sub-Phase 9: Test Suite Hardening

**Why**: 0% coverage on 4 critical agents (2,378 LOC combined). Heavy mock usage hiding real integration bugs. No concurrency tests.

### 9.1 Create tests for untested agents

| Agent | LOC | Current coverage |
|-------|-----|-----------------|
| `app/agents/verifier.py` | 459 | 0% |
| `app/agents/chainsmith.py` | 1,103 | 0% |
| `app/agents/researcher.py` | 572 | 0% |
| `app/agents/coach.py` | 244 | 0% |

### 9.2 Add LLM failure mode tests

- Rate limiting (429)
- Timeouts
- Malformed JSON responses
- Model unavailability mid-scan
- Fallback model failure

### 9.3 Add concurrency tests

- Parallel checks accessing shared context
- Simultaneous DB writes
- Concurrent scan start requests (race condition)

### 9.4 Fix test isolation

Global `_default_db` swapping needs proper cleanup on test failure. Add assertion that connections are released.

### 9.5 Add integration tests

Full scan pipeline: discover → check → observe → verify → adjudicate → triage.

### 9.6 Rename legacy test files

`test_check_runner_findings.py` still references "findings" in filename.

### 9.7 Unify test model imports

Some tests use `base.Observation`, others use `models.Observation`. Standardize on one.

**Estimated files touched**: ~25 new/modified test files
**Risk**: Low — tests don't change production code

---

## Sub-Phase 10: Scenario System Cleanup

**Why**: Terminology mismatch between JSON schema and code, silent failures in simulation loading, hardcoded data inconsistencies.

### 10.1 Align scenario JSON schema with code

`fakobanko/scenario.json` uses `"findings"` key but code in `scenario_services/common/config.py` expects `"observations"`. Pick one, apply everywhere.

### 10.2 Fix silent simulation load failures

`app/scenarios.py:277-281` appends errors to description string instead of raising or returning them properly. Make failures visible to the operator.

### 10.3 Add atomic session file writes

Replace bare `open()` + `json.dump()` in `_save_session()` with temp file + atomic rename pattern.

**Files**: `app/scenario_services/common/config.py`

### 10.4 Fix hardcoded data inconsistencies

- `banking/api.py` and `banking/tools.py`: `total_branches: 47` but only 4 branches in code
- `config.py`: Hallucinations hardcoded `H01-H20`, not configurable
- `simulated_check.py`: Service construction doesn't validate port range (1-65535)

### 10.5 Fix rate limit bypass logic in chatbot

`chatbot.py:117-122`: IP cleanup and rate check happen *before* X-Forwarded-For override. Wrong IP gets checked.

### 10.6 Add scenario config validation

Validate that observation names in scenario JSON files match registered check output names. Flag mismatches at load time, not silently at runtime.

**Estimated files touched**: ~12
**Risk**: Low-Medium — scenario changes need manual verification

---

## Execution Order & Dependencies

```
Sub-Phase 1 (Foundations)
    |
    +---> Sub-Phase 2 (Rename)
    |         |
    +---> Sub-Phase 3 (Error Handling) ---+
    |         |                           |
    +---> Sub-Phase 4 (Concurrency)       |
              |                           |
              v                           v
         Sub-Phase 5 (Database)     Sub-Phase 7 (LLM)
              |                           |
              v                           v
         Sub-Phase 6 (API)          Sub-Phase 8 (Dedup)
              |                           |
              +-------------+-------------+
                            |
                            v
                   Sub-Phase 9 (Tests)
                            |
                            v
                   Sub-Phase 10 (Scenarios)
```

Sub-phases that share no file overlap can be parallelized.

---

## Issue Count by Sub-Phase

| Sub-Phase | Issues | Severity Breakdown |
|-----------|--------|-------------------|
| 1. Foundations | 12 | 2 critical, 4 high, 6 medium |
| 2. Rename | 7 | 1 critical, 3 high, 3 medium |
| 3. Error Handling | 20+ | 3 high, 10+ medium, rest low |
| 4. Concurrency | 10 | 2 critical, 4 high, 4 medium |
| 5. Database | 18 | 3 critical, 6 high, 9 medium |
| 6. API | 12 | 1 critical, 4 high, 7 medium |
| 7. LLM | 14 | 3 critical, 5 high, 6 medium |
| 8. Dedup | 12 | 0 critical, 3 high, 9 medium |
| 9. Tests | 15 | 4 critical gaps, 6 high, 5 medium |
| 10. Scenarios | 10 | 1 critical, 3 high, 6 medium |
