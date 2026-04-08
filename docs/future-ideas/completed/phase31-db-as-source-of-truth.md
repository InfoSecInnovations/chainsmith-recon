# Phase 31 — DB as Source of Truth

Migrate from global mutable state to the database as the authoritative store
for scan results. State becomes a thin progress tracker; all result data
(observations, chains, adjudication, check logs) flows through the DB.

This resolves Phase 27 item 6 and unblocks safe concurrent scans for swarm
mode.


## Current Architecture

```
Check.run()
  -> CheckLauncher accumulates observations in a list
  -> run_scan() assigns list to state.observations
  -> state.status = "complete"
  -> on_scan_complete() bulk-inserts to DB (fire-and-forget)

Routes:
  GET /observations        -> reads state.observations (in-memory)
  GET /observations?scan_id=X -> reads from DB (historical only)
```

**Problems:**
1. No locking — concurrent scans obliterate each other's data.
2. If the process crashes mid-scan, all observations are lost (not in DB yet).
3. Routes have a dual-read pattern (state vs DB) that complicates every
   endpoint and creates two code paths to maintain.
4. State holds ~50 mutable fields with no isolation between scans.


## Target Architecture

```
Check.run()
  -> CheckLauncher calls persist_observation() per observation
  -> DB is immediately queryable
  -> State tracks: scan_id, progress counters, status

Routes:
  GET /observations        -> reads from DB using state.active_scan_id
  GET /observations?scan_id=X -> reads from DB (same code path)
```

**Principles:**
- One code path for reading results: always the DB.
- State holds only what the DB can't serve efficiently: live progress,
  current check name, runner reference.
- Observations are durable the moment they're produced.
- Concurrent scans are isolated by scan_id.


## Design


### 1. Streaming Persistence

Today, `on_scan_complete()` does a single `bulk_create()` after the scan
finishes. Replace this with incremental writes during scan execution.

**CheckLauncher changes:**

```python
class CheckLauncher:
    def __init__(self, ..., scan_id: str, observation_writer: ObservationWriter):
        self.scan_id = scan_id
        self.observation_writer = observation_writer

    async def _run_check(self, check, context):
        result = await check.run(context)
        for obs in result.observations:
            obs_dict = self._prepare_observation(obs)
            await self.observation_writer.write(self.scan_id, obs_dict)
        ...
```

**ObservationWriter** — thin abstraction over `ObservationRepository`:

```python
class ObservationWriter:
    """Streams observations to the database during scan execution."""

    def __init__(self, repo: ObservationRepository, batch_size: int = 10):
        self._repo = repo
        self._buffer: list[dict] = []
        self._batch_size = batch_size
        self._count = 0

    async def write(self, scan_id: str, observation: dict) -> None:
        self._buffer.append(observation)
        self._count += 1
        if len(self._buffer) >= self._batch_size:
            await self.flush(scan_id)

    async def flush(self, scan_id: str) -> None:
        if self._buffer:
            await self._repo.bulk_create(scan_id, self._buffer)
            self._buffer = []

    @property
    def count(self) -> int:
        return self._count
```

**Why batched, not per-row:**
Individual inserts per observation would create excessive DB round-trips
during fast checks (port scans, header checks). Batching every 10
observations balances durability with throughput. A crash loses at most 9
observations, not thousands.

**Flush points:**
- Every `batch_size` observations (default 10).
- After each check completes (in `on_check_complete` callback).
- On scan completion (final flush).
- On scan error (flush what we have before recording failure).


### 2. Slim Down AppState

State keeps only what routes need for **live progress polling** — things
that change rapidly and aren't worth querying the DB for on every poll.

**Fields that stay in state (progress tracking):**

| Field | Purpose |
|-------|---------|
| `active_scan_id` | Points routes to the current scan in DB |
| `target` | Scope configuration for active session |
| `exclude` | Scope exclusions |
| `techniques` | MITRE technique filters |
| `status` | "idle" / "running" / "complete" / "error" |
| `phase` | "idle" / "scanning" / "done" |
| `error_message` | Error detail when status = "error" |
| `checks_total` | Total checks to run |
| `checks_completed` | Completed count (for progress %) |
| `current_check` | Name of currently executing check |
| `check_statuses` | Per-check status dict (for /scan/checks) |
| `runner` | CheckLauncher/SwarmRunner reference |
| `settings` | Parallel, rate_limit, default_techniques |
| `engagement_id` | Links scan to engagement |
| `session_id` | Unique per reset |
| `proof_settings` | Proof-of-scope config |
| `scope_checker` | Scope validation |

**Fields that move to DB-only (removed from state):**

| Field | Replacement |
|-------|-------------|
| `observations` | `ObservationRepository.get_observations(scan_id)` |
| `chains` | `ChainRepository.get_chains(scan_id)` |
| `check_log` | `CheckLogRepository.get_log(scan_id)` |
| `adjudication_status` | Column on Scan record |
| `adjudication_results` | `AdjudicationRepository.get_results(scan_id)` |
| `adjudication_error` | Column on Scan record |
| `advisor_recommendations` | New: `AdvisorRecommendation` table via `AdvisorRepository` |
| `chain_status` | Column on Scan record |
| `chain_error` | Column on Scan record |
| `chain_llm_analysis` | Column on Scan record or separate table |


### 3. Scan Record as Status Hub

Extend the Scan DB model to carry status fields that currently live in state.
This lets routes query a single record for both progress and phase status.

**New columns on Scan:**

```python
class Scan(Base):
    ...
    # Existing
    status: str              # "running", "complete", "error", "cancelled"

    # New — migrated from state
    adjudication_status: str  # "idle", "adjudicating", "complete", "error"
    adjudication_error: str | None
    chain_status: str         # "idle", "analyzing", "complete", "error"
    chain_error: str | None
    chain_llm_analysis: JSON | None
```

**Update pattern:** The engine writes these via `ScanRepository.update_status()`
as phases complete, same as it currently writes to state fields.


### 4. Route Migration

Every route currently doing the dual state-vs-DB read collapses to DB-only.

**Before (observations.py):**
```python
@router.get("/api/v1/observations")
async def list_observations(scan_id: str | None = None):
    if scan_id:
        return await repo.get_observations(scan_id)
    else:
        return state.observations  # in-memory
```

**After:**
```python
@router.get("/api/v1/observations")
async def list_observations(scan_id: str | None = None):
    sid = scan_id or state.active_scan_id
    if not sid:
        return {"observations": [], "total": 0}
    return await repo.get_observations(sid)
```

**Routes affected and changes needed:**

| Route | Current pattern | Change |
|-------|----------------|--------|
| `observations.py` | scan_id gates state vs DB | Always query DB; use `state.active_scan_id` as default |
| `chains.py` | scan_id gates state vs DB | Same. Chain status from Scan record. |
| `adjudication.py` | scan_id gates state vs DB | Same. Adjudication status from Scan record. |
| `scan.py` | STATE-ONLY for progress | Keep state for progress (status, checks_completed, current_check). Observation count from writer.count or DB. |
| `compliance.py` | STATE-ONLY | Query DB for observations/chains using active_scan_id. Keep scope fields in state. |
| `advisor.py` | STATE-ONLY | Read from `AdvisorRecommendation` table using active_scan_id. |

**Routes with no changes needed:**

| Route | Reason |
|-------|--------|
| `scan_history.py` | Already DB-only |
| `engagements.py` | Already DB-only |
| `checks.py` | No state dependency |
| `customizations.py` | File-based |
| `preferences.py` | File-based |
| `scenarios.py` | Scenario manager |
| `scope.py` | Scope config stays in state (not result data) |
| `swarm.py` | Coordinator-based |


### 5. Check Log Streaming

Check logs should also stream to DB, not accumulate in state. The same
batched writer pattern applies:

```python
class CheckLogWriter:
    async def log_event(self, scan_id: str, entry: dict) -> None:
        await self._repo.create(scan_id, entry)
```

Since check events are low-volume (one start + one complete per check),
individual inserts are fine — no batching needed.


### 6. Chain Analysis and Adjudication

These post-scan phases already write to DB via `on_adjudication_complete()`
and chain persistence. The change is:

1. Remove `state.chains`, `state.adjudication_results` accumulation.
2. Write directly to DB during analysis (already mostly happens).
3. Update `Scan.chain_status` / `Scan.adjudication_status` on the DB record
   instead of state fields.
4. Routes read from DB always.


### 7. Concurrent Scan Safety

With scan_id as the key, concurrent scans are naturally isolated:

- Each `POST /api/v1/scan` creates a new scan_id.
- Observations are keyed by scan_id in DB.
- Routes resolve scan_id from either query param or `state.active_scan_id`.

**Remaining single-tenancy in state:** `state.active_scan_id` still assumes
one "current" scan. For full multi-tenancy (multiple active scans), state
would need to become a `dict[scan_id, ScanProgress]`. This is a future
concern — the DB migration makes it possible but doesn't require it.

**Swarm compatibility:** Swarm workers submit results via the swarm
coordinator API. The coordinator can use the same `ObservationWriter` to
persist results as they arrive, keyed by scan_id. No architectural conflict.


## Migration Plan

### Wave 1: Streaming Persistence (foundation) ✓
1. ✓ Created `ObservationWriter` and `CheckLogWriter` in `app/db/writers.py`.
2. ✓ Scratch-space fallback on DB failure (`~/.chainsmith/scratch/<scan_id>/`).
3. ✓ `CheckLauncher` accepts optional `ObservationWriter`, streams per-observation.
4. ✓ `run_scan()` creates writers and passes to launcher.
5. ✓ `state.observations` still populated (backward compat).
6. ✓ `on_scan_complete()` skips bulk observation/check_log inserts when writers used.
7. ✓ 17 new tests (writers + launcher integration).

### Wave 2: Schema Extension ✓
1. ✓ Added status columns to Scan model (`adjudication_status`, `chain_status`, etc.).
2. ✓ Created `AdvisorRecommendation` table with `scan_id` FK.
3. ✓ Created Alembic migration 005.
4. ✓ `run_adjudication()` and `run_chain_analysis()` write status to Scan record.
5. ✓ `_run_scan_advisor()` writes to `AdvisorRecommendation` table.
6. ✓ State fields kept in parallel (backward compat).
7. ✓ `ScanRepository.update_scan_status()` added for targeted field updates.
8. ✓ `AdvisorRepository` with `bulk_create()` and `get_recommendations()`.
9. ✓ `_scan_to_dict()` includes new fields. `delete_scan()` cascades to new tables.

### Wave 3: Route Migration ✓
1. ✓ Migrated `observations.py` to DB-only reads via `_resolve_scan_id()`.
2. ✓ Migrated `chains.py` to DB-only reads. Chain status from Scan record.
3. ✓ Migrated `adjudication.py` to DB-only reads. Adjudication status from Scan record.
4. ✓ Migrated `compliance.py` export endpoint to use DB queries for observations/chains.
5. ✓ Migrated `advisor.py` to use `AdvisorRecommendation` table.
6. `scan.py` observation count stays in state (progress polling — removed in Wave 4).

### Wave 4: State Cleanup ✓
1. ✓ Removed `state.observations`, `state.chains`, `state.check_log`,
   `state.adjudication_results`, `state.adjudication_error`,
   `state.chain_error`, `state.chain_llm_analysis`, `state.advisor_recommendations`.
2. ✓ Kept `state.chain_status` and `state.adjudication_status` as concurrency guards
   (prevent concurrent execution of post-scan phases).
3. ✓ Engines read observations from DB, accumulate results locally, persist directly.
4. ✓ `on_scan_complete` no longer persists observations/chains/check_log (handled by writers/engines).
5. ✓ `on_adjudication_complete` accepts results as parameter instead of reading from state.
6. ✓ Route POST guards check DB for observations instead of state.
7. ✓ `/scan/log` reads from `CheckLogRepository`. `/scan` obs count from writer.
8. ✓ Tests updated (1654 pass).

### Wave 5: Tooling and Swarm ✓
1. ✓ `scratch-to-db` CLI command: imports scratch observations, deduplicates by fingerprint,
   cleans up on success. Supports `--all`, `--dry-run`, `--keep` flags.
2. ✓ `scratch-list` CLI command: lists scratch directories awaiting import.
3. ✓ Swarm coordinator wired to `ObservationWriter` — observations stream to DB
   as agents report results via `complete_task()` (now async).
4. ✓ Scanner passes `obs_writer` to coordinator in swarm mode.
5. ✓ Concurrent scan isolation: each scan gets its own scan_id, writer, and DB partition.
6. ✓ All 1654 tests pass.


## Decisions (resolved)

1. **Graceful degradation — scratch-space fallback.** If the DB becomes
   unreachable mid-scan, write remaining observations to a scratch directory
   (`~/.chainsmith/scratch/<scan_id>/`). The scan continues but no new checks
   launch after the DB error is detected. The user is notified that results
   are in scratch space. A `scratch-to-db` CLI tool imports scratch files
   into the DB once it's back, so checks don't need to be re-run.

   This gives us DB-as-truth under normal conditions while preserving the
   "don't lose work" property of the old fire-and-forget approach.

   **Scratch directory layout:**
   ```
   ~/.chainsmith/scratch/<scan_id>/
     metadata.json          # scan_id, target, started_at, error reason
     observations/
       001.json             # sequentially numbered
       002.json
     check_log/
       001.json
   ```

   **scratch-to-db tool:** Reads the scratch directory, calls the same
   `ObservationRepository.bulk_create()` and `CheckLogRepository.bulk_create()`
   used by normal persistence, then deletes the scratch directory on success.
   Idempotent — uses observation fingerprints to skip duplicates if some
   observations made it to DB before the failure.

2. **Advisor recommendations — separate table.** `AdvisorRecommendation`
   table with `scan_id` FK. Enables querying recommendations across scans
   (e.g., "which recommendations keep recurring?").

3. **Check log streaming — confirmed.** Write "started" events immediately,
   "completed" events (with observation count) when the check finishes.
   No batching needed given low volume.

4. **Query performance — tracked in performance tuning doc.** See
   `docs/future-ideas/performance-tuning.md`. Primary concern is observation
   queries replacing in-memory list access. Mitigated by existing `scan_id`
   index. Monitor if scan sizes grow past thousands.

5. **Progress polling — stays in state.** Confirmed. Only result data moves
   to DB.


## Dependencies

- Alembic migration for new Scan columns (Wave 2).
- Tests need updating across all affected routes (Waves 3-4).
- Swarm coordinator changes are independent and can proceed in parallel
  after Wave 1.


## What This Does NOT Change

- Scope configuration (`state.target`, `state.exclude`, etc.) stays in state.
  These are session config, not result data.
- Check registry, scenarios, preferences, customizations — unaffected.
- The fingerprinting and comparison logic — already DB-based, no change.
- The observation data model — same fields, same schema, just written earlier.
