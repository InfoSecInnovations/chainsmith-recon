# Concurrent Scans Overhaul

**Status:** Design / pre-implementation
**Size:** Major refactor. Touches 15+ files, 58+ references to the global `state` singleton.
**Motivator:** Today Chainsmith runs **one scan at a time, globally**. All live scan state lives in a single `AppState` instance in `app/state.py` (58 references across 15 files). This is a hard architectural limit, not a config option — and it's increasingly visible to users, operators, and module authors.

---

## 1. Why this needs doing

- **Operator experience.** A consultant running checks against two clients should be able to scan both simultaneously. Today they can't; the second `POST /api/v1/scan` returns 409.
- **CI/CD use case.** Enterprise-tier features call for CI/CD pipelines triggering scans per-PR or per-deploy. Many concurrent pipelines → many concurrent scans. Single-scan is a hard blocker for that tier's value prop.
- **Swarm orchestration.** Core already has swarm agents; distributed scanning implies the coordinator handling multiple scans at once, but the coordinator currently feeds into the same singleton state.
- **Module Phase 1 (terminal dashboard).** The module papers over the singleton by not taking a scan-id. If concurrency ships, the module can be taught `--scan <id>`. No concurrency → UI lies.
- **Test reliability.** Singleton state means every test that starts a scan must reset global state, and parallel test runs are impossible. Concurrency-capable code is also easier to test.

## 2. Current architecture (what we're changing)

```
HTTP request ─▶ routes/scan.py ─▶ asyncio.create_task(run_scan(state, ...))
                                         │
                 ┌───────────────────────┴──────────────────────┐
                 │                                              │
            AppState singleton                         CheckLauncher runner
            (app/state.py)                             (state.runner)
                 │
                 ├── status, phase, error_message
                 ├── active_scan_id  (pointer to DB row)
                 ├── target, exclude, techniques
                 ├── checks_total/completed/statuses/skip_reasons
                 ├── chain_status, adjudication_status, triage_status, chainsmith_status
                 ├── settings (rate_limit, parallel)
                 ├── runner (the CheckLauncher instance)
                 └── guardian, proof_settings
```

Key properties:
- `state = AppState()` at module scope — one instance per process.
- `_scan_lock = asyncio.Lock()` + `state.status == "running"` check in `start_scan` enforces the single-scan invariant.
- Every route that reports live progress (`/scan`, `/scan/checks`, `/scan/log`, `/chains`, `/adjudication`, `/chat`, `/compliance`) reads from `state` directly, not keyed by scan id.
- **The DB is already concurrency-ready.** Scans are keyed by `scans.id` in `app/db/models.py`, and `state.active_scan_id` is the "which DB row does this in-memory state reflect" pointer. Post-scan routes (`scan_history`, export) are already scan-id-addressed. Only *live* state is singleton.

## 3. Target architecture

```
HTTP request ─▶ routes/scan.py ─▶ ScanRegistry.start(...) ─▶ ScanSession(id, ...)
                                         │                            │
                                         │                            ├── asyncio.Task (the runner)
                                         │                            ├── status, phase
                                         │                            ├── check_statuses, skip_reasons
                                         │                            ├── runner (CheckLauncher)
                                         │                            ├── guardian, proof_settings
                                         │                            ├── pause_event, cancel_requested
                                         │                            └── settings snapshot
                                         ▼
                             ScanRegistry (process-scoped)
                             ├── dict[scan_id, ScanSession]
                             ├── list/query by status
                             ├── concurrency cap (config)
                             └── lifecycle (start / cancel / reap)
```

**Core invariants:**
- One `ScanSession` per active scan. Lifetime is `start → running → (paused ⇄ running) → (complete | cancelled | error)`. After terminal state, session lingers in the registry for a configurable TTL (e.g., 5 minutes) so late status polls get 200 not 404, then is reaped.
- Routes take `scan_id` as a path or query parameter: `GET /api/v1/scans/{scan_id}` — and a convenience `GET /api/v1/scans/current` that returns the most-recently-started live scan for single-scan UIs.
- `AppState` shrinks to **process-global** things only: default settings, the scope-being-prepared-for-next-scan, guardian factory config. Per-scan fields move onto `ScanSession`.

## 4. Scope of changes

### 4.1 New modules

- `app/scan_session.py` — `ScanSession` class; owns everything currently on `AppState` that's per-scan.
- `app/scan_registry.py` — `ScanRegistry` class; the process-wide dict/manager; exposes `start`, `get`, `list`, `cancel`, `reap_completed`.

### 4.2 `app/state.py` — shrink

Remove from `AppState`: `active_scan_id`, `_last_scan_id`, `status`, `phase`, `error_message`, `runner`, `checks_total`, `checks_completed`, `current_check`, `check_statuses`, `skip_reasons`, `chain_status`, `adjudication_status`, `triage_status`, `chainsmith_status`, `engagement_id`, `guardian`.

Keep on `AppState`: `session_id`, `target` (pre-scan scope prep), `exclude`, `techniques`, `settings` (defaults), `proof_settings` (default template). These represent "operator's current working scope intent," not "the running scan."

### 4.3 Routes — change signatures

All 15 files with `from app.state import state` need inspection.  Mechanical mapping:

| Today | Tomorrow |
|---|---|
| `state.status` | `session.status` (where `session` is looked up from registry by id) |
| `state.runner.checks` | `session.runner.checks` |
| `state.active_scan_id` | `session.id` |
| routes with no scan_id | accept `scan_id` param; default to `registry.current()` for back-compat |

**Back-compat strategy:** add `scan_id` as an optional parameter to every live-scan route. When absent, fall back to the registry's "current" (most-recently-started non-terminal) scan. Existing single-scan clients (the web UI) keep working without code changes on day one, then get upgraded in a follow-up to pass scan_id explicitly.

### 4.4 Runner (`app/engine/scanner.py`)

`run_scan(state, ...)` → `run_scan(session, ...)`. Same logic, reads and writes go to the session object. Guardian is per-session. Observation writer is per-session (already keyed on scan_id in DB).

### 4.5 Chat, advisor, adjudication, chains, triage, chainsmith

Each of these reads `state.<foo>_status` and `state.active_scan_id` to know "what am I working against". Each becomes scan-scoped: either explicitly take `scan_id` in their route, or derive from `registry.current()`.

The complication: the *chat* system is conversational — a single session can span multiple scans ("hey, re-run that, and tell me if the CSP thing changed"). Chat sessions need a lifetime decoupled from scans. Likely: `chat_session_id` becomes first-class, and chat messages optionally reference a `scan_id`. `ChatMessage` already has a nullable `scan_id`-adjacent field (currently `engagement_id`, being removed); repurpose.

### 4.6 Frontend

The web UI (`static/scan.html`) assumes singleton today. Concurrency phases for the UI:

1. **Phase A (no UI change):** concurrency exists server-side; web UI silently tracks `registry.current()` like before. Multiple scans can run via API/CLI; web UI shows one.
2. **Phase B (scan selector):** add a scan-picker dropdown on `scan.html`. Remembered in localStorage.
3. **Phase C (multi-pane):** tabbed UI for watching multiple scans at once. Probably deferred unless user demand.

### 4.7 Configuration

New config knobs (`app/config.py`):
- `max_concurrent_scans` (default: 4). Reject new scans with 429 when at capacity.
- `completed_scan_ttl_seconds` (default: 300). How long to keep terminal sessions addressable.
- `rate_limit_scope` (default: `per_scan`, alt: `global`). Today's rate limiter is implicitly global because there's one scan; concurrency forces the question of whether 10 req/s means "per scan" or "across all scans." Configurable.

### 4.8 Swarm

Swarm already implicitly assumes concurrent activity (distributed agents run in parallel). Unclear how much work it does against the singleton today — audit `app/swarm/` during implementation. Likely the coordinator gains a scan-id awareness.

## 5. Resource & correctness considerations

### 5.1 Memory

Each session holds a runner + observation writer + guardian. Bound by `max_concurrent_scans` to prevent runaway memory. Reaped terminal sessions free their runners; final results are in DB.

### 5.2 Rate limiting

See §4.7 — `rate_limit_scope` configurable. Default `per_scan` because most operators don't want cross-scan interference. Ops running lots of scans against the same target can switch to `global`.

### 5.3 Guardian

Guardian enforces scope. One per session — prevents cross-scan scope bleed. Today's implicit "current scope" becomes explicit "this session's scope snapshot at start time."

### 5.4 Shared ports, proxies, external state

Some checks (e.g., a check that spins up a local proxy) may implicitly assume single-instance. Audit during implementation. Likely a short list; most checks are stateless HTTP requests.

### 5.5 Chat and advisor concurrency

Both chat and advisor today take a scan_id from `state.active_scan_id`. With concurrency, user chat messages need to reference which scan they're talking about. Simplest answer: chat sessions get pinned to at most one scan at a time; switching scans resets the pin; `ChatMessage.scan_id` records the pin at send-time.

## 6. Phasing

Breaking this into a single PR is suicidal. Phases:

| Phase | Scope | Breaking? |
|---|---|---|
| A | Introduce `ScanSession` + `ScanRegistry` alongside `state`. Start writing to both. Every route still reads from `state`. Add `scan_id` parameters as optional. | No |
| B | Flip reads: routes read from `registry.get(scan_id or registry.current())`. Remove per-scan fields from `AppState`. | Minor — API gains `scan_id` param |
| C | Allow second scan: remove the 409 in `start_scan`, add `max_concurrent_scans` check. | No |
| D | Web UI scan selector. | UI change only |
| E | Runner changes for pause/cancel + the endpoints the web UI expects (tie-in to Phase 1 module). | Fixes current 404 bugs |
| F | Chat session decoupling. | Chat API shape changes |
| G | Frontend multi-scan UI (optional). | Deferred |

Each phase is a separate PR. A-through-C are the hard architectural work; D-G are visible features.

## 7. What stays the same

- **DB schema.** Already keyed by `scan_id`; no migration needed.
- **Check implementations.** They already take their scope + target; nothing about a check cares how many scans are running.
- **Observation writer.** Already per-scan under the hood.
- **Report generation.** Already scan-id-addressed.
- **Export formats.** Unchanged.

## 8. Risks

1. **Cross-cutting subtle bugs.** 58 references to `state.*` means it's easy to miss one. Mitigation: after phase B, grep for `state.status`, `state.runner`, etc. — they should be zero in `app/routes/` and `app/engine/`.
2. **Chat UX.** Chat-scan binding is a real UX design question, not a code change. Likely needs a short standalone design memo during phase F.
3. **Swarm unknowns.** Need to audit swarm code before claiming concurrency works for distributed scanning. Start with a limited test: "two concurrent local-only scans succeed end-to-end."
4. **Third-party modules.** Once the Module API ships, modules may have grabbed the singleton `state`. Concurrency must ship *before* the module system is widely adopted or modules pin to the old shape. **Sequence this refactor before module-system v1.0.**

## 9. Non-goals

- Distributed / multi-process scan execution (that's swarm's job)
- Priority queues for pending scans (queue full = 429; caller retries)
- Inter-scan data sharing (each scan is independent)
- Changes to check internals

## 10. Definition of done

- Two concurrent scans complete successfully end-to-end, targeting different domains.
- Every route that reports live scan state accepts an optional `scan_id` parameter and returns 404 if the id is unknown.
- `registry.current()` back-compat path keeps the web UI functional without UI changes (Phase A-C).
- `max_concurrent_scans` cap enforced with 429.
- Web UI scan selector works (Phase D).
- Pause/resume/stop endpoints exist and are wired to the runner's cooperative pause mechanism (Phase E; also unblocks terminal dashboard module).
- No reference to `state.status`, `state.runner`, `state.active_scan_id`, etc. remains in `app/routes/` or `app/engine/` (Phase B done).
- Tests can spin up N sessions in parallel.

## 11. Open questions

1. **Is `active_scan_id` already being phased out?** The `state.py` docstring says "Phase 31: points routes to current scan in DB." There may be existing migration intent we should align with — check `docs/future-ideas/completed/phase31-db-as-source-of-truth.md` before starting.
2. **Should `ScanRegistry` be a singleton or DI-injected?** Injected is cleaner for testing but means plumbing it through. Singleton is pragmatic. Start singleton, refactor if testing pain emerges.
3. **Chat session identity.** Does a chat session persist across Chainsmith restarts? If yes, chat DB already has the right shape. If no, in-memory is fine. Check existing chat persistence.
4. **Sequencing vs. module system.** This refactor should probably land *before* the module system is widely adopted (see §8.4). Worth making that dependency explicit in the module-system-design doc.
