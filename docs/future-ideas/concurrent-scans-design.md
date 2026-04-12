# Concurrent Scans Design

**Status:** Draft / request-for-comment
**Purpose:** Enable Chainsmith to run multiple scans simultaneously, as a prerequisite to the module system work. Today `app/state.py` is a module-level singleton; "the" scan is a global concept that leaks across 18 files. This design replaces that singleton with a per-scan context, introduces a scan pool + queue, and migrates subsystems (chat, advisor, triage, adjudication, chains) to be scan-aware.

**Relationship to module work:** Module system work (`module-system-design.md`, `module-phase-1/2/3-*.md`) is blocked on Phases A-D of this plan. Module API contracts must be designed concurrent-aware from day one even though A-C are the minimum runtime prerequisite; D (UI) can land in parallel with module work once A-C are done.

---

## 1. Goals

- Run N scans concurrently, bounded by hardware-derived default, user-overridable.
- Per-scan scope, state, and lifecycle — no shared "current scan" concept.
- Queue overflow: additional scan requests queue rather than reject.
- Subsystems (chat, advisor, triage, adjudication, chains) operate against a specific scan, not "the" scan.
- Backwards-compatible during the refactor: existing single-scan UX works at every intermediate phase.

## 2. Non-goals

- **Scan checkpointing / resume across restart.** Deferred to enterprise-tier daemon mode; out of scope here.
- **Multi-user auth / RBAC.** Core concern, handled separately; this design leaves a nullable `owner` hook for it.
- **Distributed scan execution** (multiple machines). Swarm is check-level, not scan-level; unrelated axis.
- **Horizontal scaling.** Single-process concurrency only.

---

## 3. Core concept: `ScanContext`

Today `app/state.py` exposes module-level `state.status`, `state.pause_event`, `state.stop_requested`, `state.scope`, etc. Eighteen files reach into it directly. This design replaces that with an explicit object:

```python
# app/scan_context.py
@dataclass
class ScanContext:
    scan_id: str
    scope: ExtendedScopeInput
    status: ScanStatus               # queued | running | paused | completed | cancelled | failed
    pause_event: asyncio.Event
    stop_requested: bool
    started_at: datetime | None
    owner: str | None = None         # future auth hook; None during single-operator era
    # observations, check results, etc. — everything that was on state.*
```

A `ScanRegistry` holds live contexts keyed by `scan_id`. Subsystems take `scan_id` (or the `ScanContext` directly) as a parameter instead of reading from the module-level singleton.

---

## 4. Phasing

14 shippable increments. Each sub-phase leaves the system working and tested.

### Phase A — State refactor (A1–A5)

Mechanical but wide. The system still runs one scan at a time at the end of Phase A; the point is to thread `ScanContext` through every subsystem so Phase B can have N of them.

- **A1 — Foundation.** Define `ScanContext` + `ScanRegistry`. Convert `app/engine/scanner.py`, `app/checks/runner.py`, `app/routes/scan.py`. Old `app/state.py` becomes a thin compatibility shim that reads from the registry's "current" slot (registry still holds only one context during A1–A5).
- **A2 — Observations + chains.** `routes/observations.py`, `routes/chains.py`, `engine/chains.py`.
- **A3 — Triage + adjudication.** `engine/triage.py`, `engine/adjudication.py`, `agents/triage.py`, `routes/adjudication.py`.
- **A4 — Chat + advisor.** `engine/chat.py`, `routes/chat.py`, `routes/advisor.py`. Trickiest due to conversation state — chat sessions bind to a scan at session-start time.
- **A5 — Compliance, persistence, cleanup.** `routes/compliance.py`, `db/persist.py`, remove the `state.py` shim, delete all remaining references.

**Acceptance per sub-phase:** existing test suite green; manual single-scan run still works end-to-end.

### Phase B — Multi-scan runtime (B1–B3)

- **B1 — Pool + queue.** `ScanRegistry` grows to N slots + a FIFO queue. Pool size fixed at 1 initially (no behavior change). `POST /api/v1/scan` returns immediately with `scan_id`; if all slots full, it queues and returns `status: queued`.
- **B2 — Scoped control endpoints.** New routes: `POST /api/v1/scans/{scan_id}/pause|resume|cancel`. Old unscoped endpoints (`/api/v1/scan/pause` etc.) alias to "most recently started" for back-compat; deprecated, removed later. `cancel` handles both queued (dequeue) and running (stop) — idiomatic single-action pattern.
- **B3 — Hardware-detected pool size.** On startup, `psutil`-derived recommendation: `max(1, min(cpu_count // 2, available_gb // 2))`. Log the recommendation; honor `CHAINSMITH_MAX_CONCURRENT_SCANS` env override. Default raises from 1 — **this is the first phase where user behavior actually changes.**

### Phase C — Subsystem scan-awareness (C1–C5)

A-phase threaded scan_id through; C-phase surfaces it in APIs so users can operate against specific (non-current) scans. Order by user priority:

- **C1 — Chat.** Chat session binds to `scan_id` at session open; `POST /api/v1/chat` requires `scan_id`. UI chooser lands in D.
- **C2 — Advisor.** Same pattern.
- **C3 — Triage.**
- **C4 — Adjudication.**
- **C5 — Chains.**

### Phase D — UI (D0 + D1..n)

- **D0 — Design doc.** Separate doc covering scan-list view, per-scan drill-down, scan picker pattern for chat/advisor, handling of "current scan" concept in the UI (does it go away, or become "most-recent"?), CLI UX for `chainsmith scan` when the pool is full.
- **D1–Dn — Implementation.** Scoped by D0.

D can land in parallel with module system work once A-C are done.

---

## 5. Scope endpoint semantics

Today: `POST /api/v1/scope` sets a global scope; `POST /api/v1/scan` consumes it. With per-scan scope, the global endpoint has no clean meaning.

**Decision:** `POST /api/v1/scan` takes scope inline (required). `POST /api/v1/scope` is removed. `scope-wizard` POSTs directly to `/scan`.

This breaks the existing "scope then scan" CLI flow intentionally — explaining two-endpoint stateful setup to a new user is harder than "one call, scope included."

**Migration impact:**
- `scope-wizard` (module): update `--apply` to call `/scan` with inline scope instead of `/scope` + separate scan kickoff. Worth noting the wizard can't *start* a scan without enough info; `--apply` becomes "apply and start" and needs to prompt for any scan-start-specific fields.
- Web UI: scope form submits inline with the scan-start button.
- CLI: `chainsmith scan --scope <file>` reads scope from yaml/json.

---

## 6. Rate limiting

**Per-scan, not global.** Each scan enforces its own `rate_limit` independently. Two scans against the same target at 10 rps each = 20 rps outbound — document this as a known OPSEC consideration; warn users not to run concurrent scans against the same target.

**LLM rate limiting.** Per-scan only. If two scans both hammer the LLM advisor, provider 429s may occur. Documented limitation; a shared LLM gateway with a global semaphore is a future enhancement when it becomes a real problem.

---

## 7. Swarm interaction

`app/swarm/coordinator.py` currently reads the state singleton. Swarm is in development and **allowed to break during A1–A5**; updated in a follow-up sub-phase (A6 if needed) to take `ScanContext` explicitly. Per the swarm design, distributed work is check-level inside one scan — it does not add a new concurrency axis.

---

## 8. Auth hook

`ScanContext.owner: str | None = None` lands in A1. Nullable through single-operator era. When auth/RBAC is designed (core concern, separate doc), the field is populated at scan-create from the authenticated user and subsystems can filter by owner. Adding the field now is zero-cost; retrofitting it across 18+ files later is not.

---

## 9. Known limitations

- No scan persistence across process restart — running scans die with the process. Enterprise-tier daemon mode addresses this later via checkpointing; not in scope here.
- Per-scan LLM rate limiting can hit provider 429s under concurrent advisor/triage load.
- Two concurrent scans against the same target compound rate limits; documented, not enforced.

---

## 10. Open questions

1. **Default pool size floor.** `psutil` recommendation could return 1 on tiny VPSes — is that acceptable, or force minimum of 2?
2. **Queue depth bound.** Unbounded queue, or cap (e.g. 10) and reject with 429 past that? Unbounded is simpler; bounded prevents memory runaway from a misbehaving client.
3. **Scan TTL in registry.** How long are completed `ScanContext`s kept live in the registry before only being accessible via `scan_history`? Short (minutes) keeps memory light; long (hours) makes chat/advisor sessions less surprising after a scan finishes.
4. **"Current scan" back-compat lifetime.** The old unscoped `/api/v1/scan/pause` etc. aliases in B2 — how many versions do they stick around before removal?
5. **Chat session migration.** If a chat session is bound to scan X and X completes, does the session stay bound (read-only history context) or auto-migrate to the user's next scan? D0 problem.

---

## 11. Summary

Four phases, fourteen increments. A (state refactor, 5 sub-phases) is foundational and mechanical. B (multi-scan runtime, 3 sub-phases) introduces the pool. C (subsystem scan-awareness, 5 sub-phases) exposes it to users. D (UI) gets its own design pass and can run parallel to module work.

Module system work resumes after A–C. The Module API should be designed concurrent-aware (contracts take `scan_id`) regardless of which exact phase unblocks it.
