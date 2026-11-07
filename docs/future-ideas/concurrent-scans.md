# Concurrent Scans — Remaining Work

**Status:** Partial. The core runtime has landed; three work items remain.
**Track:** Concurrency
**Depends on:** nothing open
**Blocks:** `module-scope-wizard.md` (item 1), `phase54-swarm-enhancements.md` (item 3)
**Last reviewed:** 2026-10-11 (verified against code)

This replaces three earlier docs, which are now in `superseded/`: `concurrent-scans-design.md`,
`concurrent-scans-overhaul.md` and `concurrent-scans-swarm.md`. Between them they used three different
"Phase A–D" letterings, and the code comments used them too. This doc tracks the work **by
capability** and uses no letters. The superseded docs still hold the original reasoning (memory, rate
limiting, Guardian, OPSEC), and nothing in that reasoning has changed.

---

## 1. What has landed

| Capability | Where |
|---|---|
| `ScanContext` / `ScanRegistry` | `app/scan_context.py`, `app/scan_registry.py` |
| `AppState` shrunk to operator scope | `app/state.py` |
| Per-scan runtime state on a session | `app/scan_session.py` |
| Routes resolve by `scan_id` | `app/routes/scan.py` |
| Concurrency cap, 429 when over it | `max_concurrent_scans` (default 4), `app/routes/scan.py` |
| Scoped control endpoints | `POST /api/v1/scans/{scan_id}/pause\|resume\|stop` (unscoped aliases retained) |
| `scan_id` threaded into chat, advisor, adjudication, chains, observations | the five route modules |
| `run_scan()` reads scope from the `ScanSession`, not global state | fixed 2026-09-10; `tests/scanning/test_scan_scope_isolation.py` |
| Swarm tasks carry `scan_id`; coordinator takes a `ScanSession` | `app/swarm/models.py`, `app/swarm/coordinator.py` |
| Scan selector component | `static/js/scan-selector.js`, mounted on `scan.html` and `observations.html` |

`app/scan_registry.py`'s module docstring still calls the registry "observational". That is stale:
routes read from it authoritatively.

---

## 2. Remaining work

### 2.1 Scope inline on `POST /api/v1/scan`; remove `POST /api/v1/scope`

**Why:** the CLI's two-step flow (set scope, then start the scan) is still process-global. Two operators,
or a script and an operator, can interleave and start a scan with the wrong scope. This is the residual
half of audit finding F-3 (`audits/doc-status-audit-2026-09-10.md`).

**Decision already taken** (superseded design doc, §5): `POST /api/v1/scan` takes scope inline and
requires it. `POST /api/v1/scope` is removed. This breaks the scope-then-scan flow on purpose.

- API: `POST /api/v1/scan` accepts `target`, `exclude`, `techniques`, and the rest of the scope inline.
  Delete `app/routes/scope.py`'s POST handler.
- CLI: `chainsmith scan --scope <file>` reads scope from YAML/JSON. Remove the `set_scope` call in
  `app/cli_client.py`.
- Web UI: the scope form submits with the start-scan button.
- `module-scope-wizard.md`: `--apply` becomes "apply and start".

**Interim mitigation, pending an operator decision:** set `max_concurrent_scans: 1`.

### 2.2 Finish the UI

- Mount the scan selector on every page that reads scan-scoped data, or decide that a page stays
  "most recent scan" on purpose. Today only `scan.html` and `observations.html` have it.
- Decide between **queue** and **reject** when the cap is reached. The original design wanted a queue;
  the code returns 429. Either way, the UI and `chainsmith scan` need a clear message when the pool is full.
- Decide whether "current scan" survives as a concept in the UI or becomes "most recent".

### 2.3 Per-scan swarm coordinators

`get_coordinator()` is still a process singleton (`app/swarm/coordinator.py`), and
`create_tasks_from_plan()` calls `reset()`. **A second swarm scan wipes the first one's task pool.**

- Make `get_coordinator(session)` return one coordinator per scan, owned by the `ScanRegistry`.
  The superseded swarm memo recommended this over a single multi-tenant coordinator, because it keeps a
  swarm bug's blast radius to one scan.
- Agents already receive `scan_id` on each task. Route each result to the right session's writer.
- Agent capacity across scans: start with first-come, first-served and document it. Defer fair-share
  until someone runs concurrent swarm scans in earnest.
- Until this lands, swarm mode should refuse a second concurrent scan. It should not corrupt the first one.

---

## 3. Known limitations (unchanged, documented)

- Rate limits are **per scan**. Two scans at 10 rps against the same target send 20 rps.
- LLM rate limits are per scan. Two scans that both lean on the advisor can trigger provider 429s.
