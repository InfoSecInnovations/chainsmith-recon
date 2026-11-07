> **Snapshot from 2026-09-10; kept for reference.** Current status lives in [`../README.md`](../README.md).
> Since this was written: F-5 is resolved (the framework selector was never built and is now listed as Ready),
> and F-2's "Phase D not started" is wrong. The scan selector exists on two pages; see
> [`../concurrent-scans.md`](../concurrent-scans.md).

# Doc Status Audit — 2026-09-10

**Scope:** every non-completed doc in `docs/future-ideas/` (21, excluding phase 57 itself).
**Method:** status headers and stated prerequisites checked against the code. Status verdicts only —
no content rewrites. Docs marked *header-only* were not verified against the code; their claims may
still be stale.
**Why:** Phase 57's §16 found that `concurrent-scans-overhaul.md` claimed pre-implementation status
for work that had landed, while every module-track doc listed it as a blocker. That was not an
isolated slip.

---

## 1. Headline findings

### F-1 — Two concurrent-scans docs, two incompatible phase letterings

`concurrent-scans-design.md` and `concurrent-scans-overhaul.md` both letter their phases A, B, C —
**differently** — and different docs cite different ones:

- `module-system-design.md` and the three module-phase docs cite **`concurrent-scans-design.md` Phases A–C**.
- `concurrent-scans-swarm.md` cites **`concurrent-scans-overhaul.md` Phase B**.
- The *code* uses a third lettering again: `app/state.py` says *"Phase B … shrinks AppState"* (that is
  A5 in the design doc), and `app/scan_registry.py` says *"Phase C enforces the max_concurrent_scans cap."*
  Session memory also refers to a **Phase F** (chat decoupling) that neither doc defines.

Consequence: *"have A–C landed?"* is unanswerable from the docs, which is why the module track's gate
status went unnoticed. **Recommendation:** retire the letters. Track concurrent-scans by capability,
and merge the two docs or mark one explicitly as the successor.

### F-2 — By capability, concurrent scans is substantially landed

| Capability | State |
|---|---|
| `ScanContext` / `ScanRegistry` exist | ✅ `app/scan_context.py`, `app/scan_registry.py` (107 lines) |
| `AppState` shrunk to operator scope | ✅ `app/state.py` down to 57 lines |
| Per-scan runtime state on a session | ✅ `app/scan_session.py` (186 lines) |
| Routes resolve by `scan_id` | ✅ `app/routes/scan.py` |
| Concurrency cap enforced | ✅ `max_concurrent_scans: int = 4` (`app/config.py:119`), 429 over cap (`app/routes/scan.py:87-107`) |
| Scoped control endpoints | ✅ `POST /api/v1/scans/{scan_id}/pause|resume|stop` (`app/routes/scan.py:214-230`), unscoped aliases retained |
| `scan_id` threaded into chat/advisor/adjudication/chains/observations | ✅ present in all five route modules |
| **`POST /api/v1/scope` removed, scope inline on `/scan`** | ❌ **not done** — see F-3 |
| Phase D (UI) | ❌ not started; the D0 design doc was never written |

`app/scan_registry.py:9` still says *"Until then the registry is observational"* — stale; routes read
from it authoritatively.

### F-3 — Live bug: concurrent scans read global scope mid-run

`concurrent-scans-design.md` §5 decided that `POST /api/v1/scan` takes scope inline and
`POST /api/v1/scope` is removed. That did not happen — `POST /api/v1/scope` still exists
(`app/routes/scope.py:45`) and scope prep is still a process-global singleton.

`app/routes/scan.py` snapshots `target` / `exclude` / `techniques` onto the `ScanSession` at creation,
but **`run_scan()` then ignores that snapshot and re-reads the global `state`** during the run:

- `app/engine/scanner.py:190` — `techniques=state.techniques` (check selection)
- `app/engine/scanner.py:210-212` — `scope_domains`, `excluded_domains`, `base_domain` (the scan context
  *and* the compliance record)
- `app/engine/scanner.py:439` — `session_id=state.session_id`

With `max_concurrent_scans` defaulting to **4**, changing scope while a scan is running rewrites the
running scan's scope context and its compliance record. This is not a documentation problem.

#### F-3a — Investigation findings (2026-09-10)

**What is protected.** Most checks subclass `ServiceIteratingCheck`, whose `run()` calls `is_in_scope()`
per service (`app/checks/base.py:513`) against `session.guardian`. Guardian is correctly snapshotted
per scan, so a wrong context cannot make these probe out of scope — they block and log.

**What is not.** The three checks that read `context["base_domain"]` / `scope_domains` directly —
`network_dns_enumeration`, `network_dns_records`, `network_port_scan` — are direct `BaseCheck`
subclasses with no `is_in_scope()` call. They trust the context. They are also the **seed phase**:
`port_scan` populates `context["services"]` for everything downstream. So the failure shape is a
genuine out-of-scope DNS/port sweep against another scan's domain, followed by a scan full of
`scope_blocked` errors as Guardian correctly rejects the rest.

**The trigger needs no race.** The CLI is a thin API client: `app/cli.py:235` calls
`client.set_scope(...)` → `POST /api/v1/scope` (`app/cli_client.py:65-72`), then starts the scan. Two
concurrent invocations interleave as `A.set_scope → B.set_scope → A.start_scan`, so scan A is *created*
with B's target. The two-step global-scope flow is not concurrency-safe by construction.

**Also found:** `session.proof_settings` was passed by reference (not copied like `settings`) and read
by nothing; `on_scan_start` wrote `target_domain` from global state into the durable DB row; and the
compliance report took no `scan_id` at all.

#### F-3b — Fix status

**Fix (1) — landed 2026-09-10.** `run_scan()` now resolves the `ScanSession` first and reads scope only
from it (`app/engine/scanner.py`); `on_scan_start()` takes the session (`app/db/persist.py`);
`proof_settings` is deep-copied (`app/routes/scan.py`); new `ScanSession.operator_session_id`; the
compliance report accepts `scan_id` and reports that scan's own scope. Regression tests in
`tests/scanning/test_scan_scope_isolation.py`. Suite: 2255 passed, 5 skipped; ruff clean.

**Fix (2) — outstanding.** Scope must move inline onto `POST /api/v1/scan` and `POST /api/v1/scope` must
go, per `concurrent-scans-design.md` §5. Until then the CLI interleave above can still create a
mis-scoped session at request time — fix (1) does not close it. **Interim mitigation:
`max_concurrent_scans: 1`.**

**Fix (3) — landed 2026-09-10, phase 57.2.** The counterpart gap the F-3a note left open: traffic and
violation records carried no scan id, so a compliance report aggregated across every concurrent scan
no matter which one it claimed to describe. `TrafficEntry` and `ViolationEntry` now carry `scan_id`;
`Guardian` carries the scan it is gating and stamps its window violations; `get_entries`,
`get_violations`, `generate_report` and the two `/api/v1/compliance/*` read routes all filter by it.
An unscoped read still aggregates, which is the right answer for a workspace-wide review. Tests in
`tests/core/test_proof_scan_scoping.py`. Note `TrafficLogger.log_request` still has no callers —
traffic logging was never wired to the HTTP client, and wiring it is separate work.

**Still open beyond fix (2):** `violation_logger` / `traffic_logger` are process singletons writing one
`violations_log.jsonl` / `traffic_log.jsonl` with no `scan_id` per record, so compliance *statistics*
still aggregate across concurrent scans even though the scope half of the report is now correct.
Tracked in `phase57-evidence-and-capture.md` 57.2.

### F-4 — The module track's gate is open

Every module doc lists concurrent-scans A–C as blocking. Per F-2 the substance has landed, and the
remaining gaps (F-3, Phase D/UI) do not block the module API, which takes `scan_id` regardless. The
module track is **unblocked**, and has been for some time.

Note also that `module-system-design.md`'s banner still lists *"Engagements port as reference
implementation (§10)"* as future work. Engagements were removed in Phase 52 and are not returning —
Phase 57 §5.4 uses workspaces instead. That reference implementation needs replacing or deleting.

### F-5 — Half a paired item shipped

`compliance-framework-selector.md` reads *"Ready to implement (co-implement with
compliance-framework-badges.md)"*. The badges doc is in `completed/`. The selector needs re-checking:
either it shipped alongside and the doc is stale, or it was dropped and the pairing note is now wrong.

---

## 2. Per-doc status

| Doc | Header claims | Verdict |
|---|---|---|
| `concurrent-scans-design.md` | Draft / RFC | **Stale — largely implemented.** See F-2. Lettering conflicts with the overhaul doc (F-1) |
| `concurrent-scans-overhaul.md` | Design / pre-implementation | **Stale — largely implemented.** Describes `AppState` as a 58-reference singleton; it is 57 lines |
| `concurrent-scans-swarm.md` | Design / pre-implementation; depends on overhaul Phase B | **Prerequisite met in substance** (session-scoped reads exist). Work itself genuinely pending. Re-express the dependency without letters |
| `module-system-design.md` | Partially superseded by phase 56; prereq design A–C | **Prereq satisfied (F-4).** §10 engagements reference is dead |
| `module-phase-1-terminal-dashboard.md` | Pending; needs A–C, module system, phase 55 | **Concurrent-scans prereq satisfied.** Still blocked on module system + phase 55 |
| `module-phase-2-scan-reporter.md` | Pending; same prereqs | Same as above |
| `module-phase-3-scope-wizard.md` | Pending; same prereqs | Same, **plus** its `--apply` rework depends on the inline-scope change that never landed (F-3) |
| `phase32-nist-cui-hardening.md` | Design — open questions resolved | Genuinely pending. **Now load-bearing for `phase57-evidence-and-capture.md` O-3 / D-1** (evidence encryption) |
| `phase38-non-deterministic-sampling.md` | Absorbed banner added | **Absorbed by `phase58-ai-grading.md` §4 / 58.3.** Done |
| `phase47-raw-check-io-capture.md` | Absorbed banner added | **Absorbed by `phase57-evidence-and-capture.md` §5 / 57.2.** Done. Obsolete Alembic step flagged in the banner |
| `phase46-fakobanko-semantic-cache.md` | *(no status header)* | Header-only. Genuinely pending as far as reviewed |
| `phase48-oversight.md` | *(no status header)* | Header-only. Overlaps Phase 56's contract work — re-scope against what 56 delivered |
| `phase49-observability.md` | *(no status header)* | Header-only. Overlaps Phase 51 (streaming) and Phase 57 §12 (provenance) — re-scope |
| `phase54-swarm-enhancements.md` | Design / backlog; depends swarm + phase 51 | **Phase 51 prereq is met** (51 is in `completed/`). Swarm prereq still open |
| `phase55-terminal-dashboard-stream-client.md` | Pending; phase 51 done through 51.4 | **Accurate.** Best-maintained header in the folder |
| `compliance-framework-selector.md` | Ready to implement | **Needs re-check (F-5)** — its pair shipped |
| `guardian-interactive-approval.md` | *(none)* | Header-only. Premise (Phase 42 hard gate) still holds |
| `performance-tuning.md` | *(none)* | Notes, not a phase. No status header needed |
| `schema-migration-tooling.md` | *(none)* | Header-only; premise verified — Alembic **is** gone, `create_all` is the authority. **Relevant to 57.1's new evidence table** |
| `future-improvements.md` | *(none)* | Backlog list. Phase 57 O-4 adds swarm evidence capture to it |
| `next-steps.txt` | *(none)* | Needs Phase 57 at the front; 38 and 47 marked absorbed |

---

## 3. Recommended actions

1. **Triage F-3 first.** It is a live correctness issue, not documentation.
2. Decide the concurrent-scans doc merge (F-1) and drop phase letters in favour of capabilities.
3. Update the two concurrent-scans status headers, and the stale comment at `app/scan_registry.py:9`.
4. Mark the module track unblocked; replace the engagements reference implementation (F-4).
5. Add pointer headers to `phase38` and `phase47` naming Phase 57 as their home.
6. Re-check `compliance-framework-selector.md` (F-5).
7. Give every future-ideas doc a status header. Seven have none, which is how this drift started.
8. Re-scope `phase48` and `phase49` against what Phase 56 and Phase 51 already delivered.

---

## 4. Actions completed 2026-09-10

- **Item 1 (F-3 triage)** — investigated (F-3a) and fix (1) landed (F-3b). Fix (2) outstanding.
- **Item 5** — absorbed banners added to `phase38` and `phase47`.
- **Phase 57 split** — the combined doc became `phase57-evidence-and-capture.md`,
  `phase58-ai-grading.md`, and `lab-edition.md`; the original carries a SUPERSEDED banner and is safe to
  delete once reviewed.

Items 2, 3, 4, 6, 7, 8 remain open.
