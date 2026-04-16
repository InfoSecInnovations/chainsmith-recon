# Concurrent Scans — Swarm Coordinator

**Status:** Design / pre-implementation
**Depends on:** `concurrent-scans-overhaul.md` Phase B (session-scoped reads)
**Motivator:** The swarm coordinator currently assumes a single `AppState`. Concurrent scans require it to be session-scoped before distributed swarm execution is safe to run in parallel.

This memo was split out during the Phase A audit of the concurrent-scans overhaul (see §4.8 and §8.3 of that doc). Phase A's dual-write scaffolding does **not** change swarm behavior; this is the follow-up.

---

## Audit findings (as of Phase A landing)

Swarm touches state from two files:

**`app/swarm/coordinator.py`:**
- Constructor already receives `AppState` by DI (`self.state`), not the module-level singleton. Good.
- Reads `state.target` directly in `create_tasks_from_plan` (lines ~161–164, ~202) to build the per-task scan context.
- Mutates `self.state.checks_completed` and `self.state.check_statuses[...]` inside `complete_task` (lines ~345–378) as swarm agents report results.
- Has an `observation_writer` attribute set by `run_scan` and used during task completion. Already per-scan (writer is constructed per scan).

**`app/swarm/runner.py`:**
- Docstring references `state.runner.checks`. Its actual code uses the `coordinator` + an injected `checks` list. The runner itself does not import `state`.

Net: swarm is already closer to session-scoped than the rest of the codebase. The coordinator takes state via DI; nothing grabs the module singleton.

## What Phase B+ needs to change

### 1. Coordinator accepts `ScanSession` instead of `AppState`

Flip the constructor parameter. `state.target` → `session.target`, `state.checks_completed` → `session.checks_completed`, `state.check_statuses` → `session.check_statuses`. Since container identity is preserved in Phase A (session and state share the `check_statuses` dict reference), this change is mechanically small.

### 2. Coordinator must support multiple concurrent task pools

Today `get_coordinator()` returns a process-wide singleton. With N concurrent scans, each needs its own task plan, its own pending/in-flight bookkeeping, and its own observation writer.

Two options:

- **Per-scan coordinators.** `get_coordinator()` becomes `get_coordinator(session)` or the registry owns a coordinator per session. Simpler mental model; slightly more memory per scan.
- **Single coordinator, multi-tenant.** Coordinator maintains task queues keyed by scan_id. Agents pull from whichever scan has the oldest ready task. Better for shared agent pools; more complex state.

Recommendation: **per-scan coordinators** for the first concurrent-swarm release. It matches the per-scan ScanSession model and keeps the blast radius of swarm bugs limited to a single scan. Revisit if operators run many concurrent swarm scans against shared agent pools.

### 3. Agent dispatch needs scan awareness

Agents currently poll the coordinator and receive tasks. With multiple coordinators (option A) or multi-tenant tasks (option B), each task must carry its `scan_id` so the agent's response routes back to the right observation writer.

The `Task` model (`app/swarm/models.py`) should gain a `scan_id` field if it does not already have one. Audit during implementation.

### 4. Agent capacity vs. concurrency cap

`cfg.swarm.max_agents` and `cfg.concurrency.max_concurrent_scans` interact. If max_agents=50 and max_concurrent_scans=4, an operator expects ~12 agents per scan under full load. The coordinator layer should either:

- Evenly share agents across active scans, or
- First-come-first-served, with a per-scan agent reservation (e.g., `cfg.swarm.min_agents_per_scan`).

Defer the policy decision until someone actually runs multiple concurrent swarm scans in production. Ship with naive first-come behavior and document it.

## Non-goals

- Changing the swarm protocol between coordinator and agents. Task JSON shape stays the same aside from the `scan_id` field.
- Cross-scan task stealing, priority queues, or fairness scheduling.
- Distributed coordinator (multi-process). Still one coordinator per process.

## Sequencing

Land after Phase B of the main overhaul (once routes read from sessions, not `state`). Before Phase C's `max_concurrent_scans` enforcement is turned on in swarm mode, this must be done — otherwise a second swarm scan will silently mangle the first one's state.

## Open questions

1. Does `Task` already carry `scan_id`? (Audit before starting implementation.)
2. Does `get_coordinator()` hold any state that would break if called twice with different sessions in the same process?
3. Should a swarm scan hold a coordinator even after it completes (for post-scan diagnostics) or reap immediately?
