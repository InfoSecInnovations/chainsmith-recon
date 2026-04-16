# Phase 54 — Swarm Enhancements

**Status:** Design / backlog
**Depends on:** concurrent-scans-swarm.md (coordinator session-scoping), phase51-scan-state-streaming.md (in-process event bus)
**Motivator:** Collect deferred swarm work that becomes relevant once swarm
moves beyond in-process execution or scales past its current topology.

This phase is an umbrella: each section below is a candidate sub-phase. Pick
off individually based on operator demand. Nothing here is blocking the
current single-process swarm.

---

## 54.1 Cross-process event bus

**Problem.** Phase 51's `ScanEventBus` lives in-process. If swarm agents ever
run in a separate process (subprocess worker pool, remote worker, container
per agent), they can't publish `check_started` / `check_completed` /
`observation_added` into the parent's bus, so SSE subscribers on the web UI
would go silent for swarm-executed work.

**Today.** Swarm agents run in-process and share `app/scan_registry.py` +
the in-memory bus, so this works. Don't build anything yet.

**When to revisit.** When any swarm deployment mode puts agents outside the
API process.

**Sketch of options:**
- **Redis pub/sub** on topic `scan:{scan_id}`. Parent subscribes, swarm
  workers publish. Adds a Redis dependency but standard-issue.
- **DB polling tail.** Workers write events to an `events` table; parent
  tails it and fans out to SSE subscribers. No new infra but higher latency.
- **gRPC/HTTP callback.** Each worker posts events to the parent over a
  local socket. Simple, no broker, but parent must be reachable from workers.

Recommend Redis if a broker already exists in the deployment; DB tail if
not, since it reuses the DB that already stores observations.

---

## 54.2 Swarm OPSEC envelope

Topology-aware rate limiting, jitter, and source-IP rotation across swarm
agents. Today agents share the scan's OPSEC settings but don't coordinate
pacing globally — N agents on the same target can spike traffic beyond the
operator's intended rate. Requires a shared token bucket or coordinator-side
dispatch throttle.

---

## 54.3 Swarm telemetry and agent health

Per-agent metrics (checks completed, error rate, latency, last-heartbeat)
surfaced in the UI. Needed once operators run swarm in anger and want to
spot a wedged agent. Depends on 54.1 for cross-process visibility.

---

## 54.4 Swarm agent failure recovery

If an agent crashes mid-check, the check is currently lost from that scan.
Add re-dispatch with a retry budget and a terminal "agent lost" observation
so operators see what happened. Requires task-state tracking in the
coordinator that survives agent restarts.

---

## 54.5 Heterogeneous agent capabilities

Let agents advertise which check suites / tools they can run (e.g. only
agents with nmap installed take nmap tasks; only agents in a specific
network segment take internal-network checks). Coordinator becomes a
capability-matching dispatcher instead of round-robin.

---

## Risks

- **Scope creep.** This doc is an umbrella; resist implementing all sections
  at once. Each needs its own design pass and a real operator requirement.
- **Broker dependency.** 54.1 likely introduces Redis or equivalent. Ensure
  the in-process path remains the default so single-box deployments don't
  need a broker.

---

## Definition of done

Per sub-phase; no aggregate DoD. This file exists to keep swarm follow-ups
discoverable instead of scattered across other phase docs.
