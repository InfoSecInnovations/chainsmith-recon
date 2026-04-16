# Phase 55 — Terminal Dashboard SSE Stream Client

**Status:** Design / pending implementation
**Depends on:**
- Phase 51 (scan state streaming) — DONE through 51.4
- `module-phase-1-terminal-dashboard.md` **has NOT shipped**; this phase is a
  **prerequisite dependency that must land before the module is built**, so
  the module's initial polling client can be swapped for (or shipped alongside)
  an SSE client with a `--stream` flag.
**Unblocks:** `module-phase-1-terminal-dashboard.md`

---

## 1. Why this is its own phase

Originally tracked as sub-phase 51.5 inside `phase51-scan-state-streaming.md`.
Extracted because:

- 51.1–51.4 are backend + web-UI work and are all done.
- 51.5 is a **consumer migration inside a module that does not exist yet**.
  Leaving it inside phase 51 blocks phase 51's definition-of-done on an
  unrelated future module.
- Making it a standalone phase lets it be scheduled as a prerequisite of
  `module-phase-1-terminal-dashboard.md` rather than a trailing task of 51.

## 2. Scope

Build the SSE client plumbing the terminal dashboard module will consume, so
that when module-phase-1 is implemented it can ship with streaming support
from day one (behind a `--stream` flag, flipped to default once stable).

Concretely:

1. A reusable async SSE client for `GET /api/v1/scans/{scan_id}/stream` that
   handles `Last-Event-ID` reconnects, heartbeat comments, and the event types
   enumerated in `phase51-scan-state-streaming.md` §3.
2. A thin adapter that exposes the same message surface as the planned
   polling client in `module-phase-1-terminal-dashboard.md` §7, so the
   dashboard's widget layer is transport-agnostic.
3. A `--stream` CLI flag spec for `chainsmith watch` (opt-in at first, default
   after bake-in), mirroring the web UI's capability-gated opt-in in 51.4.

## 3. Relationship to module-phase-1

`module-phase-1-terminal-dashboard.md` §4.2 already anticipates this:

> **Recommendation:** ship the module with **polling first**, adopt SSE via
> `--stream` flag once phase 51 is stable.

That recommendation is now promoted to a **hard prerequisite**: module-phase-1
will not begin implementation until phase 55 lands the stream client, so the
module ships with both transports at once and avoids a post-ship rewrite of
its data layer.

## 4. Definition of done

- Reusable SSE consumer exists and has unit tests against fixture event streams.
- Client honors `Last-Event-ID` on reconnect and surfaces heartbeat/idle signals.
- `--stream` flag spec is finalized and referenced from
  `module-phase-1-terminal-dashboard.md` §4.2.
- module-phase-1-terminal-dashboard.md updated to mark phase 55 as a
  prerequisite rather than an internal sub-step.
