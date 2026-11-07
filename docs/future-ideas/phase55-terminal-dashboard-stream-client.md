# Phase 55 — Terminal Dashboard SSE Stream Client

**Status:** Ready. The server side exists (`app/routes/scan_stream.py`).
**Track:** Modules
**Depends on:** phase 51 scan-state streaming, which has landed ([`completed/phase51-scan-state-streaming.md`](completed/phase51-scan-state-streaming.md))
**Unblocks:** [`module-terminal-dashboard.md`](module-terminal-dashboard.md)
**Size:** S
**Last reviewed:** 2026-10-11

---

## 1. Why this is its own phase

Originally tracked as sub-phase 51.5 inside `completed/phase51-scan-state-streaming.md`.
Extracted because:

- 51.1–51.4 are backend + web-UI work and are all done.
- 51.5 is a **consumer migration inside a module that does not exist yet**.
  Leaving it inside phase 51 blocks phase 51's definition-of-done on an
  unrelated future module.
- Making it a standalone phase lets it be scheduled as a prerequisite of
  `module-terminal-dashboard.md` rather than a trailing task of 51.

## 2. Scope

Build the SSE client plumbing the terminal dashboard module will consume, so
that when the terminal-dashboard module is implemented it can ship with streaming support
from day one (behind a `--stream` flag, flipped to default once stable).

Concretely:

1. A reusable async SSE client for `GET /api/v1/scans/{scan_id}/stream` that
   handles `Last-Event-ID` reconnects, heartbeat comments, and the event types
   enumerated in `completed/phase51-scan-state-streaming.md` §3.
2. A thin adapter that exposes the same message surface as the planned
   polling client in `module-terminal-dashboard.md` §7, so the
   dashboard's widget layer is transport-agnostic.
3. A `--stream` CLI flag spec for `chainsmith watch` (opt-in at first, default
   after bake-in), mirroring the web UI's capability-gated opt-in in 51.4.

## 3. Relationship to the terminal-dashboard module

`module-terminal-dashboard.md` §4.2 already anticipates this:

> **Recommendation:** ship the module with **polling first**, adopt SSE via
> `--stream` flag once phase 51 is stable.

That recommendation is now promoted to a **hard prerequisite**: the terminal-dashboard module
will not begin implementation until phase 55 lands the stream client, so the
module ships with both transports at once and avoids a post-ship rewrite of
its data layer.

## 4. Definition of done

- Reusable SSE consumer exists and has unit tests against fixture event streams.
- Client honors `Last-Event-ID` on reconnect and surfaces heartbeat/idle signals.
- `--stream` flag spec is finalized and referenced from
  `module-terminal-dashboard.md` §4.2.
- module-terminal-dashboard.md updated to mark phase 55 as a
  prerequisite rather than an internal sub-step.
