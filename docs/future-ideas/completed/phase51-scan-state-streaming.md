# Phase 51 — Scan State Streaming (SSE)

**Status:** Design / pending implementation
**Depends on:** concurrent-scans-overhaul Phase E (scoped scan control endpoints)
**Unblocks:** module-phase-1-terminal-dashboard (reactive mode), future chat/advisor push paths

---

## 1. Motivation

Today every live-scan consumer — web UI, the planned terminal dashboard module,
any future CLI watcher — polls `GET /api/v1/scan` (and companions) at 500ms–1s
intervals to detect state changes. That is:

- **Wasteful.** Most polls return the same bytes. At N concurrent scans with M
  watchers each, the poll fanout grows as N·M.
- **Latent.** A check that finishes 50ms after the last poll isn't visible for
  another ~950ms. The UI feels laggy even when the backend is snappy.
- **Hard to extend.** Adding observation-level live updates means *more* poll
  endpoints and more diffing logic on the client.

A single Server-Sent Events (SSE) stream per scan replaces the poll fanout with
an event push: the server emits one event per state change, watchers listen.

## 2. Non-goals

- WebSockets. SSE is one-way (server → client), which is exactly what this is.
  WebSockets would add protocol complexity for no benefit.
- Replacing polling endpoints. Polls stay as the fallback and for non-browser
  callers that don't want an event loop.
- Pushing chat deltas through the same stream. Chat already has its own SSE
  path (`app/engine/chat.py::sse_manager`); this phase stays focused on scan
  state. Unifying them is a later consideration (see §7).

## 3. Endpoint shape

```
GET /api/v1/scans/{scan_id}/stream    # scoped (preferred)
GET /api/v1/scan/stream               # back-compat alias → current scan
```

Response: `text/event-stream`. Connection stays open until the scan reaches a
terminal status and a final `scan_complete` event flushes, or the client
disconnects.

### Event types

Each event carries a JSON body:

| Event           | Payload                                                                 | Fires on                                      |
|-----------------|-------------------------------------------------------------------------|-----------------------------------------------|
| `snapshot`      | `{status, phase, checks_total, checks_completed, current_check, ...}`   | Once on connect, for late joiners             |
| `status_changed`| `{status, phase}`                                                       | `session.status` or `session.phase` transition|
| `check_started` | `{name, suite}`                                                         | `on_check_start` callback                     |
| `check_completed`| `{name, success, observations}`                                        | `on_check_complete` callback                  |
| `check_skipped` | `{name, reason}`                                                        | When a skip reason is recorded                |
| `observation_added`| `{id, severity, host, check}`                                        | Per-observation write (hook into `ObservationWriter`) |
| `scan_complete` | `{status, observations_count, duration_s}`                              | Terminal state (complete/error/cancelled)     |
| `heartbeat`     | `{}` (empty)                                                            | Every 15s while idle, to keep proxies open    |

Event id is a **monotonic per-session sequence** (int, starts at 1, incremented
on every publish). Clients reconnect with `Last-Event-ID` and receive a replay
of any events with a higher sequence. Wall-clock is carried separately in the
payload (`ts_ns`) for display/ordering diagnostics; it is **not** used as the
replay cursor — wall clocks can jump backwards (NTP), sequences cannot.

**Envelope:** every event payload includes `scan_id` at the top level. The
stream is scan-scoped today (one connection = one scan), so the field is
redundant in 51. It is included for forward-compat with the unified
`SseManager` in §7, which will multiplex topics over one connection and needs
`scan_id` as the demux key. Paying ~20 bytes/event now avoids a breaking wire
change later.

**Heartbeat format:** emit as an SSE comment (`: keepalive\n\n`), not a named
event. It keeps the TCP connection open through proxy idle timeouts without
waking the client's `onmessage` handler.

**Ordering:** event delivery is best-effort per-scan. In particular,
`observation_added` events from `ObservationWriter` may interleave with
`check_completed` from the scanner callback rather than strictly preceding it.
See future-improvements.md for the revisit.

**Capability advertisement:** both `GET /api/v1/scan` (unscoped/current) and
`GET /api/v1/scans/{scan_id}/status` (scoped) responses gain a
`capabilities: {stream: true|false}` field. The scoped variant is required so
concurrent-scan UIs can decide per-scan whether to open an `EventSource`
rather than inferring from the current scan's capabilities. UI opens an
`EventSource` only when `stream` is true; otherwise it stays on the polling
path. A dedicated `/api/v1/capabilities` endpoint is deferred to
future-improvements.md.

**Single tenant:** no per-subscriber auth beyond scan-id scoping. Chainsmith
is single-tenant today; revisit if/when that changes.

## 4. Implementation sketch

Per-session publisher on `ScanSession`:

```python
# app/scan_session.py
event_queue: asyncio.Queue | None = None  # lazy-constructed on first subscriber
event_log: collections.deque[Event] = field(...)  # hot ring buffer, ~50 events
```

### Replay strategy (hybrid: hot ring + DB)

`observation_added` payloads can number in the thousands for large scans;
buffering all of them in memory is a perf hit. Use a two-tier replay:

- **Hot ring buffer (~50 events, in-memory):** holds status/phase transitions,
  `check_started`, `check_completed`, `check_skipped`, `scan_complete`. Fast
  path for typical reconnects (tab refresh, brief network blip).
- **DB-backed replay for deeper history:** on reconnect with a `Last-Event-ID`
  older than the ring's oldest entry, query `observations` and `check_log`
  WHERE `event_seq > last_event_id AND scan_id = ?` and synthesize
  `observation_added` / `check_completed` / `check_started` / `check_skipped`
  events from those rows.

  **Schema additions (no migration — system is not yet in use):**
  - Add `event_seq INTEGER` column to `observations` and `check_log`, populated
    at insert from the scan's monotonic sequence (same counter that stamps
    live events, so ring and DB share one id space).
  - Add compound index `(scan_id, event_seq)` on both tables for replay
    queries.

  **Live ↔ replay mapping:** `check_log.event` is the source of truth for
  `check_started`/`check_completed`/`check_skipped`; there is no explicit
  `success` boolean — success is `event == 'completed'` (fail is
  `event == 'failed'`). Codify this mapping in a single
  `CheckLog.to_sse_event()` helper shared by the live publisher and the
  replay path so the two cannot drift.

`observation_added` events are *never* stored in the ring — they always replay
from the DB. This keeps ring memory bounded regardless of scan size and gives
the DB as single source of truth for observation history.

Serializer shared between live-publish and replay paths to avoid drift.

- `scanner.run_scan` already calls `on_check_start`/`on_check_complete` — wrap
  those to also publish SSE events.
- `ObservationWriter.write` publishes `observation_added`.
- `mark_terminal` publishes `scan_complete`.
- The route handler (`/api/v1/scans/{scan_id}/stream`) subscribes to the
  session's queue, sends `snapshot` first, replays the ring buffer for late
  joiners (matching `Last-Event-ID`), then streams new events until the scan
  terminates + TTL grace window.

**Terminal TTL grace window:** after a scan reaches a terminal status, keep
the event bus alive for **30 seconds** so late reconnects (tab refresh,
network blip) still get `snapshot` with the final state and the trailing
`scan_complete` event. After 30s the bus is torn down; reconnects after that
fall back to REST for final state.

Keep the publisher decoupled via a thin pub/sub: one `ScanEventBus` per
session owns subscriber queues; `ScanSession` only holds the bus reference.
Fan-out to multiple subscribers is O(subscribers); unsubscribe on client
disconnect.

## 5. Client migration

**Web UI (`static/scan.html`):** opt-in. Keep polling as default; add a feature
flag in `app/config.py` (`scan_stream.enabled`, default false) and let the UI
open an `EventSource` when the server advertises support via a capability
field. No UI redesign — same widgets, different data source.

**Terminal dashboard module:** ship with polling first (module-phase-1 §4.2
already bakes this assumption). Once SSE is stable, add the reactive path
behind a `--stream` flag, then flip the default once bake-in confirms.

## 6. Phases

| Phase | Scope                                                                              | Breaking? |
|-------|-----------------------------------------------------------------------------------|-----------|
| 51.1  | `ScanEventBus`, event types, publisher hooks in `scanner.py` + `ObservationWriter`| No        |
| 51.2  | `GET /api/v1/scans/{scan_id}/stream` + unscoped alias; snapshot + heartbeat       | No        |
| 51.3  | `Last-Event-ID` replay via per-session ring buffer                                | No        |
| 51.4  | Web UI opt-in `EventSource` path, fallback to polling on error                    | No        |

Each sub-phase is a separate PR. 51.1–51.3 are the backend; 51.4 is the web-UI
consumer migration. The terminal-dashboard SSE client migration is tracked
separately in `phase55-terminal-dashboard-stream-client.md` as a prerequisite
of `module-phase-1-terminal-dashboard.md`.

## 7. Interaction with existing SSE (chat)

`app/engine/chat.py::sse_manager` is a chat-session-scoped SSE path. Scan
streaming is scan-scoped. They are distinct streams with distinct lifetimes
and do not share infrastructure in this phase.

**Future consideration (not in 51):** unify under a single `SseManager` class
that multiplexes topics (`chat:{session_id}`, `scan:{scan_id}`) over one
process-wide bus. Only worth doing once we have a third consumer.

## 8. Risks

1. **Proxy/load-balancer buffering.** Some reverse proxies buffer
   `text/event-stream` by default; the heartbeat mitigates disconnects. Ship
   docs noting this for nginx/Caddy/Traefik deployments.
2. **Backpressure.** A slow subscriber can stall the event queue. Bound each
   subscriber's queue to ~1000 events; on overflow the server **closes the
   connection**. The browser `EventSource` auto-reconnects with
   `Last-Event-ID`, which drops into the normal DB-backed replay path and
   restores state. No dedicated `resync` event type — reusing the reconnect
   path keeps the protocol small and exercises the same code as transient
   network drops.
3. **Test reliability.** SSE tests are flakier than polling tests; use
   `httpx.AsyncClient` with explicit read timeouts and small-event fixtures.
4. **Cross-process scans (swarm).** If swarm ever runs scans in a separate
   process, the in-memory `ScanEventBus` can't reach them. Swarm agents
   currently run in-process and share `app/scan_registry.py`, so this works
   today. Tracked in phase54-swarm-enhancements.md (cross-process event bus).

## Implementation status (as of 2026-04-15)

- **51.1a — DONE.** `app/scan_events.py` (ScanEventBus/Subscription/ScanEvent),
  `ScanSession.event_seq`/`next_seq()`/`ensure_event_bus()`,
  `tests/core/test_scan_events.py`.
- **51.1b — DONE.** `event_seq` column + `(scan_id, event_seq)` compound index
  on `ObservationRecord` and `CheckLog`. `CheckLog._SSE_EVENT_TYPE` and
  `CheckLog.to_sse_event()` are the single live/replay mapping. Repos pass
  `event_seq` through on insert; `_check_log_to_dict` exposes it.
  Tests in `tests/db/test_db_repositories.py`.
- **51.1c — DONE.** `ScanSession.publish_event(type, payload)` is the single
  publish seam; stamps seq + builds ScanEvent + pushes on the bus and returns
  the seq so callers stamp the DB row. `ObservationWriter.write`,
  `CheckLogWriter.log_event`, and `ScanSession.mark_terminal` all publish.
  Tests in `tests/core/test_writers.py::TestWriterPublishers`.
- **51.2b — DONE.** `TERMINAL_BUS_TTL_S = 30.0` and
  `ScanSession._schedule_event_bus_teardown()` in `app/scan_session.py`.
  `mark_terminal` publishes `scan_complete`, then schedules
  `event_bus.close()` via `loop.call_later(TTL, ...)`. Sync contexts with no
  running loop close the bus immediately. Tests in
  `tests/core/test_scan_session.py` cover all three branches.
- **51.2 — DONE.** `app/routes/scan_stream.py` implements the scoped
  `/api/v1/scans/{scan_id}/stream` and unscoped `/api/v1/scan/stream`
  routes with snapshot + heartbeat comment. `ScanStatus.capabilities` and
  `_status_payload` advertise `{"stream": true}`. Routers are registered in
  `app/routes/__init__.py` and `app/main.py`. Tests in
  `tests/scanning/test_scan_stream_api.py` pass: 404 paths exercise HTTP
  through `httpx.AsyncClient`; streaming-body tests drive the `_stream()`
  async generator directly because `httpx` ASGITransport does not
  propagate client disconnects for long-lived `text/event-stream`
  responses, making `client.stream()` teardown hang. The production
  route is correct under a real ASGI server (uvicorn); only the in-process
  test harness needed the workaround.

- **51.3a — DONE.** Hot ring buffer on `ScanEventBus` (`_ring`, default
  50 events, `observation_added` excluded). `events_since(last_seq)` and
  `ring_floor` expose the ring. `/api/v1/scans/{scan_id}/stream` and
  `/api/v1/scan/stream` read `Last-Event-ID` header, replay ring events
  after the snapshot, then dedup live events by tracking `replayed_max`.
  Subscribe-then-snapshot ordering closes the race between replay and
  live publish. Tests in `tests/core/test_scan_events.py` (ring
  semantics) and `tests/scanning/test_scan_stream_api.py`
  (end-to-end replay + dedup).
- **51.3b — DONE.** DB-backed replay for reconnects with `Last-Event-ID`
  older than `ring_floor` (and always for `observation_added`, which is
  never in the ring). `ObservationRepository.get_events_since()` and
  `CheckLogRepository.get_events_since()` use the `(scan_id, event_seq)`
  indexes; `CheckLog.to_sse_event()` keeps the live/replay mapping single.
  `_stream()` captures `upper_seq = session.event_seq` at subscribe time
  to bound DB replay, then `_merge_replay()` unions ring + DB by seq (ring
  wins on collisions) and emits between snapshot and live.
- **51.4 — DONE.** `ScanStreamConfig.enabled` (default false) gates
  `capabilities.stream` in `_status_payload` (`app/routes/scan.py`). YAML key
  `scan_stream.enabled` and env `CHAINSMITH_SCAN_STREAM_ENABLED` wire the
  flag. `static/scan.html` reads `capabilities.stream` from the initial
  status response; when true it opens an `EventSource` on
  `/api/v1/scans/{id}/stream` and debounces event notifications into the
  existing `pollStatus()` refresh path (same widgets, event-driven trigger).
  Transport errors fall back to 500ms polling; terminal `scan_complete`
  closes the stream cleanly. Selecting a different scan or stopping the
  scan tears down both paths via `stopLiveUpdates()`.
- **51.5 — EXTRACTED.** Terminal dashboard `--stream` flag is now tracked as
  its own phase in `phase55-terminal-dashboard-stream-client.md` and is a
  prerequisite of `module-phase-1-terminal-dashboard.md`, not a trailing task
  of phase 51.

**Next-session starter moves:**
1. Start 51.3b — DB-backed replay for reconnects older than `ring_floor`.
   Add `ObservationRepository.get_events_since(scan_id, last_seq, upper_seq)`
   and `CheckLogRepository.get_events_since(scan_id, last_seq, upper_seq)`
   (both using the existing `(scan_id, event_seq)` composite index).
   Merge sort by seq, emit between snapshot and ring replay in `_stream()`.
2. Start 51.4 — Web UI opt-in `EventSource` path gated on
   `capabilities.stream` from `/api/v1/scan` or the scoped status endpoint.

## 9. Definition of done

- `GET /api/v1/scans/{scan_id}/stream` emits the event types in §3 in order.
- Snapshot replay works for reconnects via `Last-Event-ID`.
- Web UI works unchanged with streaming disabled; with it enabled, updates are
  visibly snappier (<100ms typical) and polling stops.
- Heartbeat keeps connections alive through typical reverse-proxy timeouts.
- No regression in the polling endpoints; fallback path is tested.
