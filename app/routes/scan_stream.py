"""
app/routes/scan_stream.py - Phase 51.2: per-scan SSE stream endpoint.

GET /api/v1/scans/{scan_id}/stream   (scoped; 404 on unknown id)
GET /api/v1/scan/stream              (unscoped alias; resolves current scan)

Each connection:
  1. Emits an initial `snapshot` event with the session's current state so
     late joiners render immediately without waiting for the next change.
  2. Subscribes to ScanSession.event_bus and forwards each published
     ScanEvent as a named SSE event.
  3. Emits an SSE comment heartbeat (`: keepalive`) every 15s while idle so
     reverse-proxy idle timeouts don't kill the connection. The heartbeat
     is a comment, not a named event, so browser `onmessage` handlers
     don't wake up for it.
  4. Closes when the session's bus closes (after terminal + TTL grace in
     51.2b) or when the client disconnects.

Last-Event-ID replay (hot ring + DB-backed) lands in 51.3; for now the
snapshot is the only backfill.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.db.repositories import CheckLogRepository, ObservationRepository
from app.scan_context import resolve_session
from app.scan_events import ScanEvent, SubscriberClosed
from app.scan_registry import get_registry

logger = logging.getLogger(__name__)

router = APIRouter()

HEARTBEAT_INTERVAL_S = 15.0


def _snapshot_payload(session) -> dict:
    """Shape the initial `snapshot` event payload from session state."""
    obs_count = 0
    if session.runner is not None:
        writer = getattr(session.runner, "observation_writer", None)
        if writer:
            obs_count = writer.count
    return {
        "scan_id": session.id,
        "status": session.status,
        "phase": session.phase,
        "checks_total": session.checks_total,
        "checks_completed": session.checks_completed,
        "current_check": session.current_check,
        "observations_count": obs_count,
        "error": session.error_message,
    }


def _format_sse(event: ScanEvent) -> bytes:
    """Encode a ScanEvent as a single SSE frame."""
    return (
        f"id: {event.seq}\n"
        f"event: {event.type}\n"
        f"data: {json.dumps(event.payload, default=str)}\n\n"
    ).encode("utf-8")


def _parse_last_event_id(raw: str | None) -> int | None:
    """Parse a `Last-Event-ID` header into an int seq, or None if unusable."""
    if not raw:
        return None
    try:
        seq = int(raw.strip())
    except (TypeError, ValueError):
        return None
    return seq if seq >= 0 else None


async def _db_replay_events(
    scan_id: str,
    last_seq: int,
    upper_seq: int,
    ring_events: list[ScanEvent],
) -> list[tuple[int, str, dict]]:
    """Fetch DB-backed replay rows for (last_seq, upper_seq].

    Always queries observations (never in the ring). Queries check_log only
    when the ring does not already cover the full requested range — i.e.
    when `last_seq < ring_floor` or the ring is empty. Returns a flat list
    of (seq, event_type, payload) tuples, order not guaranteed (merged by
    `_merge_replay`).
    """
    obs_repo = ObservationRepository()
    check_repo = CheckLogRepository()
    results: list[tuple[int, str, dict]] = []
    try:
        obs_rows = await obs_repo.get_events_since(scan_id, last_seq, upper_seq)
    except RuntimeError:
        # DB not initialized (CLI-only / test harness). Ring replay alone is
        # acceptable; missing observation_added events will show up via the
        # client's next polling pass.
        return results
    results.extend((seq, "observation_added", payload) for seq, payload in obs_rows)

    ring_floor = min((e.seq for e in ring_events), default=None)
    needs_check_backfill = ring_floor is None or last_seq < ring_floor - 1
    if needs_check_backfill:
        # Only fetch check rows older than ring_floor (or all of them if the
        # ring is empty) — events at or above ring_floor are already in
        # `ring_events` and `_merge_replay` would discard DB copies anyway.
        upper = (ring_floor - 1) if ring_floor is not None else upper_seq
        upper = min(upper, upper_seq)
        check_rows = await check_repo.get_events_since(scan_id, last_seq, upper)
        results.extend(check_rows)
    return results


def _merge_replay(
    scan_id: str,
    ring_events: list[ScanEvent],
    db_events: list[tuple[int, str, dict]],
) -> list[ScanEvent]:
    """Merge ring and DB replay sources into a seq-ordered ScanEvent list.

    Ring entries take precedence on seq collisions (they carry the original
    ts_ns from live publish). DB-only events get a synthesized ts_ns of 0
    — the design doc treats ts_ns as diagnostic, not a replay cursor.
    """
    by_seq: dict[int, ScanEvent] = {e.seq: e for e in ring_events}
    for seq, event_type, payload in db_events:
        if seq in by_seq:
            continue
        by_seq[seq] = ScanEvent(
            seq=seq,
            type=event_type,
            scan_id=scan_id,
            ts_ns=0,
            payload={"scan_id": scan_id, **payload},
        )
    return [by_seq[s] for s in sorted(by_seq)]


async def _stream(
    session, last_event_id: int | None = None
) -> "asyncio.AsyncIterator[bytes]":
    """Generator that yields SSE-framed bytes for one subscriber.

    On connect: emit `snapshot`, then replay any events with
    `seq > last_event_id` so tab-refresh reconnects resume without a gap.
    Replay has two tiers (design §4):
      - Ring (51.3a): status/phase/check events, bounded to ~50 entries.
      - DB (51.3b): always supplies `observation_added` (never in the ring),
        and backfills check events older than `ring_floor` when the client's
        `Last-Event-ID` predates the ring.
    """
    bus = session.ensure_event_bus()
    # Subscribe first so any event published *during* replay setup lands in
    # the live queue; then snapshot the ring. Events published in the gap
    # appear in both the ring and the live queue — we dedup by tracking
    # `replayed_max` and skipping live events with seq <= that watermark.
    sub = bus.subscribe()
    # Bound DB replay to events that existed at subscribe time. Anything
    # published after this point comes in via the live subscription, so we
    # must not replay it from the DB or we'd double-emit.
    upper_seq = session.event_seq
    ring_events: list[ScanEvent] = []
    db_events: list[tuple[int, str, dict]] = []
    if last_event_id is not None:
        ring_events = bus.events_since(last_event_id)
        db_events = await _db_replay_events(
            session.id, last_event_id, upper_seq, ring_events
        )
    # Initial snapshot — seq 0 so it sorts before any live events.
    snapshot = ScanEvent(
        seq=0,
        type="snapshot",
        scan_id=session.id,
        ts_ns=ScanEvent.now_ns(),
        payload=_snapshot_payload(session),
    )
    yield _format_sse(snapshot)
    # Merge ring + DB replay, ordered by seq. Ring entries win on seq
    # collisions — they are the original live events, complete with ts_ns.
    merged = _merge_replay(session.id, ring_events, db_events)
    replayed_max = last_event_id if last_event_id is not None else 0
    for event in merged:
        yield _format_sse(event)
        if event.seq > replayed_max:
            replayed_max = event.seq

    try:
        while True:
            try:
                event = await asyncio.wait_for(sub.get(), timeout=HEARTBEAT_INTERVAL_S)
            except asyncio.TimeoutError:
                # Heartbeat keeps the TCP connection alive through proxies.
                yield b": keepalive\n\n"
                continue
            except SubscriberClosed:
                return
            if event.seq <= replayed_max:
                # Already emitted via ring replay; skip the dupe.
                continue
            yield _format_sse(event)
    finally:
        sub.close()


def _require_session_for_stream(scan_id: str | None, *, for_path: bool):
    if for_path:
        session = get_registry().get(scan_id) if scan_id else None
        if session is None:
            raise HTTPException(404, f"Scan '{scan_id}' not found")
        return session
    session = resolve_session(scan_id)
    if session is None:
        raise HTTPException(404, "No scan available to stream")
    return session


# SSE responses must disable buffering on upstream proxies. `X-Accel-Buffering`
# is nginx-specific; Caddy/Traefik honor the `Cache-Control: no-cache` hint.
_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


@router.get("/api/v1/scans/{scan_id}/stream")
async def stream_scan_scoped(
    scan_id: str,
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
):
    """Scoped SSE stream for the named scan (404 if unknown)."""
    session = _require_session_for_stream(scan_id, for_path=True)
    last_seq = _parse_last_event_id(last_event_id)
    return StreamingResponse(
        _stream(session, last_seq),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


@router.get("/api/v1/scan/stream")
async def stream_scan_unscoped(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
):
    """Back-compat alias: streams the current non-terminal scan by default."""
    session = _require_session_for_stream(scan_id, for_path=False)
    last_seq = _parse_last_event_id(last_event_id)
    return StreamingResponse(
        _stream(session, last_seq),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )
