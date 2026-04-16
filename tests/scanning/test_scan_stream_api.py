"""
Phase 51.2 tests for GET /api/v1/scans/{scan_id}/stream and /api/v1/scan/stream.

404 paths exercise the HTTP layer through httpx.AsyncClient + ASGI transport.
The streaming-body tests exercise the `_stream()` async generator directly —
httpx's ASGITransport does not reliably propagate client disconnects for
long-lived `text/event-stream` responses, so driving the generator directly
is faster and deterministic. Route wiring for the streaming endpoints is
covered by the 404 tests plus the FastAPI startup import.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from httpx import ASGITransport, AsyncClient

import app.routes.scan_stream as scan_stream_module
from app.main import app
from app.routes.scan_stream import _stream
from app.scan_registry import get_registry
from app.scan_session import ScanSession

pytestmark = pytest.mark.unit


@pytest.fixture
def clean_registry():
    reg = get_registry()
    reg._reset()
    yield reg
    reg._reset()


async def _drain(session, gen, *, max_frames: int = 20, timeout: float = 1.0):
    """Collect frames from `_stream()` until the bus closes or timeout fires."""
    frames: list[bytes] = []
    deadline = time.time() + timeout
    while len(frames) < max_frames and time.time() < deadline:
        try:
            chunk = await asyncio.wait_for(gen.__anext__(), timeout=0.2)
        except asyncio.TimeoutError:
            continue
        except StopAsyncIteration:
            break
        frames.append(chunk)
    await gen.aclose()
    return frames


@pytest.mark.asyncio
async def test_scoped_stream_unknown_scan_404(clean_registry):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/scans/nope/stream")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unscoped_stream_no_session_404(clean_registry):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/scan/stream")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_snapshot_is_first_event(clean_registry):
    session = ScanSession(id="scan-A", target="example.com", phase="scanning")
    session.checks_total = 7
    session.checks_completed = 2
    session.current_check = "port_scan"
    clean_registry.register(session)

    gen = _stream(session)
    first = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    frame = first.decode("utf-8")
    assert "event: snapshot" in frame
    assert "id: 0" in frame
    assert '"scan_id": "scan-A"' in frame
    assert '"checks_total": 7' in frame
    session.ensure_event_bus().close()
    await gen.aclose()


@pytest.mark.asyncio
async def test_live_event_is_forwarded(clean_registry):
    session = ScanSession(id="scan-B", target="example.com")
    clean_registry.register(session)

    gen = _stream(session)
    snapshot = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"event: snapshot" in snapshot

    session.publish_event("check_started", {"name": "port_scan", "suite": "network"})
    session.mark_terminal("complete")

    frames = await _drain(session, gen, max_frames=5, timeout=2.0)
    text = b"\n".join(frames).decode("utf-8")
    assert "event: check_started" in text
    assert "event: scan_complete" in text


@pytest.mark.asyncio
async def test_last_event_id_replays_ring(clean_registry):
    """Reconnect with Last-Event-ID=N replays ring events with seq > N."""
    session = ScanSession(id="scan-R", target="example.com")
    clean_registry.register(session)
    # Seed the ring with three events before anyone connects.
    session.publish_event("check_started", {"name": "a"})  # seq 1
    session.publish_event("check_completed", {"name": "a"})  # seq 2
    session.publish_event("check_started", {"name": "b"})  # seq 3

    gen = _stream(session, last_event_id=1)
    snapshot = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"event: snapshot" in snapshot
    frames = [await asyncio.wait_for(gen.__anext__(), timeout=1.0) for _ in range(2)]
    text = b"\n".join(frames).decode("utf-8")
    # Events 2 and 3 should replay; event 1 should not.
    assert "id: 2" in text
    assert "id: 3" in text
    assert "id: 1" not in text
    session.ensure_event_bus().close()
    await gen.aclose()


@pytest.mark.asyncio
async def test_last_event_id_dedups_live_stream(clean_registry):
    """Events seen via ring replay must not repeat on the live stream."""
    session = ScanSession(id="scan-D", target="example.com")
    clean_registry.register(session)
    session.publish_event("check_started", {"name": "a"})  # seq 1

    gen = _stream(session, last_event_id=0)  # replay everything
    snapshot = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"event: snapshot" in snapshot
    replayed = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"id: 1" in replayed
    # New event after subscribe — must not re-emit seq 1.
    session.publish_event("check_completed", {"name": "a"})  # seq 2
    live = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"id: 2" in live
    assert b"id: 1" not in live
    session.ensure_event_bus().close()
    await gen.aclose()


@pytest.mark.asyncio
async def test_db_replay_fills_observation_events(monkeypatch, clean_registry):
    """Phase 51.3b: observation_added events replay from the DB, not the ring."""
    session = ScanSession(id="scan-DB", target="example.com")
    clean_registry.register(session)
    # Seed the ring with a check event so ring_floor is defined.
    session.publish_event("check_started", {"name": "a"})  # seq 1
    # Advance event_seq to simulate observation rows that were written live
    # but (because observation_added is never in the ring) are only recoverable
    # from the DB on replay.
    session.event_seq = 5

    async def fake_db_replay(scan_id, last_seq, upper_seq, ring_events):
        assert scan_id == "scan-DB"
        assert last_seq == 0
        assert upper_seq == 5
        # Ring contained seq 1; DB supplies observation_added at seq 2 & 4.
        return [
            (2, "observation_added", {"id": "o2", "severity": "low",
                                      "host": "h", "check": "c"}),
            (4, "observation_added", {"id": "o4", "severity": "high",
                                      "host": "h", "check": "c"}),
        ]

    monkeypatch.setattr(scan_stream_module, "_db_replay_events", fake_db_replay)

    gen = scan_stream_module._stream(session, last_event_id=0)
    snapshot = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"event: snapshot" in snapshot
    # Expect replay order: seq 1 (ring), 2 (db), 4 (db).
    frames = [await asyncio.wait_for(gen.__anext__(), timeout=1.0) for _ in range(3)]
    text = b"\n".join(frames).decode("utf-8")
    assert "id: 1\nevent: check_started" in text
    assert "id: 2\nevent: observation_added" in text
    assert "id: 4\nevent: observation_added" in text
    # Ordering: seq 1 before seq 2 before seq 4.
    assert text.index("id: 1") < text.index("id: 2") < text.index("id: 4")
    session.ensure_event_bus().close()
    await gen.aclose()


def test_merge_replay_ring_wins_on_seq_collision():
    """Ring entries take precedence when a DB row has the same seq."""
    from app.scan_events import ScanEvent

    ring = [
        ScanEvent(seq=3, type="check_started", scan_id="s", ts_ns=99,
                  payload={"scan_id": "s", "name": "ring"}),
    ]
    db = [
        (2, "observation_added", {"id": "o"}),
        (3, "check_started", {"name": "db"}),  # collision — ring wins
        (5, "observation_added", {"id": "p"}),
    ]
    merged = scan_stream_module._merge_replay("s", ring, db)
    assert [e.seq for e in merged] == [2, 3, 5]
    collided = next(e for e in merged if e.seq == 3)
    assert collided.ts_ns == 99
    assert collided.payload["name"] == "ring"
    # DB-only events carry scan_id in their payload.
    assert merged[0].payload["scan_id"] == "s"
    assert merged[-1].payload["scan_id"] == "s"


@pytest.mark.asyncio
async def test_heartbeat_is_sse_comment(monkeypatch, clean_registry):
    """With a fast heartbeat interval, an idle stream emits `: keepalive`."""
    monkeypatch.setattr(scan_stream_module, "HEARTBEAT_INTERVAL_S", 0.05)

    session = ScanSession(id="scan-C", target="example.com")
    clean_registry.register(session)

    gen = _stream(session)
    snapshot = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert b"event: snapshot" in snapshot
    # Two idle iterations should produce at least one keepalive comment.
    keepalives = []
    for _ in range(5):
        try:
            chunk = await asyncio.wait_for(gen.__anext__(), timeout=0.3)
        except asyncio.TimeoutError:
            break
        if chunk.startswith(b": keepalive"):
            keepalives.append(chunk)
            break
    await gen.aclose()
    assert keepalives, "expected at least one keepalive comment"
