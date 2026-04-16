"""
Phase 51.1a tests for the per-scan event bus.

Covers pure infrastructure only — no publishers, no HTTP route:
  - Fan-out to multiple subscribers.
  - Unsubscribe / close semantics end the async iterator cleanly.
  - Bounded-queue overflow drops the slow subscriber; fast ones keep
    receiving.
  - ScanSession.next_seq() is monotonic and starts at 1.
"""

from __future__ import annotations

import asyncio

import pytest

from app.scan_events import ScanEvent, ScanEventBus, SubscriberClosed
from app.scan_session import ScanSession


def _evt(seq: int, scan_id: str = "scan-1", type_: str = "ping") -> ScanEvent:
    return ScanEvent(
        seq=seq,
        type=type_,
        scan_id=scan_id,
        ts_ns=ScanEvent.now_ns(),
        payload={"i": seq},
    )


@pytest.mark.asyncio
async def test_fan_out_delivers_to_all_subscribers():
    bus = ScanEventBus()
    a = bus.subscribe()
    b = bus.subscribe()
    assert bus.subscriber_count == 2

    bus.publish(_evt(1))
    bus.publish(_evt(2))

    for sub in (a, b):
        e1 = await sub.get()
        e2 = await sub.get()
        assert (e1.seq, e2.seq) == (1, 2)


@pytest.mark.asyncio
async def test_close_ends_async_iteration():
    bus = ScanEventBus()
    sub = bus.subscribe()

    bus.publish(_evt(1))
    sub.close()

    seqs = [e.seq async for e in sub]
    # Depending on drain order we may or may not see the pre-close event,
    # but iteration must terminate rather than hang.
    assert seqs in ([1], [])
    assert bus.subscriber_count == 0


@pytest.mark.asyncio
async def test_get_after_close_raises_subscriber_closed():
    bus = ScanEventBus()
    sub = bus.subscribe()
    sub.close()
    with pytest.raises(SubscriberClosed):
        await sub.get()


@pytest.mark.asyncio
async def test_overflow_drops_slow_subscriber_only():
    bus = ScanEventBus(queue_size=2)
    slow = bus.subscribe()
    fast = bus.subscribe()

    got_fast: list[int] = []

    # Fill slow's queue to capacity; drain fast so only slow is behind.
    bus.publish(_evt(1))
    got_fast.append((await fast.get()).seq)
    bus.publish(_evt(2))
    got_fast.append((await fast.get()).seq)
    # slow now holds [1, 2]; fast is empty.
    bus.publish(_evt(3))
    # slow overflows and is dropped; fast receives event 3 normally.
    got_fast.append((await fast.get()).seq)

    assert got_fast == [1, 2, 3]
    assert bus.subscriber_count == 1
    assert fast in bus._subscribers
    assert slow not in bus._subscribers

    # Slow subscriber's iterator terminates with whatever was queued pre-drop.
    tail = [e.seq async for e in slow]
    assert tail == [1, 2]


@pytest.mark.asyncio
async def test_publish_after_close_is_noop():
    bus = ScanEventBus()
    sub = bus.subscribe()
    bus.close()
    assert bus.is_closed

    bus.publish(_evt(1))  # must not raise

    with pytest.raises(SubscriberClosed):
        await sub.get()


@pytest.mark.asyncio
async def test_subscribe_after_close_returns_closed_sub():
    bus = ScanEventBus()
    bus.close()
    sub = bus.subscribe()
    with pytest.raises(SubscriberClosed):
        await sub.get()


def test_session_next_seq_is_monotonic_from_one():
    s = ScanSession(id="scan-1", target="example.com")
    assert s.event_seq == 0
    assert [s.next_seq() for _ in range(3)] == [1, 2, 3]
    assert s.event_seq == 3


def test_session_event_bus_is_lazy_and_memoized():
    s = ScanSession(id="scan-1", target="example.com")
    assert s.event_bus is None
    bus = s.ensure_event_bus()
    assert s.event_bus is bus
    assert s.ensure_event_bus() is bus


# ---------------------------------------------------------------------------
# Phase 51.3a — hot ring buffer for Last-Event-ID replay.
# ---------------------------------------------------------------------------


def test_ring_stores_non_observation_events():
    bus = ScanEventBus(ring_size=8)
    bus.publish(_evt(1, type_="check_started"))
    bus.publish(_evt(2, type_="check_completed"))
    assert [e.seq for e in bus.events_since(0)] == [1, 2]
    assert bus.ring_floor == 1


def test_ring_excludes_observation_added():
    """observation_added payloads always replay from the DB (design §4)."""
    bus = ScanEventBus(ring_size=8)
    bus.publish(_evt(1, type_="check_started"))
    bus.publish(_evt(2, type_="observation_added"))
    bus.publish(_evt(3, type_="check_completed"))
    seqs = [e.seq for e in bus.events_since(0)]
    assert seqs == [1, 3]


def test_ring_rolls_over_at_capacity():
    bus = ScanEventBus(ring_size=3)
    for i in range(1, 6):
        bus.publish(_evt(i, type_="check_started"))
    # Only the last three survive; ring_floor advances.
    seqs = [e.seq for e in bus.events_since(0)]
    assert seqs == [3, 4, 5]
    assert bus.ring_floor == 3


def test_events_since_filters_by_last_seq():
    bus = ScanEventBus(ring_size=8)
    for i in range(1, 5):
        bus.publish(_evt(i, type_="check_started"))
    assert [e.seq for e in bus.events_since(2)] == [3, 4]
    assert bus.events_since(99) == []


def test_ring_floor_none_when_empty():
    bus = ScanEventBus()
    assert bus.ring_floor is None
