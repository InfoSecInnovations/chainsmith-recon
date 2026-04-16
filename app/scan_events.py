"""
app/scan_events.py - Per-scan event bus for SSE streaming (Phase 51.1a).

Pure infrastructure: defines the ScanEvent payload and a ScanEventBus that
per-session publishers push to and HTTP stream handlers subscribe to.

Publishers (scanner callbacks, ObservationWriter, mark_terminal) and the
HTTP route land in later sub-phases (51.1c / 51.2a). Nothing outside this
module imports it yet.

Design notes:
  - Subscribers each get their own bounded asyncio.Queue. Fan-out is
    O(subscribers); publishers never block on a slow consumer.
  - On queue overflow the subscriber's queue is *closed* (a sentinel is
    pushed and the subscriber is unsubscribed). The HTTP layer reacts by
    closing the connection; the browser reconnects with Last-Event-ID and
    re-enters the normal replay path. No dedicated resync protocol.
  - Sequence numbers are owned by ScanSession.next_seq(), not the bus —
    the same counter stamps DB rows (observations.event_seq, etc.) so the
    hot ring and DB replay share one id space (see design §4).
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

DEFAULT_SUBSCRIBER_QUEUE_SIZE = 1000

# Phase 51.3a: hot ring buffer size for status/check events. Observation
# events are never stored here — they replay from the DB (design §4) so
# ring memory stays bounded regardless of scan size.
DEFAULT_RING_SIZE = 50

# Event types excluded from the ring. These payloads can number in the
# thousands and are always replayed via the `observations.event_seq` index.
_RING_EXCLUDED_TYPES = frozenset({"observation_added"})


@dataclass(frozen=True)
class ScanEvent:
    """One event on the per-scan bus.

    `type` is a short string (e.g. "status_changed", "check_started"); the
    canonical set lives in the design doc §3 and will be enforced by the
    publishers in 51.1c, not here — the bus itself is type-agnostic so
    tests and future event kinds don't need to touch this module.
    """

    seq: int
    type: str
    scan_id: str
    ts_ns: int
    payload: dict[str, Any]

    @staticmethod
    def now_ns() -> int:
        return time.time_ns()


# Sentinel pushed into a subscriber's queue when the bus drops it (overflow
# or explicit unsubscribe). Consumers should treat receipt as end-of-stream.
CLOSED = object()


class SubscriberClosed(Exception):
    """Raised by Subscription.get() after the bus closed this subscriber."""


class Subscription:
    """One subscriber's view of the bus. Async-iterable."""

    def __init__(self, bus: ScanEventBus, queue_size: int) -> None:
        self._bus = bus
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._close_event = asyncio.Event()
        self._closed = False

    async def get(self) -> ScanEvent:
        if self._queue.empty() and self._close_event.is_set():
            self._closed = True
            raise SubscriberClosed()
        get_task = asyncio.ensure_future(self._queue.get())
        close_task = asyncio.ensure_future(self._close_event.wait())
        try:
            done, _ = await asyncio.wait(
                {get_task, close_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            if not get_task.done():
                get_task.cancel()
            if not close_task.done():
                close_task.cancel()
        if get_task in done and not get_task.cancelled():
            item = get_task.result()
            if item is CLOSED:
                self._closed = True
                raise SubscriberClosed()
            return item  # type: ignore[return-value]
        # Closed while waiting; deliver any buffered items before signaling end.
        if not self._queue.empty():
            return self._queue.get_nowait()
        self._closed = True
        raise SubscriberClosed()

    def __aiter__(self) -> Subscription:
        return self

    async def __anext__(self) -> ScanEvent:
        try:
            return await self.get()
        except SubscriberClosed:
            raise StopAsyncIteration from None

    def close(self) -> None:
        """Unsubscribe and signal end-of-stream to any waiter."""
        self._bus._drop(self)
        self._close_event.set()

    # Internal: publisher push path. Returns False if the queue overflowed;
    # the bus uses that signal to close this subscriber.
    def _offer(self, event: ScanEvent) -> bool:
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            return False


class ScanEventBus:
    """Per-scan pub/sub. One instance lives on each ScanSession.

    Publishers call `publish(event)`; subscribers call `subscribe()` to get
    a Subscription and iterate it. `close()` tears the bus down at the end
    of a scan's terminal TTL grace window (51.2b).
    """

    def __init__(
        self,
        *,
        queue_size: int = DEFAULT_SUBSCRIBER_QUEUE_SIZE,
        ring_size: int = DEFAULT_RING_SIZE,
    ) -> None:
        self._queue_size = queue_size
        self._subscribers: set[Subscription] = set()
        self._closed = False
        # Hot ring for Last-Event-ID replay (51.3a). Observation events are
        # excluded — they always replay from the DB (design §4).
        self._ring: deque[ScanEvent] = deque(maxlen=ring_size)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def is_closed(self) -> bool:
        return self._closed

    def subscribe(self) -> Subscription:
        if self._closed:
            sub = Subscription(self, self._queue_size)
            sub.close()
            return sub
        sub = Subscription(self, self._queue_size)
        self._subscribers.add(sub)
        return sub

    def publish(self, event: ScanEvent) -> None:
        if self._closed:
            return
        if event.type not in _RING_EXCLUDED_TYPES:
            self._ring.append(event)
        # Copy the set: closing a subscriber during iteration mutates it.
        for sub in list(self._subscribers):
            if not sub._offer(event):
                # Slow subscriber — drop it. The HTTP layer's next write
                # will fail, the client reconnects with Last-Event-ID, and
                # DB-backed replay restores state.
                sub.close()

    def close(self) -> None:
        """Tear down the bus. Idempotent."""
        if self._closed:
            return
        self._closed = True
        for sub in list(self._subscribers):
            sub.close()
        self._subscribers.clear()

    # Internal: Subscription.close() calls this.
    def _drop(self, sub: Subscription) -> None:
        self._subscribers.discard(sub)

    # ---- 51.3a: Last-Event-ID replay from the hot ring ----

    def events_since(self, last_seq: int) -> list[ScanEvent]:
        """Return ring events with `seq > last_seq`, oldest first.

        Observation events are not in the ring by construction; callers that
        need them must supplement via DB-backed replay (51.3b).
        """
        return [e for e in self._ring if e.seq > last_seq]

    @property
    def ring_floor(self) -> int | None:
        """Lowest seq present in the ring, or None if empty.

        A `Last-Event-ID` older than the floor indicates the ring has rolled
        past the client's last-seen event; the DB-backed path must fill the
        gap once 51.3b lands.
        """
        if not self._ring:
            return None
        return self._ring[0].seq
