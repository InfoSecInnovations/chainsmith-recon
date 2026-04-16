"""
app/scan_session.py - Per-Scan Session State

Introduced in Phase A of the concurrent-scans overhaul. A ScanSession owns
the fields that today live on the AppState singleton but are logically
per-scan: status/phase, progress counters, runner reference, guardian,
cooperative pause/stop controls, and post-scan phase statuses.

Phase A: ScanSession exists alongside AppState. run_scan() creates one per
scan, registers it in ScanRegistry, and mirrors scalar writes into it.
Mutable containers (check_statuses, skip_reasons, pause_event, runner,
guardian) are held by reference so writes through `state` show up on the
session without explicit mirroring. Routes still read from `state`.

Phase B will flip reads to the registry and remove the per-scan fields
from AppState entirely.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.check_launcher import CheckLauncher
    from app.guardian import Guardian
    from app.proof_of_scope import ProofOfScopeSettings
    from app.scan_events import ScanEventBus


TERMINAL_STATUSES = frozenset({"complete", "error", "cancelled"})

# Phase 51.2b: how long the per-scan event bus stays alive after a terminal
# status. Late reconnects within this window still get `snapshot` + (once
# 51.3's ring replay lands) the trailing `scan_complete` frame. After the
# window, the bus is closed and reconnects fall back to REST for final state.
TERMINAL_BUS_TTL_S = 30.0


@dataclass
class ScanSession:
    """
    Live state for one scan.

    Scalar fields (status, phase, current_check, checks_completed, ...) are
    dual-written by the scanner during Phase A. Container fields
    (check_statuses, skip_reasons, pause_event) hold the same references
    as AppState so single-site writes flow through.
    """

    id: str
    target: str
    exclude: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    status: str = "running"
    phase: str = "scanning"
    error_message: str | None = None

    runner: CheckLauncher | None = None
    guardian: Guardian | None = None

    checks_total: int = 0
    checks_completed: int = 0
    current_check: str | None = None
    check_statuses: dict[str, str] = field(default_factory=dict)
    skip_reasons: dict[str, str] = field(default_factory=dict)

    # Post-scan phase statuses (concurrency guards; result data lives in DB).
    chain_status: str = "idle"
    adjudication_status: str = "idle"
    triage_status: str = "idle"
    chainsmith_status: str = "idle"

    # Cooperative pause/stop. pause_event set = running, cleared = paused.
    pause_event: asyncio.Event | None = None
    stop_requested: bool = False

    settings: dict = field(default_factory=dict)
    proof_settings: ProofOfScopeSettings | None = None

    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    # Phase 51.1a: monotonic per-session sequence stamped on every published
    # event and on event_seq columns for DB-backed replay. Same counter
    # powers both so the hot ring and DB share one id space. Bus is lazy —
    # only constructed when a publisher or subscriber first needs it.
    event_seq: int = 0
    event_bus: ScanEventBus | None = None

    def __post_init__(self) -> None:
        if self.pause_event is None:
            ev = asyncio.Event()
            ev.set()
            self.pause_event = ev

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def next_seq(self) -> int:
        """Return the next monotonic event sequence for this scan.

        Callers stamp both live ScanEvents and DB rows (observations.event_seq,
        check_log.event_seq) from this single counter so the SSE hot ring
        and DB-backed replay share one id space.
        """
        self.event_seq += 1
        return self.event_seq

    def ensure_event_bus(self) -> ScanEventBus:
        """Lazily construct the per-session event bus."""
        if self.event_bus is None:
            from app.scan_events import ScanEventBus

            self.event_bus = ScanEventBus()
        return self.event_bus

    def publish_event(self, event_type: str, payload: dict) -> int:
        """Allocate a sequence number and publish an event on the bus.

        Phase 51.1c: single seam for publishers (ObservationWriter,
        CheckLogWriter, mark_terminal, etc.). Returns the stamped seq so
        callers can also write it onto DB rows (observations.event_seq,
        check_log.event_seq) — same counter, one id space.
        """
        from app.scan_events import ScanEvent

        seq = self.next_seq()
        bus = self.ensure_event_bus()
        bus.publish(
            ScanEvent(
                seq=seq,
                type=event_type,
                scan_id=self.id,
                ts_ns=ScanEvent.now_ns(),
                payload={"scan_id": self.id, **payload},
            )
        )
        return seq

    def mark_terminal(self, status: str, error_message: str | None = None) -> None:
        """Record a terminal state and completion timestamp."""
        if status not in TERMINAL_STATUSES:
            raise ValueError(f"{status!r} is not a terminal status")
        self.status = status
        if error_message is not None:
            self.error_message = error_message
        if self.completed_at is None:
            self.completed_at = time.time()
        # Phase 51.1c: final event on the bus. Subscribers use this to
        # close cleanly; the bus itself is torn down later (51.2b TTL).
        duration_s = self.completed_at - self.started_at if self.started_at is not None else None
        self.publish_event(
            "scan_complete",
            {
                "status": self.status,
                "error_message": error_message,
                "duration_s": duration_s,
            },
        )
        self._schedule_event_bus_teardown()

    def _schedule_event_bus_teardown(self, delay: float | None = None) -> None:
        """Close the event bus after a grace window (51.2b).

        Late reconnects within the window see the still-live bus; once it
        closes, they fall back to REST. If no event loop is running (test
        harness, CLI sync path), close immediately — there is nothing that
        could reconnect in the meantime.
        """
        bus = self.event_bus
        if bus is None or bus.is_closed:
            return
        # Resolve TTL at call time so tests (and future runtime tuning) can
        # monkeypatch the module attribute.
        ttl = TERMINAL_BUS_TTL_S if delay is None else delay
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            bus.close()
            return
        loop.call_later(ttl, bus.close)
