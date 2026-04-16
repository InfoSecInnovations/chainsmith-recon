"""
Phase A tests for ScanSession and ScanRegistry.

These cover the new concurrent-scans scaffolding introduced before any
route flips to reading from the registry. Focus:
  - ScanSession construction, terminal transitions, shared-ref semantics.
  - ScanRegistry register/get/list/current/most_recent/active_count.
  - Reap-by-TTL of completed sessions.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.scan_registry import ScanRegistry
from app.scan_session import TERMINAL_STATUSES, ScanSession


def _make(id_: str = "scan-1", **overrides) -> ScanSession:
    kwargs = {
        "id": id_,
        "target": "example.com",
        "started_at": time.time(),
    }
    kwargs.update(overrides)
    return ScanSession(**kwargs)


# ─── ScanSession ────────────────────────────────────────────────


def test_session_defaults_are_non_terminal():
    s = _make()
    assert s.status == "running"
    assert not s.is_terminal
    assert s.completed_at is None


@pytest.mark.parametrize("status", ["complete", "error", "cancelled"])
def test_mark_terminal_sets_completion(status):
    s = _make()
    s.mark_terminal(status)
    assert s.is_terminal
    assert s.status == status
    assert s.completed_at is not None


def test_mark_terminal_rejects_non_terminal_status():
    s = _make()
    with pytest.raises(ValueError):
        s.mark_terminal("running")


def test_mark_terminal_preserves_first_completion():
    s = _make()
    s.mark_terminal("complete")
    first = s.completed_at
    time.sleep(0.001)
    s.mark_terminal("error", error_message="late failure")
    assert s.completed_at == first
    assert s.error_message == "late failure"


def test_terminal_statuses_const():
    assert frozenset({"complete", "error", "cancelled"}) == TERMINAL_STATUSES


def test_shared_container_refs_flow_through():
    """Scanner relies on container identity — mutations via state reach session."""
    shared_statuses: dict[str, str] = {}
    shared_event = asyncio.Event()
    s = _make(check_statuses=shared_statuses, pause_event=shared_event)

    shared_statuses["port_scan"] = "running"
    assert s.check_statuses["port_scan"] == "running"
    assert s.pause_event is shared_event


# ─── ScanRegistry ───────────────────────────────────────────────


def test_registry_register_and_get():
    reg = ScanRegistry()
    s = _make("scan-a")
    reg.register(s)
    assert reg.get("scan-a") is s
    assert reg.get("nope") is None


def test_registry_list_and_status_filter():
    reg = ScanRegistry()
    reg.register(_make("a"))
    reg.register(_make("b", status="complete", completed_at=time.time()))
    assert len(reg.list()) == 2
    assert [s.id for s in reg.list(status="running")] == ["a"]


def test_registry_active_excludes_terminal():
    reg = ScanRegistry()
    running = _make("a")
    reg.register(running)
    done = _make("b")
    done.mark_terminal("complete")
    reg.register(done)
    assert reg.active_count() == 1
    assert reg.active() == [running]


def test_registry_current_returns_newest_non_terminal():
    reg = ScanRegistry()
    older = _make("old", started_at=100.0)
    newer = _make("new", started_at=200.0)
    reg.register(older)
    reg.register(newer)
    assert reg.current() is newer


def test_registry_current_ignores_terminal():
    reg = ScanRegistry()
    done = _make("done", started_at=300.0)
    done.mark_terminal("complete")
    reg.register(done)
    reg.register(_make("live", started_at=100.0))
    assert reg.current().id == "live"


def test_registry_current_none_when_all_terminal():
    reg = ScanRegistry()
    done = _make("done")
    done.mark_terminal("complete")
    reg.register(done)
    assert reg.current() is None


def test_registry_most_recent_includes_terminal():
    reg = ScanRegistry()
    done = _make("done", started_at=300.0)
    done.mark_terminal("complete")
    reg.register(done)
    reg.register(_make("older", started_at=100.0))
    assert reg.most_recent().id == "done"


def test_registry_reap_drops_expired_terminal_only():
    reg = ScanRegistry()
    now = 1_000_000.0

    fresh_done = _make("fresh", started_at=now - 10)
    fresh_done.mark_terminal("complete")
    fresh_done.completed_at = now - 10

    stale_done = _make("stale", started_at=now - 1000)
    stale_done.mark_terminal("complete")
    stale_done.completed_at = now - 600

    live = _make("live", started_at=now - 5)

    reg.register(fresh_done)
    reg.register(stale_done)
    reg.register(live)

    dropped = reg.reap_completed(ttl_seconds=300, now=now)

    assert dropped == 1
    assert reg.get("stale") is None
    assert reg.get("fresh") is not None
    assert reg.get("live") is not None


def test_registry_remove():
    reg = ScanRegistry()
    s = _make("x")
    reg.register(s)
    assert reg.remove("x") is s
    assert reg.get("x") is None
    assert reg.remove("x") is None


# ---------------------------------------------------------------------------
# Phase 51.2b — terminal TTL grace window for the event bus.
# ---------------------------------------------------------------------------


def test_mark_terminal_closes_bus_synchronously_without_event_loop():
    """No running loop (CLI/sync path) → close immediately, no scheduling."""
    session = _make("sync-scan")
    bus = session.ensure_event_bus()
    session.mark_terminal("complete")
    assert bus.is_closed, "bus should close immediately when no loop is running"


@pytest.mark.asyncio
async def test_mark_terminal_defers_bus_close_under_event_loop(monkeypatch):
    """With a running loop, bus stays open for the TTL then closes."""
    import app.scan_session as scan_session_module

    monkeypatch.setattr(scan_session_module, "TERMINAL_BUS_TTL_S", 0.05)
    session = _make("ttl-scan")
    bus = session.ensure_event_bus()
    session.mark_terminal("complete")
    # Still open immediately after terminal — grace window is running.
    assert not bus.is_closed
    # Wait past the TTL; bus should have closed via loop.call_later.
    await asyncio.sleep(0.15)
    assert bus.is_closed


@pytest.mark.asyncio
async def test_schedule_teardown_is_noop_when_bus_already_closed():
    session = _make("idempotent")
    bus = session.ensure_event_bus()
    bus.close()
    # Should not raise and should not re-schedule anything.
    session._schedule_event_bus_teardown(delay=0.01)
    await asyncio.sleep(0.05)
    assert bus.is_closed
