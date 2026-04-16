"""
Tests for GET /api/v1/scans/live — Phase D of the concurrent-scans overhaul.

This endpoint is the backing data source for the web UI scan selector. It
surfaces every ScanSession currently in the process-scoped registry
(both active and TTL-window terminals), so the dropdown can show live
progress in real time instead of lagging behind the DB writes.
"""

from __future__ import annotations

import time

import pytest

from app.routes.scan_history import list_live_scans
from app.scan_registry import get_registry
from app.scan_session import ScanSession

pytestmark = pytest.mark.unit


@pytest.fixture
def clean_registry():
    reg = get_registry()
    reg._reset()
    yield reg
    reg._reset()


def _session(
    id_: str, *, target: str = "example.com", started_at: float | None = None, **overrides
) -> ScanSession:
    kwargs = {
        "id": id_,
        "target": target,
        "started_at": started_at if started_at is not None else time.time(),
    }
    kwargs.update(overrides)
    return ScanSession(**kwargs)


@pytest.mark.asyncio
async def test_live_scans_empty_registry(clean_registry):
    result = await list_live_scans()
    assert result == {"scans": []}


@pytest.mark.asyncio
async def test_live_scans_includes_active(clean_registry):
    clean_registry.register(_session("scan-1", target="a.example.com"))
    clean_registry.register(_session("scan-2", target="b.example.com"))

    result = await list_live_scans()

    ids = {s["id"] for s in result["scans"]}
    assert ids == {"scan-1", "scan-2"}
    for s in result["scans"]:
        assert s["is_terminal"] is False
        assert s["status"] == "running"


@pytest.mark.asyncio
async def test_live_scans_most_recent_first(clean_registry):
    now = time.time()
    clean_registry.register(_session("older", started_at=now - 100))
    clean_registry.register(_session("newer", started_at=now - 5))
    clean_registry.register(_session("newest", started_at=now))

    result = await list_live_scans()
    order = [s["id"] for s in result["scans"]]
    assert order == ["newest", "newer", "older"]


@pytest.mark.asyncio
async def test_live_scans_includes_ttl_terminals(clean_registry):
    """Terminal sessions stay queryable until reaped — Phase D dropdown
    wants to let users watch a just-finished scan's final state."""
    s = _session("done-1")
    s.mark_terminal("complete")
    clean_registry.register(s)

    result = await list_live_scans()
    assert len(result["scans"]) == 1
    assert result["scans"][0]["is_terminal"] is True
    assert result["scans"][0]["status"] == "complete"
    assert result["scans"][0]["completed_at"] is not None


@pytest.mark.asyncio
async def test_live_scans_exposes_progress_fields(clean_registry):
    s = _session("scan-1")
    s.checks_total = 10
    s.checks_completed = 4
    s.current_check = "dns_enumeration"
    s.phase = "scanning"
    clean_registry.register(s)

    result = await list_live_scans()
    row = result["scans"][0]
    assert row["checks_total"] == 10
    assert row["checks_completed"] == 4
    assert row["current_check"] == "dns_enumeration"
    assert row["phase"] == "scanning"
    assert row["target"] == "example.com"
