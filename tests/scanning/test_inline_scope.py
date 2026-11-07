"""
B-1: scope travels with POST /api/v1/scan, and a scan never reads scope prep.

Before, a scan took its scope from process-global state set by an earlier
POST /api/v1/scope, so two clients could interleave "set scope" and "start
scan" and one would scan with the other's scope.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from app.api_models import ProofSettingsInput, ScanStartInput, ScanWindowInput
from app.config import get_config
from app.routes import scan as scan_route
from app.scan_registry import get_registry
from app.state import state

pytestmark = pytest.mark.unit


@pytest.fixture
def started(monkeypatch):
    """Start scans without running them; return the registered sessions."""
    registry = get_registry()
    registry._reset()
    monkeypatch.setattr(get_config().concurrency, "max_concurrent_scans", 5)

    async def no_run(*args, **kwargs):
        return None

    monkeypatch.setattr(scan_route, "run_scan", no_run)
    for attr in ("target", "exclude", "techniques"):
        monkeypatch.setattr(state, attr, getattr(state, attr))
    yield registry
    registry._reset()


async def _start(**fields):
    response = await scan_route.start_scan(ScanStartInput(**fields))
    return get_registry().get(response["scan_id"])


async def test_target_is_required():
    with pytest.raises(HTTPException) as caught:
        await scan_route.start_scan(ScanStartInput())
    assert caught.value.status_code == 400
    assert "target" in caught.value.detail


async def test_the_scan_uses_its_own_body_not_the_operator_prep(started, monkeypatch):
    # Another client has set different prep scope in the meantime.
    monkeypatch.setattr(state, "target", "someone-else.test")
    monkeypatch.setattr(state, "exclude", ["x.test"])

    session = await _start(target="example.com", exclude=["admin.example.com"])

    assert session.target == "example.com"
    assert session.exclude == ["admin.example.com"]
    assert session.guardian.check_url("https://www.example.com/")[0] is True
    assert session.guardian.check_url("https://someone-else.test/")[0] is False
    assert session.guardian.check_url("https://admin.example.com/")[0] is False


async def test_two_interleaved_scans_keep_their_own_scope(started):
    first = await _start(target="a.example.com")
    second = await _start(target="b.example.com")

    assert (first.target, second.target) == ("a.example.com", "b.example.com")
    assert first.guardian.check_url("https://b.example.com/")[0] is False


async def test_proof_settings_come_from_the_body(started):
    session = await _start(
        target="example.com",
        proof_of_scope=ProofSettingsInput(
            traffic_logging=False, block_exclusions=False, log_violations=False
        ),
    )
    ps = session.proof_settings
    assert (ps.traffic_logging, ps.block_exclusions, ps.log_violations) == (False, False, False)


async def test_a_body_scan_window_is_enforced(started):
    past = datetime.now(UTC) - timedelta(days=2)
    window = ScanWindowInput(start=past.isoformat(), end=(past + timedelta(hours=1)).isoformat())

    with pytest.raises(HTTPException) as caught:
        await _start(target="example.com", scan_window=window)
    assert caught.value.status_code == 409

    session = await _start(
        target="example.com", scan_window=window, acknowledge_outside_window=True
    )
    assert session.proof_settings.outside_window_acknowledged is True
    assert session.proof_settings.outside_window_acknowledged_at


async def test_the_scan_scope_is_mirrored_into_prep_for_chat_and_the_advisor(started):
    await _start(target="example.com", exclude=["admin.example.com"])
    assert state.target == "example.com"
    assert state.exclude == ["admin.example.com"]


async def test_a_one_sided_window_is_accepted_and_enforced(started):
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()

    with pytest.raises(HTTPException) as caught:
        await _start(target="example.com", scan_window=ScanWindowInput(start=future))
    assert caught.value.status_code == 409  # not yet open
