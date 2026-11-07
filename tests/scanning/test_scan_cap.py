"""
D-1 / D-5: the concurrent-scan cap rejects with 429 and a Retry-After header.

Reject, do not queue: a scan's traffic starts when the operator asked for it or
not at all. The cap defaults to 1 until scope moves inline onto the scan request.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api_models import ScanStartInput
from app.config import ConcurrencyConfig, get_config
from app.routes import scan as scan_route
from app.scan_registry import get_registry
from app.scan_session import ScanSession
from app.state import state

pytestmark = pytest.mark.unit


@pytest.fixture
def at_cap(monkeypatch):
    registry = get_registry()
    registry._reset()
    monkeypatch.setattr(state, "target", "example.com")
    monkeypatch.setattr(get_config().concurrency, "max_concurrent_scans", 1)
    registry.register(ScanSession(id="running-1", target="example.com"))
    yield registry
    registry._reset()


def test_the_cap_defaults_to_one():
    assert ConcurrencyConfig().max_concurrent_scans == 1


async def test_a_scan_over_the_cap_gets_429_with_retry_after(at_cap, monkeypatch):
    monkeypatch.setattr(get_config().concurrency, "retry_after_seconds", 45)

    with pytest.raises(HTTPException) as caught:
        await scan_route.start_scan(ScanStartInput(target="example.com"))

    assert caught.value.status_code == 429
    assert caught.value.headers == {"Retry-After": "45"}
    assert at_cap.active_count() == 1  # the rejected scan was not registered


async def test_retry_after_is_never_below_one_second(at_cap, monkeypatch):
    monkeypatch.setattr(get_config().concurrency, "retry_after_seconds", 0)

    with pytest.raises(HTTPException) as caught:
        await scan_route.start_scan(ScanStartInput(target="example.com"))

    assert caught.value.headers == {"Retry-After": "1"}
