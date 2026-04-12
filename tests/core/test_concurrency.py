"""
Tests for concurrency guards in route handlers.

Covers:
- asyncio.Lock preventing concurrent scan starts
- asyncio.Lock preventing concurrent chain analysis
- asyncio.Lock preventing concurrent adjudication
"""

import asyncio

import pytest

pytestmark = [pytest.mark.unit]

try:
    import fastapi  # noqa: F401

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

skip_no_fastapi = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")


@skip_no_fastapi
class TestScanLockGuard:
    """Test that the scan route lock prevents double-starts."""

    @pytest.mark.asyncio
    async def test_scan_lock_exists(self):
        """Verify _scan_lock is an asyncio.Lock."""
        from app.routes.scan import _scan_lock

        assert isinstance(_scan_lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_scan_lock_serializes_access(self):
        """Verify the lock serializes access (basic check)."""
        from app.routes.scan import _scan_lock

        acquired = []

        async def task(label: str):
            async with _scan_lock:
                acquired.append(f"{label}_start")
                await asyncio.sleep(0.01)
                acquired.append(f"{label}_end")

        await asyncio.gather(task("a"), task("b"))
        # One must complete before the other starts
        a_start = acquired.index("a_start")
        a_end = acquired.index("a_end")
        b_start = acquired.index("b_start")
        b_end = acquired.index("b_end")
        # Either a finishes before b starts, or vice versa
        assert (a_end < b_start) or (b_end < a_start)


@skip_no_fastapi
class TestChainLockGuard:
    @pytest.mark.asyncio
    async def test_chain_lock_exists(self):
        from app.routes.chains import _chain_lock

        assert isinstance(_chain_lock, asyncio.Lock)


@skip_no_fastapi
class TestAdjudicationLockGuard:
    @pytest.mark.asyncio
    async def test_adjudication_lock_exists(self):
        from app.routes.adjudication import _adjudication_lock

        assert isinstance(_adjudication_lock, asyncio.Lock)
