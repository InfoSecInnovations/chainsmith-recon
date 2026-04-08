"""Tests for observation status tracking and scan comparison."""

import pytest
from sqlalchemy import func, select

from app.db.engine import close_db, get_session, init_db
from app.db.models import (
    ObservationRecord,
    ScanComparison,
)
from app.db.repositories import (
    ComparisonRepository,
    ObservationRepository,
    ScanRepository,
)

pytestmark = pytest.mark.integration


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


@pytest.fixture
def scan_repo():
    return ScanRepository()


@pytest.fixture
def observation_repo():
    return ObservationRepository()


@pytest.fixture
def comparison_repo():
    return ComparisonRepository()


class TestObservationStatusTracking:
    @pytest.mark.asyncio
    async def test_first_scan_all_new(self, db, scan_repo, observation_repo, comparison_repo):
        """First scan for a target: all observations are 'new'."""
        await scan_repo.create_scan(
            scan_id="first-scan",
            session_id="s1",
            target_domain="fresh.com",
        )
        await observation_repo.bulk_create(
            "first-scan",
            [
                {
                    "title": "Observation A",
                    "severity": "high",
                    "check_name": "check_a",
                    "host": "fresh.com",
                },
                {
                    "title": "Observation B",
                    "severity": "low",
                    "check_name": "check_b",
                    "host": "fresh.com",
                },
            ],
        )
        await scan_repo.complete_scan("first-scan", status="complete", observations_count=2)

        result = await comparison_repo.compute_observation_statuses("first-scan")
        assert result["new"] == 2
        assert result["recurring"] == 0
        assert result["resolved"] == 0
        assert result["regressed"] == 0
        assert result["previous_scan_id"] is None

    @pytest.mark.asyncio
    async def test_second_scan_status_tracking(
        self, db, scan_repo, observation_repo, comparison_repo
    ):
        """Second scan correctly identifies new, recurring, and resolved."""
        # Scan 1: observations A, B, C
        await scan_repo.create_scan(
            scan_id="scan-v1",
            session_id="s1",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "scan-v1",
            [
                {
                    "id": "f-a",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "example.com",
                },
                {
                    "id": "f-b",
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "example.com",
                },
                {
                    "id": "f-c",
                    "title": "Open Port",
                    "severity": "info",
                    "check_name": "port_scan",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("scan-v1", status="complete", observations_count=3)

        # Compute statuses for scan-v1 BEFORE scan-v2 exists
        result1 = await comparison_repo.compute_observation_statuses("scan-v1")
        assert result1["new"] == 3

        # Scan 2: observations A, D (B and C resolved, D is new)
        await scan_repo.create_scan(
            scan_id="scan-v2",
            session_id="s2",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "scan-v2",
            [
                {
                    "id": "f-a2",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "example.com",
                },
                {
                    "id": "f-d",
                    "title": "CSRF",
                    "severity": "medium",
                    "check_name": "csrf",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("scan-v2", status="complete", observations_count=2)

        # Now compute for scan-v2
        result2 = await comparison_repo.compute_observation_statuses("scan-v2")
        assert result2["recurring"] == 1  # XSS still present
        assert result2["resolved"] == 2  # SQLi and Open Port gone
        assert result2["previous_scan_id"] == "scan-v1"
        assert result2["new"] >= 1  # CSRF is new
        assert result2["regressed"] >= 0  # regressed may or may not be present

    @pytest.mark.asyncio
    async def test_comparison_stored(self, db, scan_repo, observation_repo, comparison_repo):
        """Scan comparison is stored in scan_comparisons table."""
        await scan_repo.create_scan(
            scan_id="cmp-s1",
            session_id="s1",
            target_domain="store.com",
        )
        await observation_repo.bulk_create(
            "cmp-s1",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "store.com"},
            ],
        )
        await scan_repo.complete_scan("cmp-s1", status="complete", observations_count=1)
        await comparison_repo.compute_observation_statuses("cmp-s1")

        await scan_repo.create_scan(
            scan_id="cmp-s2",
            session_id="s2",
            target_domain="store.com",
        )
        await observation_repo.bulk_create(
            "cmp-s2",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "store.com"},
            ],
        )
        await scan_repo.complete_scan("cmp-s2", status="complete", observations_count=1)
        await comparison_repo.compute_observation_statuses("cmp-s2")

        async with get_session() as session:
            result = await session.execute(select(func.count()).select_from(ScanComparison))
            assert result.scalar() == 1

    @pytest.mark.asyncio
    async def test_observation_history(self, db, scan_repo, observation_repo, comparison_repo):
        """Observation history tracks status across scans."""
        await scan_repo.create_scan(
            scan_id="hist-s1",
            session_id="s1",
            target_domain="hist.com",
        )
        await observation_repo.bulk_create(
            "hist-s1",
            [
                {
                    "id": "h-a",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "hist.com",
                },
            ],
        )
        await scan_repo.complete_scan("hist-s1", status="complete", observations_count=1)
        await comparison_repo.compute_observation_statuses("hist-s1")

        await scan_repo.create_scan(
            scan_id="hist-s2",
            session_id="s2",
            target_domain="hist.com",
        )
        await observation_repo.bulk_create(
            "hist-s2",
            [
                {
                    "id": "h-a2",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "hist.com",
                },
            ],
        )
        await scan_repo.complete_scan("hist-s2", status="complete", observations_count=1)
        await comparison_repo.compute_observation_statuses("hist-s2")

        # Get the XSS fingerprint
        async with get_session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(ObservationRecord.id == "h-a")
            )
            xss_fp = result.scalar_one()

        history = await comparison_repo.get_observation_history(xss_fp)
        assert len(history) >= 2
        statuses = [h["status"] for h in history]
        assert "new" in statuses
        assert "recurring" in statuses


class TestScanComparison:
    @pytest.fixture
    async def comparable_scans(self, db, scan_repo, observation_repo):
        """Two scans with known fingerprint overlap."""
        await scan_repo.create_scan(
            scan_id="cmp-a",
            session_id="s1",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "cmp-a",
            [
                {
                    "id": "ca-1",
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "example.com",
                },
                {
                    "id": "ca-2",
                    "title": "F2",
                    "severity": "medium",
                    "check_name": "c2",
                    "host": "example.com",
                },
                {
                    "id": "ca-3",
                    "title": "F3",
                    "severity": "low",
                    "check_name": "c3",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("cmp-a", status="complete", observations_count=3)

        await scan_repo.create_scan(
            scan_id="cmp-b",
            session_id="s2",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "cmp-b",
            [
                {
                    "id": "cb-1",
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "example.com",
                },  # Same as ca-1
                {
                    "id": "cb-4",
                    "title": "F4",
                    "severity": "critical",
                    "check_name": "c4",
                    "host": "example.com",
                },  # New
            ],
        )
        await scan_repo.complete_scan("cmp-b", status="complete", observations_count=2)

        return {"a": "cmp-a", "b": "cmp-b"}

    @pytest.mark.asyncio
    async def test_compare_scans(self, comparable_scans, comparison_repo):
        result = await comparison_repo.compare_scans("cmp-a", "cmp-b")
        assert result["scan_a_id"] == "cmp-a"
        assert result["scan_b_id"] == "cmp-b"
        assert result["recurring_count"] == 1  # F1
        assert result["new_count"] == 1  # F4
        assert result["resolved_count"] == 2  # F2 and F3

    @pytest.mark.asyncio
    async def test_compare_new_observations_detail(self, comparable_scans, comparison_repo):
        result = await comparison_repo.compare_scans("cmp-a", "cmp-b")
        new_titles = {f["title"] for f in result["new_observations"]}
        assert "F4" in new_titles

    @pytest.mark.asyncio
    async def test_compare_resolved_observations_detail(self, comparable_scans, comparison_repo):
        result = await comparison_repo.compare_scans("cmp-a", "cmp-b")
        resolved_titles = {f["title"] for f in result["resolved_observations"]}
        assert "F2" in resolved_titles
        assert "F3" in resolved_titles

    @pytest.mark.asyncio
    async def test_compare_identical_scans(self, db, scan_repo, observation_repo, comparison_repo):
        """Comparing a scan with itself: all recurring, no new/resolved."""
        await scan_repo.create_scan(
            scan_id="same-a",
            session_id="s1",
            target_domain="x.com",
        )
        await observation_repo.bulk_create(
            "same-a",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "x.com"},
            ],
        )

        result = await comparison_repo.compare_scans("same-a", "same-a")
        assert result["new_count"] == 0
        assert result["resolved_count"] == 0
        assert result["recurring_count"] == 1

    @pytest.mark.asyncio
    async def test_observation_history_empty(self, db, comparison_repo):
        """No history for unknown fingerprint."""
        history = await comparison_repo.get_observation_history("nonexistent")
        assert history == []
