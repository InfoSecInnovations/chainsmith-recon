"""
Tests for trend analysis (Phase 4b).

Covers TrendRepository: data points, risk scores, severity breakdown,
suite breakdown, override exclusion, and averages.
"""

import pytest

from app.db.engine import close_db, init_db
from app.db.repositories import (
    ComparisonRepository,
    EngagementRepository,
    ObservationOverrideRepository,
    ObservationRepository,
    ScanRepository,
    TrendRepository,
)

pytestmark = pytest.mark.unit

# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


@pytest.fixture
def trend_repo():
    return TrendRepository()


@pytest.fixture
def scan_repo():
    return ScanRepository()


@pytest.fixture
def observation_repo():
    return ObservationRepository()


@pytest.fixture
def comparison_repo():
    return ComparisonRepository()


@pytest.fixture
def engagement_repo():
    return EngagementRepository()


@pytest.fixture
def override_repo():
    return ObservationOverrideRepository()


async def _create_scan_with_observations(
    scan_repo, observation_repo, comparison_repo, scan_id, target, observations, engagement_id=None
):
    """Helper to create a completed scan with observations and compute statuses."""
    await scan_repo.create_scan(
        scan_id=scan_id,
        session_id=f"s-{scan_id}",
        target_domain=target,
        engagement_id=engagement_id,
    )
    await observation_repo.bulk_create(scan_id, observations)
    await scan_repo.complete_scan(scan_id, status="complete", observations_count=len(observations))
    await comparison_repo.compute_observation_statuses(scan_id)


# --- Single Scan Trend -------------------------------------------------------


class TestSingleScanTrend:
    @pytest.mark.asyncio
    async def test_target_trend_single_scan(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        trend_repo,
    ):
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "trend-s1",
            "example.com",
            [
                {
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "example.com",
                    "suite": "web",
                },
                {
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "example.com",
                    "suite": "web",
                },
                {
                    "title": "Info Leak",
                    "severity": "info",
                    "check_name": "info_leak",
                    "host": "example.com",
                    "suite": "network",
                },
            ],
        )

        result = await trend_repo.get_target_trend("example.com")
        assert len(result["data_points"]) == 1

        dp = result["data_points"][0]
        assert dp["scan_id"] == "trend-s1"
        assert dp["total"] == 3
        assert dp["critical"] == 1
        assert dp["high"] == 1
        assert dp["info"] == 1
        assert dp["medium"] == 0
        assert dp["low"] == 0

    @pytest.mark.asyncio
    async def test_risk_score_computation(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        trend_repo,
    ):
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "risk-s1",
            "risk.com",
            [
                {"title": "C1", "severity": "critical", "check_name": "c1", "host": "risk.com"},
                {"title": "C2", "severity": "critical", "check_name": "c2", "host": "risk.com"},
                {"title": "H1", "severity": "high", "check_name": "h1", "host": "risk.com"},
                {"title": "M1", "severity": "medium", "check_name": "m1", "host": "risk.com"},
                {"title": "L1", "severity": "low", "check_name": "l1", "host": "risk.com"},
            ],
        )

        result = await trend_repo.get_target_trend("risk.com")
        dp = result["data_points"][0]
        # 2*10 + 1*5 + 1*2 + 1*1 = 28
        assert dp["risk_score"] == 28

    @pytest.mark.asyncio
    async def test_suite_breakdown(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        trend_repo,
    ):
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "suite-s1",
            "suite.com",
            [
                {
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "suite.com",
                    "suite": "web",
                },
                {
                    "title": "F2",
                    "severity": "medium",
                    "check_name": "c2",
                    "host": "suite.com",
                    "suite": "web",
                },
                {
                    "title": "F3",
                    "severity": "low",
                    "check_name": "c3",
                    "host": "suite.com",
                    "suite": "ai",
                },
            ],
        )

        result = await trend_repo.get_target_trend("suite.com")
        dp = result["data_points"][0]
        assert dp["by_suite"]["web"] == 2
        assert dp["by_suite"]["ai"] == 1


# --- Multi-Scan Trend ---------------------------------------------------------


class TestMultiScanTrend:
    @pytest.mark.asyncio
    async def test_multiple_scans_chronological(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        trend_repo,
    ):
        """Multiple scans produce ordered data points."""
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "multi-s1",
            "multi.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "multi.com"},
            ],
        )
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "multi-s2",
            "multi.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "multi.com"},
                {"title": "F2", "severity": "critical", "check_name": "c2", "host": "multi.com"},
            ],
        )

        result = await trend_repo.get_target_trend("multi.com")
        assert len(result["data_points"]) == 2
        assert result["data_points"][0]["scan_id"] == "multi-s1"
        assert result["data_points"][1]["scan_id"] == "multi-s2"
        assert result["data_points"][0]["total"] == 1
        assert result["data_points"][1]["total"] == 2

    @pytest.mark.asyncio
    async def test_new_resolved_counts(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        trend_repo,
    ):
        """New/resolved counts come from ObservationStatusHistory."""
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "nr-s1",
            "nr.com",
            [
                {"title": "A", "severity": "high", "check_name": "a", "host": "nr.com"},
                {"title": "B", "severity": "medium", "check_name": "b", "host": "nr.com"},
            ],
        )
        # Second scan: A persists, B gone, C new
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "nr-s2",
            "nr.com",
            [
                {"title": "A", "severity": "high", "check_name": "a", "host": "nr.com"},
                {"title": "C", "severity": "low", "check_name": "c", "host": "nr.com"},
            ],
        )

        result = await trend_repo.get_target_trend("nr.com")
        dp1 = result["data_points"][0]
        dp2 = result["data_points"][1]

        # First scan: all new
        assert dp1["new"] == 2

        # Second scan: 1 new (C), 1 resolved (B)
        assert dp2["new"] == 1
        assert dp2["resolved"] == 1


# --- Empty Cases --------------------------------------------------------------


# --- Empty Cases --------------------------------------------------------------


class TestEmptyCases:
    @pytest.mark.asyncio
    async def test_empty_target_trend(self, db, trend_repo):
        result = await trend_repo.get_target_trend("nonexistent.com")
        assert result["data_points"] == []
        assert result["averages"]["this_target"] == {}
        assert result["averages"]["all_targets"] == {}

    @pytest.mark.asyncio
    async def test_empty_engagement_trend(self, db, trend_repo):
        result = await trend_repo.get_engagement_trend("nonexistent-eng")
        assert result["data_points"] == []

    @pytest.mark.asyncio
    async def test_incomplete_scans_excluded(
        self,
        db,
        scan_repo,
        observation_repo,
        trend_repo,
    ):
        """Running/error scans are not included in trend."""
        await scan_repo.create_scan(
            scan_id="running-scan",
            session_id="s1",
            target_domain="partial.com",
        )
        await observation_repo.bulk_create(
            "running-scan",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "partial.com"},
            ],
        )
        # Don't complete the scan

        result = await trend_repo.get_target_trend("partial.com")
        assert result["data_points"] == []
