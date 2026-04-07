"""
Tests for trend analysis (Phase 4b).

Covers TrendRepository: data points, risk scores, severity breakdown,
suite breakdown, override exclusion, and averages.
"""

import pytest

from app.db.engine import close_db, get_session, init_db
from app.db.models import ObservationRecord
from app.db.repositories import (
    SEVERITY_WEIGHTS,
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


# --- Engagement Trend ---------------------------------------------------------


class TestEngagementTrend:
    @pytest.mark.asyncio
    async def test_engagement_trend(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        engagement_repo,
        trend_repo,
    ):
        eng = await engagement_repo.create_engagement(
            name="Test Eng",
            target_domain="eng.com",
        )
        eid = eng["id"]

        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "eng-s1",
            "eng.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "eng.com"},
            ],
            engagement_id=eid,
        )

        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "eng-s2",
            "eng.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "eng.com"},
                {"title": "F2", "severity": "medium", "check_name": "c2", "host": "eng.com"},
            ],
            engagement_id=eid,
        )

        result = await trend_repo.get_engagement_trend(eid)
        assert len(result["data_points"]) == 2
        assert result["data_points"][0]["scan_id"] == "eng-s1"
        assert result["data_points"][1]["scan_id"] == "eng-s2"

    @pytest.mark.asyncio
    async def test_engagement_trend_excludes_other_engagements(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        engagement_repo,
        trend_repo,
    ):
        eng_a = await engagement_repo.create_engagement(name="A", target_domain="shared.com")
        eng_b = await engagement_repo.create_engagement(name="B", target_domain="shared.com")

        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "ea-s1",
            "shared.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "shared.com"},
            ],
            engagement_id=eng_a["id"],
        )

        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "eb-s1",
            "shared.com",
            [
                {"title": "F2", "severity": "low", "check_name": "c2", "host": "shared.com"},
            ],
            engagement_id=eng_b["id"],
        )

        result_a = await trend_repo.get_engagement_trend(eng_a["id"])
        assert len(result_a["data_points"]) == 1
        assert result_a["data_points"][0]["scan_id"] == "ea-s1"


# --- Override Exclusion -------------------------------------------------------


class TestOverrideExclusion:
    @pytest.mark.asyncio
    async def test_overridden_observations_excluded(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        override_repo,
        trend_repo,
    ):
        """Observations with active overrides are excluded from trend counts."""
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "ov-s1",
            "ov.com",
            [
                {"title": "XSS", "severity": "high", "check_name": "xss", "host": "ov.com"},
                {"title": "FP", "severity": "critical", "check_name": "fp_check", "host": "ov.com"},
            ],
        )

        # Get the FP observation's fingerprint and override it
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(ObservationRecord.title == "FP")
            )
            fp_fingerprint = result.scalar_one()

        await override_repo.set_override(fp_fingerprint, "false_positive", reason="Not real")

        result = await trend_repo.get_target_trend("ov.com")
        dp = result["data_points"][0]

        # Only 1 observation should be counted (the XSS), not the false positive
        assert dp["total"] == 1
        assert dp["high"] == 1
        assert dp["critical"] == 0
        # Risk should only reflect the non-overridden observation
        assert dp["risk_score"] == SEVERITY_WEIGHTS["high"]


# --- Averages -----------------------------------------------------------------


class TestAverages:
    @pytest.mark.asyncio
    async def test_this_target_averages(
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
            "avg-s1",
            "avg.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "avg.com"},
            ],
        )
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "avg-s2",
            "avg.com",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "avg.com"},
                {"title": "F2", "severity": "high", "check_name": "c2", "host": "avg.com"},
                {"title": "F3", "severity": "medium", "check_name": "c3", "host": "avg.com"},
            ],
        )

        result = await trend_repo.get_target_trend("avg.com")
        avgs = result["averages"]["this_target"]
        # Scan 1: total=1, Scan 2: total=3 -> avg=2.0
        assert avgs["total"] == 2.0
        # Scan 1: high=1, Scan 2: high=2 -> avg=1.5
        assert avgs["high"] == 1.5

    @pytest.mark.asyncio
    async def test_all_targets_averages(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        trend_repo,
    ):
        """all_targets averages span the entire database."""
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "at-s1",
            "alpha.com",
            [
                {"title": "F1", "severity": "critical", "check_name": "c1", "host": "alpha.com"},
            ],
        )
        await _create_scan_with_observations(
            scan_repo,
            observation_repo,
            comparison_repo,
            "at-s2",
            "beta.com",
            [
                {"title": "F1", "severity": "low", "check_name": "c1", "host": "beta.com"},
                {"title": "F2", "severity": "low", "check_name": "c2", "host": "beta.com"},
                {"title": "F3", "severity": "low", "check_name": "c3", "host": "beta.com"},
            ],
        )

        # Query alpha.com — its averages should be different from all_targets
        result = await trend_repo.get_target_trend("alpha.com")

        this_avg = result["averages"]["this_target"]
        all_avg = result["averages"]["all_targets"]

        # this_target: 1 scan with 1 critical
        assert this_avg["total"] == 1.0
        assert this_avg["critical"] == 1.0

        # all_targets: 2 scans, totals 1 and 3 -> avg 2.0
        assert all_avg["total"] == 2.0


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
