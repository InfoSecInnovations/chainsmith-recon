"""
Tests for Phase 2 scan history API endpoints and modified existing endpoints.

Tests the new /api/scans/* routes and the ?scan_id= parameter on
existing /api/observations and /api/chains endpoints.
"""

import pytest
from sqlalchemy import func, select

from app.db.engine import close_db, get_session, init_db
from app.db.models import Chain, CheckLog, ObservationRecord
from app.db.repositories import (
    ChainRepository,
    CheckLogRepository,
    ObservationRepository,
    ScanRepository,
)

pytestmark = pytest.mark.integration

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
async def db(tmp_path):
    """Initialize test database."""
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


@pytest.fixture
async def seeded_db(db):
    """Database with two scans and sample data."""
    scan_repo = ScanRepository()
    observation_repo = ObservationRepository()
    chain_repo = ChainRepository()
    log_repo = CheckLogRepository()

    # Scan 1: completed with observations
    await scan_repo.create_scan(
        scan_id="scan-aaa",
        session_id="sess-1",
        target_domain="example.com",
        settings={"parallel": False},
        scenario_name="web_check",
    )
    await observation_repo.bulk_create(
        "scan-aaa",
        [
            {
                "id": "f-001",
                "title": "XSS in Search",
                "severity": "high",
                "check_name": "xss_check",
                "suite": "web",
                "host": "example.com",
                "target_url": "http://example.com/search",
                "evidence": "alert(1)",
            },
            {
                "id": "f-002",
                "title": "Missing CSP",
                "severity": "medium",
                "check_name": "header_check",
                "suite": "web",
                "host": "example.com",
            },
            {
                "id": "f-003",
                "title": "SSH Open",
                "severity": "info",
                "check_name": "port_scan",
                "suite": "network",
                "host": "api.example.com",
            },
        ],
    )
    await chain_repo.bulk_create(
        "scan-aaa",
        [
            {
                "id": "c-001",
                "title": "XSS to Session Hijack",
                "severity": "high",
                "source": "rule-based",
                "observation_ids": ["f-001", "f-002"],
            },
        ],
    )
    await log_repo.bulk_create(
        "scan-aaa",
        [
            {"check": "xss_check", "event": "started", "suite": "web"},
            {"check": "xss_check", "event": "completed", "observations": 1, "suite": "web"},
            {"check": "header_check", "event": "started", "suite": "web"},
            {"check": "header_check", "event": "completed", "observations": 1, "suite": "web"},
        ],
    )
    await scan_repo.complete_scan(
        "scan-aaa",
        status="complete",
        checks_total=2,
        checks_completed=2,
        checks_failed=0,
        observations_count=3,
        duration_ms=5000,
    )

    # Scan 2: completed, different target
    await scan_repo.create_scan(
        scan_id="scan-bbb",
        session_id="sess-2",
        target_domain="other.com",
    )
    await observation_repo.bulk_create(
        "scan-bbb",
        [
            {
                "id": "f-010",
                "title": "SQLi in Login",
                "severity": "critical",
                "check_name": "sqli_check",
                "host": "other.com",
            },
        ],
    )
    await scan_repo.complete_scan(
        "scan-bbb",
        status="complete",
        checks_total=1,
        checks_completed=1,
        observations_count=1,
    )

    return {"scan_a": "scan-aaa", "scan_b": "scan-bbb"}


# ─── ScanRepository Read Tests ──────────────────────────────────────────────


class TestScanRepositoryReads:
    """Tests for scan query methods."""

    @pytest.mark.asyncio
    async def test_get_scan(self, seeded_db):
        repo = ScanRepository()
        scan = await repo.get_scan("scan-aaa")
        assert scan is not None
        assert scan["id"] == "scan-aaa"
        assert scan["target_domain"] == "example.com"
        assert scan["status"] == "complete"
        assert scan["observations_count"] == 3
        assert scan["duration_ms"] == 5000
        assert scan["started_at"] is not None
        assert scan["completed_at"] is not None

    @pytest.mark.asyncio
    async def test_get_scan_not_found(self, seeded_db):
        repo = ScanRepository()
        scan = await repo.get_scan("nonexistent")
        assert scan is None

    @pytest.mark.asyncio
    async def test_list_scans_all(self, seeded_db):
        repo = ScanRepository()
        result = await repo.list_scans()
        assert result["total"] == 2
        assert len(result["scans"]) == 2
        # Most recent first
        assert result["scans"][0]["id"] == "scan-bbb"

    @pytest.mark.asyncio
    async def test_list_scans_filter_target(self, seeded_db):
        repo = ScanRepository()
        result = await repo.list_scans(target="example.com")
        assert result["total"] == 1
        assert result["scans"][0]["target_domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_list_scans_filter_status(self, seeded_db):
        repo = ScanRepository()
        result = await repo.list_scans(status="complete")
        assert result["total"] == 2

        result = await repo.list_scans(status="error")
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_list_scans_pagination(self, seeded_db):
        repo = ScanRepository()
        result = await repo.list_scans(limit=1, offset=0)
        assert result["total"] == 2
        assert len(result["scans"]) == 1
        first_id = result["scans"][0]["id"]

        result = await repo.list_scans(limit=1, offset=1)
        assert result["total"] == 2
        assert len(result["scans"]) == 1
        assert result["scans"][0]["id"] != first_id

    @pytest.mark.asyncio
    async def test_delete_scan(self, seeded_db):
        repo = ScanRepository()
        deleted = await repo.delete_scan("scan-aaa")
        assert deleted is True

        # Verify scan is gone
        scan = await repo.get_scan("scan-aaa")
        assert scan is None

        # Verify related data is gone
        async with get_session() as session:
            result = await session.execute(
                select(func.count())
                .select_from(ObservationRecord)
                .where(ObservationRecord.scan_id == "scan-aaa")
            )
            assert result.scalar() == 0
            result = await session.execute(
                select(func.count()).select_from(Chain).where(Chain.scan_id == "scan-aaa")
            )
            assert result.scalar() == 0
            result = await session.execute(
                select(func.count()).select_from(CheckLog).where(CheckLog.scan_id == "scan-aaa")
            )
            assert result.scalar() == 0

        # Other scan is untouched
        other = await repo.get_scan("scan-bbb")
        assert other is not None

    @pytest.mark.asyncio
    async def test_delete_scan_not_found(self, seeded_db):
        repo = ScanRepository()
        deleted = await repo.delete_scan("nonexistent")
        assert deleted is False


# ─── ObservationRepository Read Tests ───────────────────────────────────────────


class TestObservationRepositoryReads:
    """Tests for observation query methods."""

    @pytest.mark.asyncio
    async def test_get_observations(self, seeded_db):
        repo = ObservationRepository()
        observations = await repo.get_observations("scan-aaa")
        assert len(observations) == 3
        titles = {f["title"] for f in observations}
        assert "XSS in Search" in titles
        assert "Missing CSP" in titles

    @pytest.mark.asyncio
    async def test_get_observations_filter_severity(self, seeded_db):
        repo = ObservationRepository()
        observations = await repo.get_observations("scan-aaa", severity="high")
        assert len(observations) == 1
        assert observations[0]["title"] == "XSS in Search"

    @pytest.mark.asyncio
    async def test_get_observations_filter_host(self, seeded_db):
        repo = ObservationRepository()
        observations = await repo.get_observations("scan-aaa", host="api.example.com")
        assert len(observations) == 1
        assert observations[0]["title"] == "SSH Open"

    @pytest.mark.asyncio
    async def test_get_observations_empty_scan(self, seeded_db):
        repo = ObservationRepository()
        observations = await repo.get_observations("nonexistent-scan")
        assert observations == []

    @pytest.mark.asyncio
    async def test_get_observations_by_host(self, seeded_db):
        repo = ObservationRepository()
        hosts = await repo.get_observations_by_host("scan-aaa")
        assert len(hosts) == 2  # example.com and api.example.com
        host_names = {h["name"] for h in hosts}
        assert "example.com" in host_names
        assert "api.example.com" in host_names

        # Check counts per host
        for h in hosts:
            if h["name"] == "example.com":
                assert len(h["observations"]) == 2
            elif h["name"] == "api.example.com":
                assert len(h["observations"]) == 1

    @pytest.mark.asyncio
    async def test_observation_dict_shape(self, seeded_db):
        """Observation dicts have all expected keys."""
        repo = ObservationRepository()
        observations = await repo.get_observations("scan-aaa", severity="high")
        f = observations[0]
        expected_keys = {
            "id",
            "scan_id",
            "title",
            "description",
            "severity",
            "original_severity",
            "severity_override_reason",
            "override_source",
            "check_name",
            "suite",
            "target_url",
            "target_host",
            "host",
            "evidence",
            "raw_data",
            "references",
            "verification_status",
            "confidence",
            "fingerprint",
            "created_at",
        }
        assert expected_keys == set(f.keys())


# ─── ChainRepository Read Tests ─────────────────────────────────────────────


class TestChainRepositoryReads:
    """Tests for chain query methods."""

    @pytest.mark.asyncio
    async def test_get_chains(self, seeded_db):
        repo = ChainRepository()
        chains = await repo.get_chains("scan-aaa")
        assert len(chains) == 1
        assert chains[0]["title"] == "XSS to Session Hijack"
        assert chains[0]["observation_ids"] == ["f-001", "f-002"]

    @pytest.mark.asyncio
    async def test_get_chains_empty(self, seeded_db):
        repo = ChainRepository()
        chains = await repo.get_chains("scan-bbb")
        assert chains == []

    @pytest.mark.asyncio
    async def test_chain_dict_shape(self, seeded_db):
        repo = ChainRepository()
        chains = await repo.get_chains("scan-aaa")
        expected_keys = {
            "id",
            "scan_id",
            "title",
            "description",
            "severity",
            "source",
            "observation_ids",
            "created_at",
        }
        assert expected_keys == set(chains[0].keys())


# ─── CheckLogRepository Read Tests ──────────────────────────────────────────


class TestCheckLogRepositoryReads:
    """Tests for check log query methods."""

    @pytest.mark.asyncio
    async def test_get_log(self, seeded_db):
        repo = CheckLogRepository()
        log = await repo.get_log("scan-aaa")
        assert len(log) == 4
        # Should be ordered by ID (insertion order)
        assert log[0]["check"] == "xss_check"
        assert log[0]["event"] == "started"

    @pytest.mark.asyncio
    async def test_get_log_empty(self, seeded_db):
        repo = CheckLogRepository()
        log = await repo.get_log("nonexistent")
        assert log == []

    @pytest.mark.asyncio
    async def test_log_dict_shape(self, seeded_db):
        repo = CheckLogRepository()
        log = await repo.get_log("scan-aaa")
        expected_keys = {
            "check",
            "suite",
            "event",
            "observations",
            "duration_ms",
            "error_message",
            "timestamp",
            "event_seq",
        }
        assert expected_keys == set(log[0].keys())


# ─── Scan Dict Shape Tests ──────────────────────────────────────────────────


class TestScanDictShape:
    """Tests for scan serialization."""

    @pytest.mark.asyncio
    async def test_scan_dict_keys(self, seeded_db):
        repo = ScanRepository()
        scan = await repo.get_scan("scan-aaa")
        expected_keys = {
            "id",
            "session_id",
            "target_domain",
            "status",
            "started_at",
            "completed_at",
            "duration_ms",
            "checks_total",
            "checks_completed",
            "checks_failed",
            "observations_count",
            "scope",
            "settings",
            "profile_name",
            "scenario_name",
            "error_message",
            "adjudication_status",
            "adjudication_error",
            "chain_status",
            "chain_error",
            "chain_llm_analysis",
        }
        assert expected_keys == set(scan.keys())

    @pytest.mark.asyncio
    async def test_scan_timestamps_are_iso(self, seeded_db):
        import re

        repo = ScanRepository()
        scan = await repo.get_scan("scan-aaa")
        # Validate full ISO 8601 format: YYYY-MM-DDTHH:MM:SS (with optional fractional seconds and timezone)
        iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
        assert iso_pattern.match(scan["started_at"]), (
            f"started_at is not ISO 8601: {scan['started_at']}"
        )
        assert iso_pattern.match(scan["completed_at"]), (
            f"completed_at is not ISO 8601: {scan['completed_at']}"
        )
