"""Tests for repository CRUD operations."""

import pytest
from sqlalchemy import func, select

import app.db.engine as _engine_module
from app.db.engine import Database
from app.db.models import Chain, CheckLog, ObservationRecord, Scan
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
    """Initialize a SQLite database for testing."""
    database = Database()
    await database.init(backend="sqlite", db_path=tmp_path / "test.db")
    old_default = _engine_module._default_db
    _engine_module._default_db = database
    yield database
    _engine_module._default_db = old_default
    await database.close()


@pytest.fixture
def scan_repo(db):
    return ScanRepository(db)


@pytest.fixture
def observation_repo(db):
    return ObservationRepository(db)


@pytest.fixture
def chain_repo(db):
    return ChainRepository(db)


@pytest.fixture
def check_log_repo(db):
    return CheckLogRepository(db)


@pytest.fixture
def sample_observations():
    """Realistic observations as produced by checks."""
    return [
        {
            "title": "Cross-Site Scripting in Search",
            "description": "Reflected XSS via q parameter",
            "severity": "high",
            "check_name": "xss_reflected",
            "suite": "web",
            "host": "example.com",
            "target_url": "http://example.com/search?q=test",
            "evidence": "<script>alert(1)</script> reflected in response",
            "references": ["https://owasp.org/xss"],
        },
        {
            "title": "Missing Content-Security-Policy",
            "description": "No CSP header found",
            "severity": "medium",
            "check_name": "header_analysis",
            "suite": "web",
            "host": "example.com",
            "target_url": "http://example.com",
        },
        {
            "title": "SSH Service Detected",
            "severity": "info",
            "check_name": "port_scan",
            "suite": "network",
            "host": "example.com",
        },
    ]


@pytest.fixture
def sample_chains():
    """Realistic chains as produced by chain analysis."""
    return [
        {
            "title": "XSS to Session Hijack",
            "description": "Reflected XSS can steal session cookies",
            "severity": "high",
            "source": "rule-based",
            "observation_ids": ["f1", "f2"],
        },
        {
            "title": "Missing Headers Enable Attack",
            "description": "Lack of CSP allows XSS exploitation",
            "severity": "medium",
            "source": "llm",
            "observations": ["f2", "f3"],
        },
    ]


@pytest.fixture
def sample_check_log():
    """Realistic check log entries."""
    return [
        {"check": "port_scan", "event": "started", "suite": "network"},
        {"check": "port_scan", "event": "completed", "observations": 1, "suite": "network"},
        {"check": "xss_reflected", "event": "started", "suite": "web"},
        {"check": "xss_reflected", "event": "completed", "observations": 1, "suite": "web"},
        {"check": "header_analysis", "event": "started", "suite": "web"},
        {"check": "header_analysis", "event": "completed", "observations": 1, "suite": "web"},
    ]


# ─── ScanRepository Tests ────────────────────────────────────────────────────


class TestScanRepository:
    """Tests for scan CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_scan(self, db, scan_repo):
        """create_scan inserts a scan with status=running."""
        scan_id = await scan_repo.create_scan(
            scan_id="scan-001",
            session_id="sess-abc",
            target_domain="example.com",
        )
        assert scan_id == "scan-001"

        async with db.session() as session:
            result = await session.execute(select(Scan).where(Scan.id == "scan-001"))
            scan = result.scalar_one()
            assert scan.target_domain == "example.com"
            assert scan.session_id == "sess-abc"
            assert scan.status == "running"
            assert scan.started_at is not None

    @pytest.mark.asyncio
    async def test_create_scan_with_metadata(self, db, scan_repo):
        """create_scan stores optional settings and scenario."""
        await scan_repo.create_scan(
            scan_id="scan-002",
            session_id="sess-abc",
            target_domain="example.com",
            settings={"parallel": True, "rate_limit": 5.0},
            scenario_name="api_pentest",
            profile_name="aggressive",
        )

        async with db.session() as session:
            result = await session.execute(select(Scan).where(Scan.id == "scan-002"))
            scan = result.scalar_one()
            assert scan.settings == {"parallel": True, "rate_limit": 5.0}
            assert scan.scenario_name == "api_pentest"
            assert scan.profile_name == "aggressive"

    @pytest.mark.asyncio
    async def test_complete_scan(self, db, scan_repo):
        """complete_scan updates status and stats."""
        await scan_repo.create_scan(
            scan_id="scan-003",
            session_id="sess-abc",
            target_domain="example.com",
        )
        await scan_repo.complete_scan(
            scan_id="scan-003",
            status="complete",
            checks_total=10,
            checks_completed=9,
            checks_failed=1,
            observations_count=5,
            duration_ms=12345,
        )

        async with db.session() as session:
            result = await session.execute(select(Scan).where(Scan.id == "scan-003"))
            scan = result.scalar_one()
            assert scan.status == "complete"
            assert scan.checks_total == 10
            assert scan.checks_completed == 9
            assert scan.checks_failed == 1
            assert scan.observations_count == 5
            assert scan.duration_ms == 12345
            assert scan.completed_at is not None

    @pytest.mark.asyncio
    async def test_complete_scan_with_error(self, db, scan_repo):
        """complete_scan records error state."""
        await scan_repo.create_scan(
            scan_id="scan-004",
            session_id="sess-abc",
            target_domain="example.com",
        )
        await scan_repo.complete_scan(
            scan_id="scan-004",
            status="error",
            error_message="Connection refused",
        )

        async with db.session() as session:
            result = await session.execute(select(Scan).where(Scan.id == "scan-004"))
            scan = result.scalar_one()
            assert scan.status == "error"
            assert scan.error_message == "Connection refused"

    @pytest.mark.asyncio
    async def test_complete_nonexistent_scan(self, db, scan_repo):
        """complete_scan on missing ID logs warning but doesn't raise."""
        # Should not raise
        await scan_repo.complete_scan(scan_id="nonexistent", status="complete")


# ─── ObservationRepository Tests ─────────────────────────────────────────────────


class TestObservationRepository:
    """Tests for observation persistence."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, db, observation_repo, sample_observations):
        """bulk_create inserts all observations and returns count."""
        count = await observation_repo.bulk_create("scan-001", sample_observations)
        assert count == 3

        async with db.session() as session:
            result = await session.execute(
                select(func.count())
                .select_from(ObservationRecord)
                .where(ObservationRecord.scan_id == "scan-001")
            )
            assert result.scalar() == 3

    @pytest.mark.asyncio
    async def test_bulk_create_empty(self, db, observation_repo):
        """bulk_create with empty list returns 0."""
        count = await observation_repo.bulk_create("scan-001", [])
        assert count == 0

    @pytest.mark.asyncio
    async def test_observations_have_fingerprints(self, db, observation_repo, sample_observations):
        """Each observation gets a fingerprint assigned."""
        await observation_repo.bulk_create("scan-001", sample_observations)

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord).where(ObservationRecord.scan_id == "scan-001")
            )
            observations = result.scalars().all()
            for f in observations:
                assert f.fingerprint is not None
                assert len(f.fingerprint) == 16

    @pytest.mark.asyncio
    async def test_observations_have_unique_ids(self, db, observation_repo, sample_observations):
        """Each observation gets a unique ID."""
        await observation_repo.bulk_create("scan-001", sample_observations)

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord.id).where(ObservationRecord.scan_id == "scan-001")
            )
            ids = [row[0] for row in result.all()]
            assert len(ids) == len(set(ids))

    @pytest.mark.asyncio
    async def test_observation_fields_mapped(self, db, observation_repo):
        """Observation fields are correctly mapped from dict."""
        await observation_repo.bulk_create(
            "scan-001",
            [
                {
                    "title": "Test XSS",
                    "description": "Reflected XSS",
                    "severity": "high",
                    "check_name": "xss_check",
                    "suite": "web",
                    "host": "example.com",
                    "target_url": "http://example.com/search",
                    "evidence": "alert(1) in response",
                    "references": ["https://owasp.org"],
                    "confidence": 0.95,
                }
            ],
        )

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord).where(ObservationRecord.scan_id == "scan-001")
            )
            f = result.scalar_one()
            assert f.title == "Test XSS"
            assert f.description == "Reflected XSS"
            assert f.severity == "high"
            assert f.check_name == "xss_check"
            assert f.suite == "web"
            assert f.host == "example.com"
            assert f.target_url == "http://example.com/search"
            assert f.evidence == "alert(1) in response"
            assert f.references == ["https://owasp.org"]
            assert f.confidence == 0.95

    @pytest.mark.asyncio
    async def test_observation_uses_check_fallback(self, db, observation_repo):
        """Observation maps 'check' key when 'check_name' is missing."""
        await observation_repo.bulk_create(
            "scan-001",
            [
                {
                    "title": "Test",
                    "severity": "info",
                    "check": "legacy_check_name",
                }
            ],
        )

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord).where(ObservationRecord.scan_id == "scan-001")
            )
            f = result.scalar_one()
            assert f.check_name == "legacy_check_name"

    @pytest.mark.asyncio
    async def test_observation_preserves_existing_id(self, db, observation_repo):
        """If a observation has an 'id' field, it is scoped with the scan_id prefix."""
        await observation_repo.bulk_create(
            "scan-001",
            [
                {
                    "id": "custom-id-123",
                    "title": "Test",
                    "severity": "info",
                    "check_name": "test",
                }
            ],
        )

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord).where(ObservationRecord.id == "scan-001-custom-id-123")
            )
            f = result.scalar_one()
            assert f.id == "scan-001-custom-id-123"


# ─── ChainRepository Tests ──────────────────────────────────────────────────


class TestChainRepository:
    """Tests for chain persistence."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, db, chain_repo, sample_chains):
        """bulk_create inserts all chains."""
        count = await chain_repo.bulk_create("scan-001", sample_chains)
        assert count == 2

        async with db.session() as session:
            result = await session.execute(
                select(func.count()).select_from(Chain).where(Chain.scan_id == "scan-001")
            )
            assert result.scalar() == 2

    @pytest.mark.asyncio
    async def test_bulk_create_empty(self, db, chain_repo):
        """bulk_create with empty list returns 0."""
        count = await chain_repo.bulk_create("scan-001", [])
        assert count == 0

    @pytest.mark.asyncio
    async def test_chain_fields_mapped(self, db, chain_repo):
        """Chain fields are correctly mapped from dict."""
        await chain_repo.bulk_create(
            "scan-001",
            [
                {
                    "title": "Test Chain",
                    "description": "A test chain",
                    "severity": "critical",
                    "source": "llm",
                    "observation_ids": ["f1", "f2", "f3"],
                }
            ],
        )

        async with db.session() as session:
            result = await session.execute(select(Chain).where(Chain.scan_id == "scan-001"))
            c = result.scalar_one()
            assert c.title == "Test Chain"
            assert c.severity == "critical"
            assert c.source == "llm"
            assert c.observation_ids == ["f1", "f2", "f3"]

    @pytest.mark.asyncio
    async def test_chain_observations_fallback(self, db, chain_repo):
        """Chain maps 'observations' key when 'observation_ids' is missing."""
        await chain_repo.bulk_create(
            "scan-001",
            [
                {
                    "title": "Test",
                    "severity": "high",
                    "source": "rule-based",
                    "observations": ["a", "b"],
                }
            ],
        )

        async with db.session() as session:
            result = await session.execute(select(Chain).where(Chain.scan_id == "scan-001"))
            c = result.scalar_one()
            assert c.observation_ids == ["a", "b"]


# ─── CheckLogRepository Tests ───────────────────────────────────────────────


class TestCheckLogRepository:
    """Tests for check log persistence."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, db, check_log_repo, sample_check_log):
        """bulk_create inserts all log entries."""
        count = await check_log_repo.bulk_create("scan-001", sample_check_log)
        assert count == 6

        async with db.session() as session:
            result = await session.execute(
                select(func.count()).select_from(CheckLog).where(CheckLog.scan_id == "scan-001")
            )
            assert result.scalar() == 6

    @pytest.mark.asyncio
    async def test_bulk_create_empty(self, db, check_log_repo):
        """bulk_create with empty list returns 0."""
        count = await check_log_repo.bulk_create("scan-001", [])
        assert count == 0

    @pytest.mark.asyncio
    async def test_log_entry_fields(self, db, check_log_repo):
        """Log entry fields are correctly mapped."""
        await check_log_repo.bulk_create(
            "scan-001",
            [
                {
                    "check": "port_scan",
                    "event": "completed",
                    "observations": 3,
                    "suite": "network",
                    "duration_ms": 1500,
                }
            ],
        )

        async with db.session() as session:
            result = await session.execute(select(CheckLog).where(CheckLog.scan_id == "scan-001"))
            entry = result.scalar_one()
            assert entry.check_name == "port_scan"
            assert entry.event == "completed"
            assert entry.observations_count == 3
            assert entry.suite == "network"
            assert entry.duration_ms == 1500

    @pytest.mark.asyncio
    async def test_log_entries_have_auto_ids(self, db, check_log_repo, sample_check_log):
        """Log entries get auto-incrementing integer IDs."""
        await check_log_repo.bulk_create("scan-001", sample_check_log)

        async with db.session() as session:
            result = await session.execute(
                select(CheckLog.id).where(CheckLog.scan_id == "scan-001")
            )
            ids = [row[0] for row in result.all()]
            assert len(ids) == 6
            assert ids == sorted(ids)  # Auto-increment means sorted
