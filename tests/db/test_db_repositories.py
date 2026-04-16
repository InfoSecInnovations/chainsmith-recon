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
    async def test_observation_event_seq_persisted(self, db, observation_repo):
        """Phase 51.1b: event_seq passes through bulk_create into the DB."""
        await observation_repo.bulk_create(
            "scan-001",
            [
                {
                    "id": "a",
                    "title": "x",
                    "severity": "info",
                    "check_name": "c",
                    "host": "h",
                    "event_seq": 42,
                },
                {"id": "b", "title": "y", "severity": "info", "check_name": "c", "host": "h"},
            ],
        )
        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord.event_seq)
                .where(ObservationRecord.scan_id == "scan-001")
                .order_by(ObservationRecord.id)
            )
            seqs = sorted([row[0] for row in result.all()], key=lambda v: (v is None, v))
            assert seqs == [42, None]

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

    # ─── Phase 51.1b: event_seq wiring ──────────────────────────────────

    @pytest.mark.asyncio
    async def test_event_seq_persisted_and_exposed(self, db, check_log_repo):
        """event_seq passes through bulk_create and appears in get_log output."""
        await check_log_repo.bulk_create(
            "scan-001",
            [
                {"check": "a", "event": "started", "event_seq": 1},
                {"check": "a", "event": "completed", "event_seq": 7, "observations": 2},
                {"check": "b", "event": "started"},  # no seq — stays NULL
            ],
        )
        entries = await check_log_repo.get_log("scan-001")
        by_event = {(e["check"], e["event"]): e for e in entries}
        assert by_event[("a", "started")]["event_seq"] == 1
        assert by_event[("a", "completed")]["event_seq"] == 7
        assert by_event[("b", "started")]["event_seq"] is None

    @pytest.mark.asyncio
    async def test_to_sse_event_maps_event_types(self, db, check_log_repo):
        """CheckLog.to_sse_event() is the shared live/replay mapping."""
        await check_log_repo.bulk_create(
            "scan-001",
            [
                {"check": "a", "event": "started", "suite": "s"},
                {"check": "a", "event": "completed", "observations": 3},
                {"check": "b", "event": "failed", "error_message": "boom"},
                {"check": "c", "event": "skipped", "error_message": "precondition"},
            ],
        )
        async with db.session() as session:
            result = await session.execute(
                select(CheckLog).where(CheckLog.scan_id == "scan-001").order_by(CheckLog.id)
            )
            rows = list(result.scalars().all())

        types_and_payloads = [r.to_sse_event() for r in rows]
        assert types_and_payloads[0] == ("check_started", {"name": "a", "suite": "s"})
        assert types_and_payloads[1][0] == "check_completed"
        assert types_and_payloads[1][1]["success"] is True
        assert types_and_payloads[1][1]["observations"] == 3
        assert types_and_payloads[2][0] == "check_completed"
        assert types_and_payloads[2][1]["success"] is False
        assert types_and_payloads[2][1]["error"] == "boom"
        assert types_and_payloads[3] == (
            "check_skipped",
            {"name": "c", "suite": None, "reason": "precondition"},
        )

    # ─── Phase 51.3b: DB-backed replay ──────────────────────────────────

    @pytest.mark.asyncio
    async def test_check_log_get_events_since_range(self, db, check_log_repo):
        """get_events_since returns rows in (last_seq, upper_seq] ordered by seq."""
        await check_log_repo.bulk_create(
            "scan-R",
            [
                {"check": "a", "event": "started", "event_seq": 1},
                {"check": "a", "event": "completed", "event_seq": 4, "observations": 2},
                {"check": "b", "event": "started", "event_seq": 5},
                {"check": "b", "event": "skipped", "event_seq": 9, "error_message": "precond"},
                {"check": "c", "event": "started"},  # NULL seq — excluded
            ],
        )
        events = await check_log_repo.get_events_since("scan-R", last_seq=1, upper_seq=5)
        assert [seq for seq, _, _ in events] == [4, 5]
        assert events[0][1] == "check_completed"
        assert events[1][1] == "check_started"
        # Empty range is a no-op.
        assert await check_log_repo.get_events_since("scan-R", 10, 10) == []
        # upper_seq < last_seq is also a no-op.
        assert await check_log_repo.get_events_since("scan-R", 10, 5) == []


class TestObservationRepositoryReplay:
    """Phase 51.3b: DB-backed replay for observation_added events."""

    @pytest.mark.asyncio
    async def test_get_events_since_range(self, db, observation_repo):
        await observation_repo.bulk_create(
            "scan-OR",
            [
                {
                    "id": "a",
                    "title": "x",
                    "severity": "low",
                    "check_name": "c1",
                    "host": "h1",
                    "event_seq": 2,
                },
                {
                    "id": "b",
                    "title": "y",
                    "severity": "high",
                    "check_name": "c2",
                    "host": "h2",
                    "event_seq": 6,
                },
                {
                    "id": "c",
                    "title": "z",
                    "severity": "info",
                    "check_name": "c3",
                    "host": "h3",
                    "event_seq": 11,
                },
                {
                    "id": "d",
                    "title": "w",
                    "severity": "info",
                    "check_name": "c4",
                    "host": "h4",
                },  # NULL seq — excluded
            ],
        )
        events = await observation_repo.get_events_since("scan-OR", last_seq=2, upper_seq=10)
        assert [seq for seq, _ in events] == [6]
        assert events[0][1]["severity"] == "high"
        assert events[0][1]["host"] == "h2"
        assert events[0][1]["check"] == "c2"
        # Inclusive of upper bound.
        events = await observation_repo.get_events_since("scan-OR", 5, 6)
        assert [seq for seq, _ in events] == [6]
        # Empty range.
        assert await observation_repo.get_events_since("scan-OR", 11, 11) == []
