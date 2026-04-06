"""Tests for repository CRUD operations and the scan persistence orchestrator."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import func, select

from app.db.engine import close_db, get_session, init_db
from app.db.models import Chain, CheckLog, Finding, Scan
from app.db.repositories import (
    ChainRepository,
    CheckLogRepository,
    FindingRepository,
    ScanRepository,
)


pytestmark = pytest.mark.integration

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
async def db(tmp_path):
    """Initialize an in-memory SQLite database for testing."""
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


@pytest.fixture
def scan_repo():
    return ScanRepository()


@pytest.fixture
def finding_repo():
    return FindingRepository()


@pytest.fixture
def chain_repo():
    return ChainRepository()


@pytest.fixture
def check_log_repo():
    return CheckLogRepository()


@pytest.fixture
def sample_findings():
    """Realistic findings as produced by checks."""
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
            "finding_ids": ["f1", "f2"],
        },
        {
            "title": "Missing Headers Enable Attack",
            "description": "Lack of CSP allows XSS exploitation",
            "severity": "medium",
            "source": "llm",
            "findings": ["f2", "f3"],
        },
    ]


@pytest.fixture
def sample_check_log():
    """Realistic check log entries."""
    return [
        {"check": "port_scan", "event": "started", "suite": "network"},
        {"check": "port_scan", "event": "completed", "findings": 1, "suite": "network"},
        {"check": "xss_reflected", "event": "started", "suite": "web"},
        {"check": "xss_reflected", "event": "completed", "findings": 1, "suite": "web"},
        {"check": "header_analysis", "event": "started", "suite": "web"},
        {"check": "header_analysis", "event": "completed", "findings": 1, "suite": "web"},
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

        async with get_session() as session:
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

        async with get_session() as session:
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
            findings_count=5,
            duration_ms=12345,
        )

        async with get_session() as session:
            result = await session.execute(select(Scan).where(Scan.id == "scan-003"))
            scan = result.scalar_one()
            assert scan.status == "complete"
            assert scan.checks_total == 10
            assert scan.checks_completed == 9
            assert scan.checks_failed == 1
            assert scan.findings_count == 5
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

        async with get_session() as session:
            result = await session.execute(select(Scan).where(Scan.id == "scan-004"))
            scan = result.scalar_one()
            assert scan.status == "error"
            assert scan.error_message == "Connection refused"

    @pytest.mark.asyncio
    async def test_complete_nonexistent_scan(self, db, scan_repo):
        """complete_scan on missing ID logs warning but doesn't raise."""
        # Should not raise
        await scan_repo.complete_scan(scan_id="nonexistent", status="complete")


# ─── FindingRepository Tests ─────────────────────────────────────────────────


class TestFindingRepository:
    """Tests for finding persistence."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, db, finding_repo, sample_findings):
        """bulk_create inserts all findings and returns count."""
        count = await finding_repo.bulk_create("scan-001", sample_findings)
        assert count == 3

        async with get_session() as session:
            result = await session.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == "scan-001")
            )
            assert result.scalar() == 3

    @pytest.mark.asyncio
    async def test_bulk_create_empty(self, db, finding_repo):
        """bulk_create with empty list returns 0."""
        count = await finding_repo.bulk_create("scan-001", [])
        assert count == 0

    @pytest.mark.asyncio
    async def test_findings_have_fingerprints(self, db, finding_repo, sample_findings):
        """Each finding gets a fingerprint assigned."""
        await finding_repo.bulk_create("scan-001", sample_findings)

        async with get_session() as session:
            result = await session.execute(select(Finding).where(Finding.scan_id == "scan-001"))
            findings = result.scalars().all()
            for f in findings:
                assert f.fingerprint is not None
                assert len(f.fingerprint) == 16

    @pytest.mark.asyncio
    async def test_findings_have_unique_ids(self, db, finding_repo, sample_findings):
        """Each finding gets a unique ID."""
        await finding_repo.bulk_create("scan-001", sample_findings)

        async with get_session() as session:
            result = await session.execute(select(Finding.id).where(Finding.scan_id == "scan-001"))
            ids = [row[0] for row in result.all()]
            assert len(ids) == len(set(ids))

    @pytest.mark.asyncio
    async def test_finding_fields_mapped(self, db, finding_repo):
        """Finding fields are correctly mapped from dict."""
        await finding_repo.bulk_create(
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

        async with get_session() as session:
            result = await session.execute(select(Finding).where(Finding.scan_id == "scan-001"))
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
    async def test_finding_uses_check_fallback(self, db, finding_repo):
        """Finding maps 'check' key when 'check_name' is missing."""
        await finding_repo.bulk_create(
            "scan-001",
            [
                {
                    "title": "Test",
                    "severity": "info",
                    "check": "legacy_check_name",
                }
            ],
        )

        async with get_session() as session:
            result = await session.execute(select(Finding).where(Finding.scan_id == "scan-001"))
            f = result.scalar_one()
            assert f.check_name == "legacy_check_name"

    @pytest.mark.asyncio
    async def test_finding_preserves_existing_id(self, db, finding_repo):
        """If a finding has an 'id' field, it is used as-is."""
        await finding_repo.bulk_create(
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

        async with get_session() as session:
            result = await session.execute(select(Finding).where(Finding.id == "custom-id-123"))
            f = result.scalar_one()
            assert f.id == "custom-id-123"


# ─── ChainRepository Tests ──────────────────────────────────────────────────


class TestChainRepository:
    """Tests for chain persistence."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, db, chain_repo, sample_chains):
        """bulk_create inserts all chains."""
        count = await chain_repo.bulk_create("scan-001", sample_chains)
        assert count == 2

        async with get_session() as session:
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
                    "finding_ids": ["f1", "f2", "f3"],
                }
            ],
        )

        async with get_session() as session:
            result = await session.execute(select(Chain).where(Chain.scan_id == "scan-001"))
            c = result.scalar_one()
            assert c.title == "Test Chain"
            assert c.severity == "critical"
            assert c.source == "llm"
            assert c.finding_ids == ["f1", "f2", "f3"]

    @pytest.mark.asyncio
    async def test_chain_findings_fallback(self, db, chain_repo):
        """Chain maps 'findings' key when 'finding_ids' is missing."""
        await chain_repo.bulk_create(
            "scan-001",
            [
                {
                    "title": "Test",
                    "severity": "high",
                    "source": "rule-based",
                    "findings": ["a", "b"],
                }
            ],
        )

        async with get_session() as session:
            result = await session.execute(select(Chain).where(Chain.scan_id == "scan-001"))
            c = result.scalar_one()
            assert c.finding_ids == ["a", "b"]


# ─── CheckLogRepository Tests ───────────────────────────────────────────────


class TestCheckLogRepository:
    """Tests for check log persistence."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, db, check_log_repo, sample_check_log):
        """bulk_create inserts all log entries."""
        count = await check_log_repo.bulk_create("scan-001", sample_check_log)
        assert count == 6

        async with get_session() as session:
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
                    "findings": 3,
                    "suite": "network",
                    "duration_ms": 1500,
                }
            ],
        )

        async with get_session() as session:
            result = await session.execute(select(CheckLog).where(CheckLog.scan_id == "scan-001"))
            entry = result.scalar_one()
            assert entry.check_name == "port_scan"
            assert entry.event == "completed"
            assert entry.findings_count == 3
            assert entry.suite == "network"
            assert entry.duration_ms == 1500

    @pytest.mark.asyncio
    async def test_log_entries_have_auto_ids(self, db, check_log_repo, sample_check_log):
        """Log entries get auto-incrementing integer IDs."""
        await check_log_repo.bulk_create("scan-001", sample_check_log)

        async with get_session() as session:
            result = await session.execute(
                select(CheckLog.id).where(CheckLog.scan_id == "scan-001")
            )
            ids = [row[0] for row in result.all()]
            assert len(ids) == 6
            assert ids == sorted(ids)  # Auto-increment means sorted


# ─── Persist Orchestrator Tests ──────────────────────────────────────────────


class TestPersistOrchestrator:
    """Tests for the scan persistence orchestrator (app/db/persist.py)."""

    @pytest.fixture
    def mock_state(self):
        """Create a mock AppState with realistic data."""
        state = MagicMock()
        state.session_id = "test-session"
        state.target = "example.com"
        state.settings = {"parallel": False, "rate_limit": 10.0}
        state.status = "complete"
        state.phase = "done"
        state.error_message = None
        state.engagement_id = None
        state.checks_total = 3
        state.checks_completed = 3
        state.check_statuses = {
            "port_scan": "completed",
            "xss_check": "completed",
            "header_check": "failed",
        }
        state.findings = [
            {
                "title": "XSS Found",
                "severity": "high",
                "check_name": "xss_check",
                "host": "example.com",
            },
        ]
        state.chains = [
            {"title": "Attack Chain", "severity": "high", "source": "rule-based"},
        ]
        state.check_log = [
            {"check": "port_scan", "event": "completed", "findings": 0},
        ]
        return state

    @pytest.mark.asyncio
    async def test_on_scan_start_creates_record(self, db, mock_state):
        """on_scan_start creates a scan record and returns ID."""
        from app.db.persist import on_scan_start

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = True
            scan_id = await on_scan_start(mock_state)

        assert scan_id is not None
        assert len(scan_id) == 16

        async with get_session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            assert scan.target_domain == "example.com"
            assert scan.status == "running"

    @pytest.mark.asyncio
    async def test_on_scan_start_disabled(self, db, mock_state):
        """on_scan_start returns None when auto_persist is False."""
        from app.db.persist import on_scan_start

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = False
            scan_id = await on_scan_start(mock_state)

        assert scan_id is None

    @pytest.mark.asyncio
    async def test_on_scan_start_graceful_on_error(self, db, mock_state):
        """on_scan_start returns None (doesn't raise) on DB error."""
        from app.db.persist import on_scan_start

        with (
            patch("app.db.persist.get_config") as mock_cfg,
            patch("app.db.persist._scan_repo") as mock_repo,
        ):
            mock_cfg.return_value.storage.auto_persist = True
            mock_repo.create_scan = AsyncMock(side_effect=Exception("DB down"))
            scan_id = await on_scan_start(mock_state)

        assert scan_id is None

    @pytest.mark.asyncio
    async def test_on_scan_complete_persists_all(self, db, mock_state):
        """on_scan_complete writes findings, chains, log, and updates scan."""
        import time

        from app.db.persist import on_scan_complete, on_scan_start

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = True
            scan_id = await on_scan_start(mock_state)
            started_at = time.time() - 5.0  # 5 seconds ago
            await on_scan_complete(mock_state, scan_id, started_at)

        async with get_session() as session:
            # Scan updated
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            assert scan.status == "complete"
            assert scan.findings_count == 1
            assert scan.checks_failed == 1
            assert scan.duration_ms >= 5000

            # Findings persisted
            result = await session.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )
            assert result.scalar() == 1

            # Chains persisted
            result = await session.execute(
                select(func.count()).select_from(Chain).where(Chain.scan_id == scan_id)
            )
            assert result.scalar() == 1

            # Check log persisted
            result = await session.execute(
                select(func.count()).select_from(CheckLog).where(CheckLog.scan_id == scan_id)
            )
            assert result.scalar() == 1

    @pytest.mark.asyncio
    async def test_on_scan_complete_skips_when_no_scan_id(self, db, mock_state):
        """on_scan_complete does nothing when scan_id is None."""
        import time

        from app.db.persist import on_scan_complete

        # Should not raise
        await on_scan_complete(mock_state, None, time.time())

        async with get_session() as session:
            result = await session.execute(select(func.count()).select_from(Finding))
            assert result.scalar() == 0

    @pytest.mark.asyncio
    async def test_on_scan_complete_graceful_on_error(self, db, mock_state):
        """on_scan_complete logs warning but doesn't raise on DB error."""
        import time

        from app.db.persist import on_scan_complete

        with (
            patch("app.db.persist.get_config") as mock_cfg,
            patch("app.db.persist._finding_repo") as mock_repo,
        ):
            mock_cfg.return_value.storage.auto_persist = True
            mock_repo.bulk_create = AsyncMock(side_effect=Exception("DB full"))
            # Should not raise
            await on_scan_complete(mock_state, "scan-999", time.time())
