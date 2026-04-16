"""Tests for the scan persistence orchestrator (app/db/persist.py)."""

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

import app.db.engine as _engine_module
from app.db.engine import Database
from app.db.models import ObservationRecord, Scan

pytestmark = pytest.mark.integration


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
def mock_state():
    """Create a mock AppState with realistic data."""
    state = MagicMock()
    state.session_id = "test-session"
    state.target = "example.com"
    state.settings = {"parallel": False, "rate_limit": 10.0}
    state.status = "complete"
    state.phase = "done"
    state.error_message = None
    state.checks_total = 3
    state.checks_completed = 3
    state.check_statuses = {
        "port_scan": "completed",
        "xss_check": "completed",
        "header_check": "failed",
    }
    return state


class TestPersistOrchestrator:
    """Tests for the scan persistence orchestrator (app/db/persist.py)."""

    @pytest.mark.asyncio
    async def test_on_scan_start_creates_record(self, db, mock_state):
        """on_scan_start creates a scan record and returns ID."""
        from app.db.persist import on_scan_start

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = True
            scan_id = await on_scan_start(mock_state, db=db)

        assert scan_id is not None
        assert len(scan_id) == 16

        async with db.session() as session:
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
            scan_id = await on_scan_start(mock_state, db=db)

        assert scan_id is None

    @pytest.mark.asyncio
    async def test_on_scan_start_graceful_on_error(self, db, mock_state):
        """on_scan_start returns None (doesn't raise) on DB error and logs a warning."""
        from app.db.persist import on_scan_start

        broken_db = MagicMock()
        broken_db.session.side_effect = OperationalError("DB down", {}, None)

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = True
            with patch("app.db.persist.logger") as mock_logger:
                scan_id = await on_scan_start(mock_state, db=broken_db)

        assert scan_id is None
        mock_logger.warning.assert_called_once()
        assert "persist" in mock_logger.warning.call_args[0][0].lower()

    @pytest.mark.asyncio
    async def test_on_scan_complete_updates_scan_record(self, db, mock_state):
        """on_scan_complete updates scan record with final stats."""
        import time

        from app.db.persist import on_scan_complete, on_scan_start

        # Create a mock obs_writer with a count
        obs_writer = MagicMock()
        obs_writer.count = 5

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = True
            scan_id = await on_scan_start(mock_state, db=db)
            started_at = time.time() - 5.0  # 5 seconds ago
            await on_scan_complete(mock_state, scan_id, started_at, db=db, obs_writer=obs_writer)

        async with db.session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            assert scan.status == "complete"
            assert scan.observations_count == 5  # from obs_writer.count
            assert scan.checks_failed == 1
            assert scan.duration_ms >= 5000

    @pytest.mark.asyncio
    async def test_on_scan_complete_skips_when_no_scan_id(self, db, mock_state):
        """on_scan_complete does nothing when scan_id is None."""
        import time

        from app.db.persist import on_scan_complete

        # Should not raise
        await on_scan_complete(mock_state, None, time.time(), db=db)

        async with db.session() as session:
            result = await session.execute(select(func.count()).select_from(ObservationRecord))
            assert result.scalar() == 0

    @pytest.mark.asyncio
    async def test_on_scan_complete_graceful_on_error(self, db, mock_state):
        """on_scan_complete logs warning but doesn't raise on DB error."""
        import time

        from app.db.persist import on_scan_complete

        broken_db = MagicMock()
        broken_db.session.side_effect = OperationalError("DB full", {}, None)

        with patch("app.db.persist.get_config") as mock_cfg:
            mock_cfg.return_value.storage.auto_persist = True
            with patch("app.db.persist.logger") as mock_logger:
                # Should not raise
                await on_scan_complete(mock_state, "scan-999", time.time(), db=broken_db)

        mock_logger.warning.assert_called_once()
        assert "persist" in mock_logger.warning.call_args[0][0].lower()
