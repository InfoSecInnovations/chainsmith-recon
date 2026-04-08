"""Tests for database engine lifecycle, fingerprinting, and storage configuration."""

from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.db.engine import close_db, get_session, init_db
from app.db.models import Chain, CheckLog, ObservationRecord, Scan
from app.db.repositories import _generate_fingerprint

pytestmark = pytest.mark.integration

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
async def db(tmp_path):
    """Initialize an in-memory SQLite database for testing."""
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


# ─── Engine Tests ────────────────────────────────────────────────────────────


class TestEngine:
    """Tests for database engine lifecycle."""

    @pytest.mark.asyncio
    async def test_init_creates_db_file(self, tmp_path):
        """init_db creates the SQLite file and tables."""
        db_path = tmp_path / "subdir" / "test.db"
        await init_db(backend="sqlite", db_path=db_path)
        assert db_path.exists()
        await close_db()

    @pytest.mark.asyncio
    async def test_init_creates_parent_dirs(self, tmp_path):
        """init_db creates parent directories if they don't exist."""
        db_path = tmp_path / "a" / "b" / "c" / "test.db"
        await init_db(backend="sqlite", db_path=db_path)
        assert db_path.parent.exists()
        await close_db()

    @pytest.mark.asyncio
    async def test_get_session_before_init_raises(self):
        """get_session raises RuntimeError if called before init_db."""
        # Ensure engine is closed from any prior test
        await close_db()
        with pytest.raises(RuntimeError, match="not initialized"):
            get_session()

    @pytest.mark.asyncio
    async def test_close_db_is_idempotent(self, db):
        """Calling close_db multiple times doesn't raise."""
        await close_db()
        await close_db()  # Should not raise

    @pytest.mark.asyncio
    async def test_tables_exist_after_init(self, db):
        """All expected tables are created with correct columns."""
        async with get_session() as session:
            # Verify we can query each table without error
            await session.execute(select(func.count()).select_from(Scan))
            await session.execute(select(func.count()).select_from(ObservationRecord))
            await session.execute(select(func.count()).select_from(Chain))
            await session.execute(select(func.count()).select_from(CheckLog))

    @pytest.mark.asyncio
    async def test_scan_table_has_required_columns(self, db):
        """Scan table has the columns needed for scan lifecycle."""
        from sqlalchemy import inspect as sa_inspect

        async with get_session() as session:
            conn = await session.connection()
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in sa_inspect(sync_conn).get_columns("scans")}
            )
        for col in (
            "id",
            "session_id",
            "target_domain",
            "status",
            "started_at",
            "duration_ms",
            "checks_total",
            "observations_count",
        ):
            assert col in columns, f"scans table missing column: {col}"

    @pytest.mark.asyncio
    async def test_observations_table_has_required_columns(self, db):
        """Observations table has the columns needed for observation storage."""
        from sqlalchemy import inspect as sa_inspect

        async with get_session() as session:
            conn = await session.connection()
            columns = await conn.run_sync(
                lambda sync_conn: {
                    c["name"] for c in sa_inspect(sync_conn).get_columns("observations")
                }
            )
        for col in ("id", "scan_id", "title", "severity", "check_name", "host", "fingerprint"):
            assert col in columns, f"observations table missing column: {col}"

    @pytest.mark.asyncio
    async def test_check_log_table_has_required_columns(self, db):
        """Check log table has the columns needed for check tracking."""
        from sqlalchemy import inspect as sa_inspect

        async with get_session() as session:
            conn = await session.connection()
            columns = await conn.run_sync(
                lambda sync_conn: {
                    c["name"] for c in sa_inspect(sync_conn).get_columns("check_log")
                }
            )
        for col in ("id", "scan_id", "check_name", "event", "duration_ms"):
            assert col in columns, f"check_log table missing column: {col}"

    @pytest.mark.asyncio
    async def test_chains_table_has_required_columns(self, db):
        """Chains table has the columns needed for attack chain storage."""
        from sqlalchemy import inspect as sa_inspect

        async with get_session() as session:
            conn = await session.connection()
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in sa_inspect(sync_conn).get_columns("chains")}
            )
        for col in ("id", "scan_id", "title", "severity", "source", "observation_ids"):
            assert col in columns, f"chains table missing column: {col}"


# ─── Fingerprint Tests ───────────────────────────────────────────────────────


class TestFingerprinting:
    """Tests for observation fingerprint generation."""

    def test_fingerprint_is_deterministic(self):
        """Same inputs produce the same fingerprint."""
        fp1 = _generate_fingerprint("xss_check", "example.com", "XSS Found")
        fp2 = _generate_fingerprint("xss_check", "example.com", "XSS Found")
        assert fp1 == fp2

    def test_fingerprint_length(self):
        """Fingerprint is 16 hex characters."""
        fp = _generate_fingerprint("check", "host", "title")
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_differs_by_check(self):
        """Different check names produce different fingerprints."""
        fp1 = _generate_fingerprint("xss_check", "example.com", "Observation")
        fp2 = _generate_fingerprint("sqli_check", "example.com", "Observation")
        assert fp1 != fp2

    def test_fingerprint_differs_by_host(self):
        """Different hosts produce different fingerprints."""
        fp1 = _generate_fingerprint("xss_check", "a.com", "Observation")
        fp2 = _generate_fingerprint("xss_check", "b.com", "Observation")
        assert fp1 != fp2

    def test_fingerprint_differs_by_title(self):
        """Different titles produce different fingerprints."""
        fp1 = _generate_fingerprint("xss_check", "a.com", "XSS Found")
        fp2 = _generate_fingerprint("xss_check", "a.com", "SQLi Found")
        assert fp1 != fp2

    def test_fingerprint_handles_empty_host(self):
        """Empty host doesn't crash."""
        fp = _generate_fingerprint("check", "", "title")
        assert len(fp) == 16

    def test_fingerprint_includes_evidence(self):
        """Different evidence produces different fingerprints."""
        fp1 = _generate_fingerprint("check", "host", "title", "evidence_a")
        fp2 = _generate_fingerprint("check", "host", "title", "evidence_b")
        assert fp1 != fp2


# ─── Config Integration Tests ───────────────────────────────────────────────


class TestStorageConfig:
    """Tests for storage config loading."""

    def test_storage_in_yaml(self, tmp_path, clean_env):
        """Storage config loads from YAML."""
        from app.config import load_config

        config_file = tmp_path / "chainsmith.yaml"
        config_file.write_text("""
storage:
  backend: sqlite
  db_path: /custom/path.db
  auto_persist: false
  retention_days: 90
""")
        cfg = load_config(config_path=config_file)
        assert cfg.storage.backend == "sqlite"
        assert cfg.storage.db_path == Path("/custom/path.db")
        assert cfg.storage.auto_persist is False
        assert cfg.storage.retention_days == 90

    def test_storage_env_overrides(self, monkeypatch, clean_env):
        """Storage config responds to environment variables."""
        from app.config import load_config

        monkeypatch.setenv("CHAINSMITH_STORAGE_BACKEND", "postgresql")
        monkeypatch.setenv("CHAINSMITH_SQLITE_PATH", "/env/path.db")
        monkeypatch.setenv("CHAINSMITH_POSTGRESQL_URL", "postgresql://localhost/cs")
        monkeypatch.setenv("CHAINSMITH_STORAGE_AUTO_PERSIST", "false")
        monkeypatch.setenv("CHAINSMITH_STORAGE_RETENTION_DAYS", "30")

        cfg = load_config(config_path=Path("nonexistent.yaml"))
        assert cfg.storage.backend == "postgresql"
        assert cfg.storage.db_path == Path("/env/path.db")
        assert cfg.storage.postgresql_url == "postgresql://localhost/cs"
        assert cfg.storage.auto_persist is False
        assert cfg.storage.retention_days == 30
