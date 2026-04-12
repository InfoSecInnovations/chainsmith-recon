"""
Tests for observation manual overrides (Phase 4a).

Covers ObservationOverrideRepository CRUD and the override API endpoints.
"""

import pytest
from sqlalchemy import func, select

from app.db.engine import close_db, get_session, init_db
from app.db.models import ObservationOverride, ObservationRecord
from app.db.repositories import (
    ComparisonRepository,
    ObservationOverrideRepository,
    ObservationRepository,
    ScanRepository,
)

pytestmark = pytest.mark.integration

# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


@pytest.fixture
def override_repo():
    return ObservationOverrideRepository()


@pytest.fixture
def scan_repo():
    return ScanRepository()


@pytest.fixture
def observation_repo():
    return ObservationRepository()


@pytest.fixture
def comparison_repo():
    return ComparisonRepository()


SAMPLE_FP = "abc123def456dead"


# --- Repository CRUD Tests ---------------------------------------------------


class TestObservationOverrideCRUD:
    @pytest.mark.asyncio
    async def test_set_override_accepted(self, db, override_repo):
        result = await override_repo.set_override(
            SAMPLE_FP,
            "accepted",
            reason="Accepted per CISO",
        )
        assert result["fingerprint"] == SAMPLE_FP
        assert result["status"] == "accepted"
        assert result["reason"] == "Accepted per CISO"
        assert result["created_at"] is not None

    @pytest.mark.asyncio
    async def test_set_override_false_positive(self, db, override_repo):
        result = await override_repo.set_override(
            SAMPLE_FP,
            "false_positive",
            reason="Test endpoint",
        )
        assert result["status"] == "false_positive"

    @pytest.mark.asyncio
    async def test_set_override_invalid_status(self, db, override_repo):
        with pytest.raises(ValueError, match="Invalid override status"):
            await override_repo.set_override(SAMPLE_FP, "invalid")

    @pytest.mark.asyncio
    async def test_set_override_upsert(self, db, override_repo):
        """Setting override twice updates rather than duplicates."""
        await override_repo.set_override(SAMPLE_FP, "accepted", reason="First")
        result = await override_repo.set_override(
            SAMPLE_FP, "false_positive", reason="Changed mind"
        )

        assert result["status"] == "false_positive"
        assert result["reason"] == "Changed mind"

        # Only one row in DB
        async with get_session() as session:
            count = await session.execute(select(func.count()).select_from(ObservationOverride))
            assert count.scalar() == 1

    @pytest.mark.asyncio
    async def test_get_override(self, db, override_repo):
        await override_repo.set_override(SAMPLE_FP, "accepted")
        result = await override_repo.get_override(SAMPLE_FP)
        assert result is not None
        assert result["fingerprint"] == SAMPLE_FP

    @pytest.mark.asyncio
    async def test_get_override_not_found(self, db, override_repo):
        result = await override_repo.get_override("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_remove_override(self, db, override_repo):
        await override_repo.set_override(SAMPLE_FP, "accepted")
        removed = await override_repo.remove_override(SAMPLE_FP)
        assert removed is True

        result = await override_repo.get_override(SAMPLE_FP)
        assert result is None

    @pytest.mark.asyncio
    async def test_remove_override_not_found(self, db, override_repo):
        removed = await override_repo.remove_override("nonexistent")
        assert removed is False

    @pytest.mark.asyncio
    async def test_list_overrides(self, db, override_repo):
        await override_repo.set_override("fp-1", "accepted", reason="OK")
        await override_repo.set_override("fp-2", "false_positive", reason="FP")
        await override_repo.set_override("fp-3", "accepted")

        result = await override_repo.list_overrides()
        assert result["total"] == 3
        assert len(result["overrides"]) == 3

    @pytest.mark.asyncio
    async def test_list_overrides_filter_status(self, db, override_repo):
        await override_repo.set_override("fp-1", "accepted")
        await override_repo.set_override("fp-2", "false_positive")
        await override_repo.set_override("fp-3", "accepted")

        result = await override_repo.list_overrides(status="accepted")
        assert result["total"] == 2
        assert all(o["status"] == "accepted" for o in result["overrides"])

    @pytest.mark.asyncio
    async def test_list_overrides_empty(self, db, override_repo):
        result = await override_repo.list_overrides()
        assert result["total"] == 0
        assert result["overrides"] == []

    @pytest.mark.asyncio
    async def test_override_no_reason(self, db, override_repo):
        result = await override_repo.set_override(SAMPLE_FP, "accepted")
        assert result["reason"] is None

    @pytest.mark.asyncio
    async def test_override_dict_shape(self, db, override_repo):
        result = await override_repo.set_override(SAMPLE_FP, "accepted", reason="Test")
        expected_keys = {"fingerprint", "status", "reason", "created_at", "updated_at"}
        assert expected_keys == set(result.keys())


# --- Override + Observation History Integration -----------------------------------


class TestOverrideWithHistory:
    @pytest.mark.asyncio
    async def test_override_appears_in_history_context(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        override_repo,
    ):
        """Override info can be retrieved alongside observation history."""
        # Create a scan with a observation
        await scan_repo.create_scan(
            scan_id="ov-scan-1",
            session_id="s1",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "ov-scan-1",
            [
                {
                    "id": "ov-f1",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("ov-scan-1", status="complete", observations_count=1)
        await comparison_repo.compute_observation_statuses("ov-scan-1")

        # Get the fingerprint
        async with get_session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(
                    ObservationRecord.id == "ov-scan--ov-f1"
                )
            )
            fp = result.scalar_one()

        # Set override
        await override_repo.set_override(fp, "accepted", reason="Known risk")

        # Verify both history and override are accessible
        history = await comparison_repo.get_observation_history(fp)
        assert len(history) >= 1

        override = await override_repo.get_override(fp)
        assert override is not None
        assert override["status"] == "accepted"

    @pytest.mark.asyncio
    async def test_reopen_after_accept(
        self,
        db,
        scan_repo,
        observation_repo,
        comparison_repo,
        override_repo,
    ):
        """Accepting then reopening removes the override."""
        await scan_repo.create_scan(
            scan_id="reopen-scan",
            session_id="s1",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "reopen-scan",
            [
                {
                    "id": "ro-f1",
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("reopen-scan", status="complete", observations_count=1)

        async with get_session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(
                    ObservationRecord.id == "reopen-s-ro-f1"
                )
            )
            fp = result.scalar_one()

        # Accept then reopen
        await override_repo.set_override(fp, "accepted", reason="Temp accept")
        assert (await override_repo.get_override(fp)) is not None

        await override_repo.remove_override(fp)
        assert (await override_repo.get_override(fp)) is None
