"""
Tests for app/db/writers.py - Streaming persistence writers.

Covers:
- ObservationWriter batching behavior
- ObservationWriter flush on demand
- ObservationWriter scratch-space fallback on DB failure
- ObservationWriter count tracking
- CheckLogWriter event persistence
- CheckLogWriter graceful failure
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.db.writers import CheckLogWriter, ObservationWriter

pytestmark = pytest.mark.unit


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


def _make_obs(title: str = "Test", severity: str = "medium") -> dict:
    """Create a minimal observation dict."""
    return {
        "id": f"obs-{title.lower().replace(' ', '-')}",
        "title": title,
        "severity": severity,
        "check_name": "test_check",
        "host": "example.com",
        "evidence": "test evidence",
    }


@pytest.fixture
def mock_obs_repo():
    repo = MagicMock()
    repo.bulk_create = AsyncMock(return_value=0)
    return repo


@pytest.fixture
def mock_log_repo():
    repo = MagicMock()
    repo.bulk_create = AsyncMock(return_value=0)
    return repo


# ═══════════════════════════════════════════════════════════════════════════════
# ObservationWriter - Batching
# ═══════════════════════════════════════════════════════════════════════════════


class TestObservationWriterBatching:
    async def test_does_not_flush_below_batch_size(self, mock_obs_repo):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=5)

        for i in range(4):
            await writer.write(_make_obs(f"Obs {i}"))

        mock_obs_repo.bulk_create.assert_not_called()
        assert writer.count == 4

    async def test_flushes_at_batch_size(self, mock_obs_repo):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=3)

        for i in range(3):
            await writer.write(_make_obs(f"Obs {i}"))

        mock_obs_repo.bulk_create.assert_called_once()
        args = mock_obs_repo.bulk_create.call_args
        assert args[0][0] == "scan-1"
        assert len(args[0][1]) == 3

    async def test_flushes_multiple_batches(self, mock_obs_repo):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=2)

        for i in range(5):
            await writer.write(_make_obs(f"Obs {i}"))

        # 5 observations with batch_size=2: 2 auto-flushes (at 2 and 4), 1 remaining
        assert mock_obs_repo.bulk_create.call_count == 2
        assert writer.count == 5

    async def test_manual_flush_writes_remaining(self, mock_obs_repo):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=10)

        for i in range(3):
            await writer.write(_make_obs(f"Obs {i}"))

        await writer.flush()

        mock_obs_repo.bulk_create.assert_called_once()
        assert len(mock_obs_repo.bulk_create.call_args[0][1]) == 3

    async def test_flush_empty_buffer_is_noop(self, mock_obs_repo):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo)
        await writer.flush()
        mock_obs_repo.bulk_create.assert_not_called()

    async def test_count_tracks_total(self, mock_obs_repo):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=2)

        for i in range(7):
            await writer.write(_make_obs(f"Obs {i}"))

        assert writer.count == 7


# ═══════════════════════════════════════════════════════════════════════════════
# ObservationWriter - Scratch Fallback
# ═══════════════════════════════════════════════════════════════════════════════


class TestObservationWriterScratchFallback:
    async def test_switches_to_scratch_on_db_failure(self, mock_obs_repo, tmp_path):
        mock_obs_repo.bulk_create.side_effect = Exception("DB unreachable")

        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=2, scratch_dir=tmp_path)

        await writer.write(_make_obs("Obs 1"))
        await writer.write(_make_obs("Obs 2"))  # triggers flush

        assert writer.db_failed is True
        assert writer.count == 2

        # Check scratch files were created
        scratch_dir = tmp_path / "scan-1" / "observations"
        assert scratch_dir.exists()
        files = sorted(scratch_dir.glob("*.json"))
        assert len(files) == 2

        # Verify content
        data = json.loads(files[0].read_text())
        assert data["title"] == "Obs 1"

    async def test_metadata_file_written_on_fallback(self, mock_obs_repo, tmp_path):
        mock_obs_repo.bulk_create.side_effect = Exception("DB unreachable")

        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=1, scratch_dir=tmp_path)
        await writer.write(_make_obs("Obs 1"))

        meta_path = tmp_path / "scan-1" / "metadata.json"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["scan_id"] == "scan-1"

    async def test_subsequent_writes_go_to_scratch(self, mock_obs_repo, tmp_path):
        mock_obs_repo.bulk_create.side_effect = Exception("DB unreachable")

        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=1, scratch_dir=tmp_path)

        # First write triggers DB failure and scratch fallback
        await writer.write(_make_obs("Obs 1"))

        # Second write should go straight to scratch (no DB attempt)
        await writer.write(_make_obs("Obs 2"))

        # DB was only called once (first batch), not for the second
        assert mock_obs_repo.bulk_create.call_count == 1

        scratch_dir = tmp_path / "scan-1" / "observations"
        files = sorted(scratch_dir.glob("*.json"))
        assert len(files) == 2

    async def test_no_scratch_on_success(self, mock_obs_repo, tmp_path):
        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=2, scratch_dir=tmp_path)

        await writer.write(_make_obs("Obs 1"))
        await writer.write(_make_obs("Obs 2"))

        assert writer.db_failed is False
        assert not (tmp_path / "scan-1").exists()


# ═══════════════════════════════════════════════════════════════════════════════
# CheckLogWriter
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckLogWriter:
    async def test_persists_event(self, mock_log_repo):
        writer = CheckLogWriter("scan-1", repo=mock_log_repo)
        entry = {"check": "port_scan", "event": "started"}

        await writer.log_event(entry)

        mock_log_repo.bulk_create.assert_called_once_with("scan-1", [entry])

    async def test_failure_does_not_raise(self, mock_log_repo):
        mock_log_repo.bulk_create.side_effect = Exception("DB error")
        writer = CheckLogWriter("scan-1", repo=mock_log_repo)

        # Should not raise
        await writer.log_event({"check": "port_scan", "event": "started"})

    async def test_multiple_events(self, mock_log_repo):
        writer = CheckLogWriter("scan-1", repo=mock_log_repo)

        await writer.log_event({"check": "port_scan", "event": "started"})
        await writer.log_event({"check": "port_scan", "event": "completed", "observations": 5})

        assert mock_log_repo.bulk_create.call_count == 2
