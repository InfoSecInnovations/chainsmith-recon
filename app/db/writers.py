"""
app/db/writers.py - Streaming persistence writers.

Write observations and check log events to the database as they are
produced during scan execution, rather than in a single bulk insert
after the scan completes.

On DB failure, ObservationWriter falls back to a scratch directory
(~/.chainsmith/scratch/<scan_id>/) so results are not lost. A separate
scratch-to-db tool can import them later.
"""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from app.db.repositories import CheckLogRepository, ObservationRepository

if TYPE_CHECKING:
    from app.db.engine import Database

logger = logging.getLogger(__name__)

SCRATCH_DIR = Path("~/.chainsmith/scratch").expanduser()


class ObservationWriter:
    """
    Streams observations to the database during scan execution.

    Batches writes for throughput (default: flush every 10 observations).
    On DB failure, switches to scratch-space fallback so no data is lost.
    """

    def __init__(
        self,
        scan_id: str,
        repo: ObservationRepository | None = None,
        db: Database | None = None,
        batch_size: int = 10,
        scratch_dir: Path | None = None,
    ):
        self.scan_id = scan_id
        self._repo = repo or ObservationRepository(db)
        self._batch_size = batch_size
        self._buffer: list[dict] = []
        self._count = 0
        self._db_failed = False
        self._scratch_dir = scratch_dir or SCRATCH_DIR
        self._scratch_path: Path | None = None
        self._scratch_seq = 0

    @property
    def count(self) -> int:
        """Total observations written (DB + scratch)."""
        return self._count

    @property
    def db_failed(self) -> bool:
        """True if the writer has fallen back to scratch space."""
        return self._db_failed

    async def write(self, observation: dict) -> None:
        """
        Buffer an observation for persistence.

        Flushes to DB when the buffer reaches batch_size. If the DB is
        unreachable, falls back to scratch-space writes.
        """
        self._buffer.append(observation)
        self._count += 1

        if len(self._buffer) >= self._batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Flush the buffer to DB or scratch space."""
        if not self._buffer:
            return

        batch = self._buffer
        self._buffer = []

        if self._db_failed:
            self._write_scratch(batch)
            return

        try:
            await self._repo.bulk_create(self.scan_id, batch)
        except Exception:
            logger.warning(
                "DB write failed — switching to scratch-space fallback for scan %s",
                self.scan_id,
                exc_info=True,
            )
            self._db_failed = True
            self._write_scratch(batch)

    def _write_scratch(self, observations: list[dict]) -> None:
        """Write observations to scratch directory as JSON files."""
        scratch = self._get_scratch_path()
        for obs in observations:
            self._scratch_seq += 1
            path = scratch / f"{self._scratch_seq:04d}.json"
            try:
                path.write_text(json.dumps(obs, default=str), encoding="utf-8")
            except Exception:
                logger.error("Failed to write scratch file %s", path, exc_info=True)

    def _get_scratch_path(self) -> Path:
        """Get or create the scratch directory for this scan."""
        if self._scratch_path is None:
            self._scratch_path = self._scratch_dir / self.scan_id / "observations"
            self._scratch_path.mkdir(parents=True, exist_ok=True)

            # Write metadata file for the scratch-to-db tool
            meta_path = self._scratch_dir / self.scan_id / "metadata.json"
            if not meta_path.exists():
                with contextlib.suppress(Exception):
                    meta_path.write_text(
                        json.dumps({"scan_id": self.scan_id, "reason": "db_write_failure"}),
                        encoding="utf-8",
                    )

            logger.warning("Scratch space initialized at %s", self._scratch_path)

        return self._scratch_path


class CheckLogWriter:
    """
    Streams check log events to the database as they happen.

    Low volume (one start + one complete per check), so no batching needed.
    On failure, logs a warning but does not halt the scan — check logs are
    helpful but not critical data.
    """

    def __init__(
        self,
        scan_id: str,
        repo: CheckLogRepository | None = None,
        db: Database | None = None,
    ):
        self.scan_id = scan_id
        self._repo = repo or CheckLogRepository(db)

    async def log_event(self, entry: dict) -> None:
        """Persist a single check log event."""
        try:
            await self._repo.bulk_create(self.scan_id, [entry])
        except Exception:
            logger.warning(
                "Failed to persist check log event for scan %s: %s",
                self.scan_id,
                entry.get("check", "unknown"),
                exc_info=True,
            )
