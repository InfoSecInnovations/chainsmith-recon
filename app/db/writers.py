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

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.db.repositories import (
    CheckLogRepository,
    EvidenceRepository,
    ObservationRepository,
)

if TYPE_CHECKING:
    from app.db.engine import Database
    from app.scan_session import ScanSession

logger = logging.getLogger(__name__)


def scratch_dir() -> Path:
    """
    Where observations land when the database is unreachable mid-scan.

    Phase 57.1a rooted this in the workspace. Resolved on call rather than at
    import: this module is imported long before an entry point selects a
    workspace, so a constant here would freeze the pre-workspace path.
    """
    from app.workspace import get_workspace

    return get_workspace().scratch_dir


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
        session: ScanSession | None = None,
    ):
        self.scan_id = scan_id
        self._repo = repo or ObservationRepository(db)
        self._batch_size = batch_size
        self._buffer: list[dict] = []
        self._count = 0
        self._db_failed = False
        self._collisions = 0
        self._explicit_scratch_dir = scratch_dir
        self._scratch_path: Path | None = None
        self._scratch_seq = 0
        # When present, each observation gets an event_seq and
        # an `observation_added` event is pushed onto the session's bus.
        self._session = session

    @property
    def _scratch_dir(self) -> Path:
        return self._explicit_scratch_dir or scratch_dir()

    @property
    def count(self) -> int:
        """Total observations written (DB + scratch)."""
        return self._count

    @property
    def db_failed(self) -> bool:
        """True once the database is unusable and every later observation goes to scratch."""
        return self._db_failed

    @property
    def collisions(self) -> int:
        """Observations kept in scratch because their id was already stored for this scan."""
        return self._collisions

    async def write(self, observation: dict) -> None:
        """
        Buffer an observation for persistence.

        Flushes to DB when the buffer reaches batch_size. If the DB is
        unreachable, falls back to scratch-space writes.
        """
        if self._session is not None:
            seq = self._session.publish_event(
                "observation_added",
                {
                    "id": observation.get("id"),
                    "severity": observation.get("severity"),
                    "host": observation.get("host") or observation.get("target_host"),
                    "check": observation.get("check_name") or observation.get("check"),
                },
            )
            observation["event_seq"] = seq
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
        except IntegrityError:
            # A row whose id is already stored is a check minting one observation
            # id twice, not the database going away. Retry row by row so only the
            # colliding rows leave the database; everything else still lands.
            await self._write_rows(batch)
        except SQLAlchemyError:
            self._fall_back(batch)

    async def _write_rows(self, batch: list[dict]) -> None:
        """Insert one row at a time after a collision; only colliding rows go to scratch."""
        for index, obs in enumerate(batch):
            try:
                await self._repo.bulk_create(self.scan_id, [obs])
            except IntegrityError:
                self._collisions += 1
                logger.error(
                    "Observation id %s from %s is already stored for scan %s; kept in scratch "
                    "space instead of the database (a check minted the same id twice)",
                    obs.get("id"),
                    obs.get("check_name") or obs.get("check"),
                    self.scan_id,
                )
                self._write_scratch([obs])
            except SQLAlchemyError:
                self._fall_back(batch[index:])
                return

    def _fall_back(self, batch: list[dict]) -> None:
        """The database is unusable: this batch and every later one go to scratch."""
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
            except OSError:
                logger.error("Failed to write scratch file %s", path, exc_info=True)

    def _get_scratch_path(self) -> Path:
        """Get or create the scratch directory for this scan."""
        if self._scratch_path is None:
            self._scratch_path = self._scratch_dir / self.scan_id / "observations"
            self._scratch_path.mkdir(parents=True, exist_ok=True)

            # Write metadata file for the scratch-to-db tool
            meta_path = self._scratch_dir / self.scan_id / "metadata.json"
            if not meta_path.exists():
                with contextlib.suppress(OSError):
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
        session: ScanSession | None = None,
    ):
        self.scan_id = scan_id
        self._repo = repo or CheckLogRepository(db)
        # When present, each log event also goes onto the bus
        # as a check_started/check_completed/check_skipped SSE event.
        self._session = session

    async def log_event(self, entry: dict) -> None:
        """Persist a single check log event."""
        if self._session is not None:
            from app.db.models import CheckLog

            event_type = CheckLog._SSE_EVENT_TYPE.get(entry.get("event", ""), "check_started")
            payload: dict = {
                "name": entry.get("check"),
                "suite": entry.get("suite"),
            }
            if event_type == "check_completed":
                payload["success"] = entry.get("event") == "completed"
                payload["observations"] = entry.get("observations", 0)
                if entry.get("error_message") or entry.get("error"):
                    payload["error"] = entry.get("error_message") or entry.get("error")
            elif event_type == "check_skipped":
                payload["reason"] = entry.get("error_message") or entry.get("error")
            seq = self._session.publish_event(event_type, payload)
            entry["event_seq"] = seq
        try:
            await self._repo.bulk_create(self.scan_id, [entry])
        except SQLAlchemyError:
            logger.warning(
                "Failed to persist check log event for scan %s: %s",
                self.scan_id,
                entry.get("check", "unknown"),
                exc_info=True,
            )


class EvidenceIndexWriter:
    """
    Indexes captured exchanges in the database.

    Unlike ObservationWriter there is no scratch-space fallback, because there
    is nothing to rescue: by the time this runs the exchange document is already
    on disk under the workspace's ``evidence/``, and that document is the
    durable copy. The database half is an index over it and can be rebuilt from
    the store. So a failure here is logged and swallowed — the corpus survives,
    and only queryability is lost until it is reindexed.
    """

    def __init__(
        self,
        repo: EvidenceRepository | None = None,
        db: Database | None = None,
    ):
        self._repo = repo or EvidenceRepository(db)

    async def write(self, exchanges: list) -> int:
        """Index a batch. Returns how many rows landed."""
        if not exchanges:
            return 0
        try:
            return await self._repo.bulk_create(exchanges)
        except (SQLAlchemyError, RuntimeError):
            # RuntimeError covers "database not initialized" — a CLI run with
            # persistence off still captures to disk, and should not be told
            # about it once per check.
            logger.warning(
                "Failed to index %d captured exchanges; documents are on disk",
                len(exchanges),
                exc_info=True,
            )
            return 0
