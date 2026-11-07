"""
app/capture/retention.py - Evidence retention (phase 57, D-5).

Captured evidence lives inside the workspace, so by default it lasts as long as
the workspace does: deleting the workspace deletes it (§5.3). An operator who
needs a shorter period sets `storage.evidence_retention_days`. Evidence older
than that is pruned:

- at server start (`app.main` lifespan), when the setting is above 0;
- on demand by `chainsmith evidence prune [--older-than N] [--dry-run]`.

Pruning removes the scan's exchange documents and grading records from the
store, and their index rows from the database. The scan row and its
observations stay: a pruned scan can still be reported on, but no longer
re-graded (`dev regrade` will find no records).

A scan's age is the time its newest evidence file was written. That is when
the evidence was captured, it needs no database, and a later re-grade does not
touch these files, so it does not reset the clock.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.capture.store import EvidenceStore

logger = logging.getLogger(__name__)

SECONDS_PER_DAY = 86400


@dataclass
class PruneResult:
    older_than_days: int
    dry_run: bool
    #: Scans whose evidence was (or, on a dry run, would be) removed.
    scans: list[str] = field(default_factory=list)
    #: Exchange documents removed. Zero on a dry run.
    documents: int = 0
    #: Index rows removed. Zero on a dry run, or when the database is unavailable.
    index_rows: int = 0


def _newest_mtime(directory: Path) -> float | None:
    newest = None
    for path in directory.rglob("*"):
        if path.is_file():
            mtime = path.stat().st_mtime
            newest = mtime if newest is None or mtime > newest else newest
    return newest


def expired_scans(
    store: EvidenceStore, older_than_days: int, now: float | None = None
) -> list[str]:
    """Scan ids in the store whose newest evidence is older than the cutoff."""
    if older_than_days <= 0:
        return []
    root = store.root
    if not root.is_dir():
        return []
    cutoff = (now if now is not None else time.time()) - older_than_days * SECONDS_PER_DAY
    expired = []
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        newest = _newest_mtime(directory)
        if newest is not None and newest < cutoff:
            expired.append(directory.name)
    return expired


async def prune_evidence(
    older_than_days: int | None = None,
    *,
    store: EvidenceStore | None = None,
    now: float | None = None,
    dry_run: bool = False,
) -> PruneResult:
    """Delete evidence older than `older_than_days` (default: the configured
    `storage.evidence_retention_days`). Never raises for one bad scan; it logs
    it and goes on."""
    if older_than_days is None:
        from app.config import get_config

        older_than_days = get_config().storage.evidence_retention_days
    result = PruneResult(older_than_days=older_than_days, dry_run=dry_run)
    if older_than_days <= 0:
        return result

    store = store or EvidenceStore()
    result.scans = expired_scans(store, older_than_days, now)
    if dry_run:
        return result

    for scan_id in result.scans:
        try:
            result.documents += store.delete_scan(scan_id)
        except OSError:
            logger.warning("Could not remove evidence for scan %s", scan_id, exc_info=True)
            continue
        try:
            from app.db.repositories import EvidenceRepository

            result.index_rows += await EvidenceRepository().delete_scan(scan_id)
        except Exception:
            # The documents are the evidence; a stale index row only costs a
            # lookup that finds nothing.
            logger.debug("Evidence index rows not removed for %s", scan_id, exc_info=True)

    if result.scans:
        logger.info(
            "Evidence retention: pruned %d scan(s) older than %d day(s), %d document(s)",
            len(result.scans),
            older_than_days,
            result.documents,
        )
    return result
