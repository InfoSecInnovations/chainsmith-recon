"""
app/db/persist.py - Scan persistence orchestrator.

Coordinates writing scan results to the database at lifecycle points.
All operations are fire-and-forget with graceful degradation: if any
DB write fails, the scan continues normally and a warning is logged.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING

from app.config import get_config
from app.db.repositories import (
    AdjudicationRepository,
    ComparisonRepository,
    ScanRepository,
)

if TYPE_CHECKING:
    from app.db.engine import Database
    from app.db.writers import ObservationWriter
    from app.state import AppState

logger = logging.getLogger(__name__)


def _is_enabled() -> bool:
    """Check if persistence is enabled in config."""
    return get_config().storage.auto_persist


async def on_scan_start(state: AppState, db: Database | None = None) -> str | None:
    """
    Called when a scan begins. Creates the scan record in the database.
    Returns the scan_id for use in subsequent persistence calls, or None
    if persistence is disabled or fails.
    """
    if not _is_enabled():
        return None

    scan_id = uuid.uuid4().hex[:16]
    try:
        get_config()
        scenario_mgr = None
        try:
            from app.scenarios import get_scenario_manager

            mgr = get_scenario_manager()
            if mgr.is_active:
                scenario_mgr = mgr.active.name
        except Exception:
            pass

        scan_repo = ScanRepository(db)
        await scan_repo.create_scan(
            scan_id=scan_id,
            session_id=state.session_id,
            target_domain=state.target or "",
            settings=state.settings,
            scenario_name=scenario_mgr,
            engagement_id=getattr(state, "engagement_id", None),
        )
        return scan_id
    except Exception:
        logger.warning(
            "Failed to persist scan start — scan will continue without persistence", exc_info=True
        )
        return None


async def on_scan_complete(
    state: AppState,
    scan_id: str | None,
    started_at: float,
    db: Database | None = None,
    obs_writer: ObservationWriter | None = None,
) -> None:
    """
    Called when a scan completes (success or error). Updates the scan
    record with final stats and computes observation status comparisons.

    Observations and check logs are streamed during execution via writers.
    Chains are persisted by run_chain_analysis() when it runs.
    """
    if scan_id is None or not _is_enabled():
        return

    duration_ms = int((time.time() - started_at) * 1000)
    scan_repo = ScanRepository(db)
    comparison_repo = ComparisonRepository(db)

    try:
        # Count failed checks
        checks_failed = sum(1 for s in state.check_statuses.values() if s == "failed")

        # Resolve observation count from writer
        obs_count = obs_writer.count if obs_writer else 0

        # Update scan record with final stats
        await scan_repo.complete_scan(
            scan_id=scan_id,
            status=state.status,
            checks_total=state.checks_total,
            checks_completed=state.checks_completed,
            checks_failed=checks_failed,
            observations_count=obs_count,
            duration_ms=duration_ms,
            error_message=state.error_message,
        )

        # Compute observation statuses (new/recurring/resolved/regressed)
        if state.status == "complete" and obs_count > 0:
            try:
                statuses = await comparison_repo.compute_observation_statuses(scan_id)
                logger.info(
                    f"Observation statuses for scan {scan_id}: "
                    f"{statuses.get('new', 0)} new, "
                    f"{statuses.get('recurring', 0)} recurring, "
                    f"{statuses.get('resolved', 0)} resolved, "
                    f"{statuses.get('regressed', 0)} regressed"
                )
            except Exception:
                logger.warning("Failed to compute observation statuses", exc_info=True)

        logger.info(f"Scan {scan_id} persisted: {obs_count} observations")
    except Exception:
        logger.warning(
            "Failed to persist scan results — data may be partially written via streaming writers",
            exc_info=True,
        )


async def on_adjudication_complete(
    scan_id: str | None,
    results: list[dict],
    db: Database | None = None,
) -> None:
    """
    Called when adjudication completes. Persists adjudication results
    to the database. Fire-and-forget with graceful degradation.
    """
    if scan_id is None or not _is_enabled():
        return

    try:
        adjudication_repo = AdjudicationRepository(db)
        count = await adjudication_repo.bulk_create(scan_id, results)
        logger.info(f"Persisted {count} adjudication results for scan {scan_id}")
    except Exception:
        logger.warning(
            "Failed to persist adjudication results",
            exc_info=True,
        )
