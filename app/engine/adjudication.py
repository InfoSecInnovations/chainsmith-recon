"""
app/engine/adjudication.py - Adjudication Orchestration

Coordinates severity adjudication of verified observations.
Reads observations from the database, runs the adjudicator agent,
and persists results back to the database.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from app.agents.adjudicator import AdjudicatorAgent
from app.config import get_config
from app.lib.llm import get_llm_client
from app.models import OperatorContext

if TYPE_CHECKING:
    from app.config import ChainsmithConfig
    from app.scan_session import ScanSession

# Optional YAML support
try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


async def _update_adjudication_status_in_db(scan_id: str | None, **fields) -> None:
    """Persist adjudication status fields to the Scan DB record (best-effort)."""
    if not scan_id:
        return
    try:
        from app.db.repositories import ScanRepository

        await ScanRepository().update_scan_status(scan_id, **fields)
    except Exception:
        logger.warning("Failed to persist adjudication status to DB", exc_info=True)


async def _load_observations_from_db(scan_id: str | None) -> list[dict]:
    """Load observations from the database for the given scan."""
    if not scan_id:
        return []
    try:
        from app.db.repositories import ObservationRepository

        return await ObservationRepository().get_observations(scan_id)
    except Exception:
        logger.warning("Failed to load observations from DB", exc_info=True)
        return []


def load_operator_context(config: "ChainsmithConfig | None" = None) -> OperatorContext | None:
    """
    Load operator context from ~/.chainsmith/adjudicator_context.yaml.

    Returns None if file doesn't exist or can't be parsed.
    This is expected and normal — adjudication works without it.

    Args:
        config: Explicit config to use. Falls back to get_config() if None.
    """
    cfg = config or get_config()
    path = Path(cfg.adjudicator.context_file).expanduser()

    if not path.exists():
        logger.info("No operator context file found at %s — proceeding without it", path)
        return None

    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — cannot load operator context file")
        return None

    try:
        with open(path) as fh:
            data = _yaml.safe_load(fh) or {}

        if not isinstance(data, dict):
            logger.warning("Operator context file is not a valid YAML mapping")
            return None

        # Rename 'asset_context' -> 'assets' for backward compat with doc examples
        if "asset_context" in data and "assets" not in data:
            data["assets"] = data.pop("asset_context")

        return OperatorContext(**data)
    except Exception as e:
        logger.warning("Failed to load operator context: %s", e)
        return None


async def run_adjudication(
    session: "ScanSession",
) -> None:
    """
    Run adjudication on verified observations.

    Reads observations from the database, runs the adjudicator agent,
    and persists results. Updates session.adjudication_status as a
    concurrency guard.
    """
    from app.models import Observation, ObservationStatus

    scan_id = session.id

    session.adjudication_status = "adjudicating"
    await _update_adjudication_status_in_db(scan_id, adjudication_status="adjudicating")

    try:
        # Check if adjudicator is enabled
        cfg = get_config()
        if not cfg.adjudicator.enabled:
            session.adjudication_status = "complete"
            await _update_adjudication_status_in_db(
                scan_id,
                adjudication_status="complete",
                adjudication_error="Adjudicator is disabled in config",
            )
            logger.info("Adjudicator disabled — skipping")
            return

        # Load observations from DB
        obs_dicts = await _load_observations_from_db(scan_id)

        # Convert dict observations to Observation models
        observations = []
        for f in obs_dicts:
            observations.append(
                Observation(
                    id=f.get("id", "unknown"),
                    observation_type=f.get("check_name", f.get("observation_type", "unknown")),
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "info"),
                    status=f.get("verification_status", f.get("status", "pending")),
                    confidence=f.get("confidence", 0.5),
                    check_name=f.get("check_name"),
                    discovered_at=f.get(
                        "discovered_at", f.get("created_at", "2000-01-01T00:00:00")
                    ),
                    target_url=f.get("target_url"),
                    target_service=f.get("host"),
                    evidence_summary=f.get("evidence"),
                )
            )

        verified = [f for f in observations if f.status == ObservationStatus.VERIFIED]
        if not verified:
            session.adjudication_status = "complete"
            await _update_adjudication_status_in_db(scan_id, adjudication_status="complete")
            logger.info("No verified observations to adjudicate")
            return

        # Load operator context
        operator_context = load_operator_context()

        # Create agent and run
        agent = AdjudicatorAgent(client=get_llm_client())
        results = await agent.adjudicate_observations(verified, operator_context)

        result_dicts = [r.model_dump(mode="json") for r in results]
        session.adjudication_status = "complete"

        logger.info(
            "Adjudication complete: %d results (%d adjusted)",
            len(results),
            sum(1 for r in results if r.original_severity != r.adjudicated_severity),
        )

        # Persist results to DB
        from app.db.persist import on_adjudication_complete

        await on_adjudication_complete(scan_id, result_dicts)
        await _update_adjudication_status_in_db(scan_id, adjudication_status="complete")

    except Exception as e:
        logger.exception("Adjudication failed: %s", e)
        session.adjudication_status = "error"
        await _update_adjudication_status_in_db(
            scan_id, adjudication_status="error", adjudication_error=str(e)
        )
