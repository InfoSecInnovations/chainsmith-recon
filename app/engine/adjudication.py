"""
app/engine/adjudication.py - Adjudication Orchestration

Coordinates severity adjudication of verified observations.
Reads observations from the database, runs the adjudicator agent,
and persists results back to the database.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from app.agents.registry import get_agent_registry
from app.lib.llm import get_llm_client
from app.models import OperatorContext

if TYPE_CHECKING:
    from app.scan_session import ScanSession

# Optional YAML support
try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from app.lib.observations import partition_by_verdict, suppression_note

logger = logging.getLogger(__name__)

# Fallback if the adjudicator spec is absent (disabled) or omits the knob.
# Canonical value lives in app/agents/adjudicator/config.yaml (parameters).
DEFAULT_ADJUDICATOR_CONTEXT_FILE = "~/.chainsmith/adjudicator_context.yaml"


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


def load_operator_context(context_file: str | None = None) -> OperatorContext | None:
    """
    Load operator context from the adjudicator's `context_file`.

    Returns None if file doesn't exist or can't be parsed.
    This is expected and normal — adjudication works without it.

    Args:
        context_file: Explicit path to use. Falls back to the adjudicator's
            resolved `config.yaml` parameter (via the agent registry) if None.
    """
    if context_file is None:
        context_file = get_agent_registry().param(
            "adjudicator", "context_file", DEFAULT_ADJUDICATOR_CONTEXT_FILE
        )
    path = Path(context_file).expanduser()

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
        # Check if adjudicator is enabled. config.yaml (enabled) is the single
        # source of truth (56.10c): a disabled agent isn't in the registry.
        if "adjudicator" not in get_agent_registry():
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

        # Narrowing is stated, not silent. This stage
        # only adjudicates what the Verifier confirmed, but what it sets aside
        # stays in the record and is counted here so a reader can see it.
        _carried, _suppressed = partition_by_verdict(observations)
        if _suppressed:
            logger.info("%s — not adjudicated, still recorded", suppression_note(_suppressed))
        verified = [f for f in _carried if f.status == ObservationStatus.VERIFIED]
        if not verified:
            session.adjudication_status = "complete"
            await _update_adjudication_status_in_db(scan_id, adjudication_status="complete")
            logger.info("No verified observations to adjudicate")
            return

        # Load operator context
        operator_context = load_operator_context()

        # Create agent (via the folder-shape factory) and run
        agent = get_agent_registry().create("adjudicator", client=get_llm_client())
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
