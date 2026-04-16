"""
app/engine/triage.py - Triage Orchestration

Coordinates remediation triage of adjudicated observations and attack chains.
Reads pipeline output from the database, loads team/operator context from YAML,
runs the Triage Agent, and persists the resulting plan.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from app.agents.triage import TriageAgent, _match_kb_entries, load_remediation_kb
from app.config import get_config
from app.lib.llm import get_llm_client
from app.lib.timeutils import iso_utc, parse_iso_utc
from app.models import (
    AdjudicatedRisk,
    AdjudicationApproach,
    AttackChain,
    Observation,
    ObservationSeverity,
    ObservationStatus,
    TeamContext,
)

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


# ─── Team Context Load/Save ─────────────────────────────────────


def load_team_context(config: "ChainsmithConfig | None" = None) -> TeamContext | None:
    """
    Load team context from ~/.chainsmith/triage_context.yaml.

    Returns None if file doesn't exist or can't be parsed.
    This is expected and normal — triage works without it.
    """
    cfg = config or get_config()
    path = Path(cfg.triage.context_file).expanduser()

    if not path.exists():
        logger.info("No team context file found at %s — proceeding without it", path)
        return None

    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — cannot load team context file")
        return None

    try:
        with open(path) as fh:
            data = _yaml.safe_load(fh) or {}

        if not isinstance(data, dict):
            logger.warning("Team context file is not a valid YAML mapping")
            return None

        # Parse answered_at if present
        answered_at = data.get("answered_at")
        if isinstance(answered_at, str):
            try:
                answered_at = parse_iso_utc(answered_at)
            except ValueError:
                answered_at = None

        # YAML parses bare yes/no as booleans — coerce to strings
        def _str_or_none(val):
            if val is None:
                return None
            if isinstance(val, bool):
                return "yes" if val else "no"
            return str(val)

        return TeamContext(
            deployment_velocity=_str_or_none(data.get("deployment_velocity")),
            incident_response=_str_or_none(data.get("incident_response")),
            remediation_surface=_str_or_none(data.get("remediation_surface")),
            team_size=_str_or_none(data.get("team_size")),
            off_limits=_str_or_none(data.get("off_limits")),
            answered_at=answered_at,
        )
    except Exception as e:
        logger.warning("Failed to load team context: %s", e)
        return None


def save_team_context(
    context: TeamContext,
    config: "ChainsmithConfig | None" = None,
) -> bool:
    """
    Save team context to ~/.chainsmith/triage_context.yaml.

    Returns True if saved successfully, False otherwise.
    """
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — cannot save team context")
        return False

    cfg = config or get_config()
    path = Path(cfg.triage.context_file).expanduser()

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "deployment_velocity": context.deployment_velocity,
            "incident_response": context.incident_response,
            "remediation_surface": context.remediation_surface,
            "team_size": context.team_size,
            "off_limits": context.off_limits,
            "answered_at": (context.answered_at.isoformat() if context.answered_at else iso_utc()),
        }

        header = (
            "# Chainsmith Triage — Team Capabilities\n"
            "# Stored locally. Not uploaded anywhere.\n"
            "# Edit directly or run: chainsmith triage --configure\n\n"
        )

        # Use default_style='"' to quote strings so YAML doesn't parse
        # yes/no as booleans on reload
        with open(path, "w") as fh:
            fh.write(header)
            _yaml.dump(data, fh, default_flow_style=False, sort_keys=False, default_style='"')

        logger.info("Team context saved to %s", path)
        return True
    except Exception as e:
        logger.warning("Failed to save team context: %s", e)
        return False


# ─── DB Helpers ──────────────────────────────────────────────────


async def _update_triage_status_in_db(scan_id: str | None, **fields) -> None:
    """Persist triage status fields to the Scan DB record (best-effort)."""
    if not scan_id:
        return
    try:
        from app.db.repositories import ScanRepository

        await ScanRepository().update_scan_status(scan_id, **fields)
    except Exception:
        logger.warning("Failed to persist triage status to DB", exc_info=True)


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


async def _load_adjudications_from_db(scan_id: str | None) -> list[dict]:
    """Load adjudication results from the database for the given scan."""
    if not scan_id:
        return []
    try:
        from app.db.repositories import AdjudicationRepository

        return await AdjudicationRepository().get_results(scan_id)
    except Exception:
        logger.warning("Failed to load adjudications from DB", exc_info=True)
        return []


async def _load_chains_from_db(scan_id: str | None) -> list[dict]:
    """Load attack chains from the database for the given scan."""
    if not scan_id:
        return []
    try:
        from app.db.repositories import ChainRepository

        return await ChainRepository().get_chains(scan_id)
    except Exception:
        logger.warning("Failed to load chains from DB", exc_info=True)
        return []


# ─── Orchestrator ────────────────────────────────────────────────


async def run_triage(session: "ScanSession") -> None:
    """
    Run triage on adjudicated observations and attack chains.

    Reads observations + adjudications + chains from DB, loads operator
    and team context from YAML files, creates TriageAgent, calls triage(),
    persists the resulting plan, and updates scan status.
    """
    scan_id = session.id

    session.triage_status = "triaging"
    await _update_triage_status_in_db(scan_id, triage_status="triaging")

    try:
        # Check if triage is enabled
        cfg = get_config()
        if not cfg.triage.enabled:
            session.triage_status = "complete"
            await _update_triage_status_in_db(
                scan_id,
                triage_status="complete",
                triage_error="Triage is disabled in config",
            )
            logger.info("Triage disabled — skipping")
            return

        # 1. Load observations from DB
        obs_dicts = await _load_observations_from_db(scan_id)

        # Convert to Observation models
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
            session.triage_status = "complete"
            await _update_triage_status_in_db(scan_id, triage_status="complete")
            logger.info("No verified observations to triage")
            return

        # 2. Load adjudications from DB
        adj_dicts = await _load_adjudications_from_db(scan_id)
        adjudications = []
        for a in adj_dicts:
            try:
                adjudications.append(
                    AdjudicatedRisk(
                        observation_id=a["observation_id"],
                        original_severity=ObservationSeverity(a["original_severity"]),
                        adjudicated_severity=ObservationSeverity(a["adjudicated_severity"]),
                        confidence=float(a.get("confidence", 0.5)),
                        approach_used=AdjudicationApproach(
                            a.get("approach_used", "evidence_rubric")
                        ),
                        rationale=a.get("rationale", ""),
                        factors=a.get("factors", {}),
                    )
                )
            except Exception as e:
                logger.warning("Failed to parse adjudication record: %s", e)

        # 3. Load chains from DB
        chain_dicts = await _load_chains_from_db(scan_id)
        chains = []
        for c in chain_dicts:
            try:
                chains.append(
                    AttackChain(
                        id=c["id"],
                        title=c.get("title", ""),
                        description=c.get("description", ""),
                        impact_statement=c.get("impact_statement", ""),
                        observation_ids=c.get("observation_ids", []),
                        individual_severities=[],
                        combined_severity=ObservationSeverity(c.get("severity", "medium")),
                        severity_reasoning=c.get("severity_reasoning", ""),
                        attack_steps=c.get("attack_steps", []),
                    )
                )
            except Exception as e:
                logger.warning("Failed to parse chain record: %s", e)

        # 4. Load contexts
        from app.engine.adjudication import load_operator_context

        operator_context = load_operator_context()
        team_context = load_team_context()

        # 5. Load remediation KB
        kb = load_remediation_kb(cfg.triage.kb_path)
        kb_entries = _match_kb_entries(verified, kb)

        # 6. Create agent and run
        agent = TriageAgent(client=get_llm_client())
        plan = await agent.triage(
            observations=verified,
            chains=chains,
            adjudications=adjudications,
            operator_context=operator_context,
            team_context=team_context,
            kb_entries=kb_entries,
            scan_id=scan_id or "",
        )

        session.triage_status = "complete"

        logger.info(
            "Triage complete: %d actions (%d quick wins, %d strategic)",
            len(plan.actions),
            plan.quick_wins,
            plan.strategic_fixes,
        )

        # 7. Persist results to DB
        from app.db.persist import on_triage_complete

        plan_dict = plan.model_dump(mode="json")
        await on_triage_complete(scan_id, plan_dict)
        await _update_triage_status_in_db(scan_id, triage_status="complete")

        # Guided Mode: proactive triage_plan_ready message
        await _emit_triage_plan_proactive(plan)

    except Exception as e:
        logger.exception("Triage failed: %s", e)
        session.triage_status = "error"
        await _update_triage_status_in_db(scan_id, triage_status="error", triage_error=str(e))


async def _emit_triage_plan_proactive(plan) -> None:
    """Push a proactive triage_plan_ready message if Guided Mode is active."""
    try:
        from app.engine.chat import sse_manager
        from app.engine.guided import maybe_emit_proactive
        from app.models import ComponentType
        from app.state import state

        top_action = plan.actions[0].action if plan.actions else "review findings"
        text = (
            f"Action plan ready. {len(plan.actions)} actions "
            f"({plan.quick_wins} quick wins). Top priority: {top_action}"
        )

        await maybe_emit_proactive(
            sse_manager=sse_manager,
            session_id=state.session_id,
            agent=ComponentType.TRIAGE,
            trigger="triage_plan_ready",
            text=text,
            actions=[
                {
                    "label": "Show plan",
                    "injected_message": "Show the triage plan details",
                }
            ],
        )
    except Exception:
        logger.debug("Guided mode proactive triage_plan_ready failed (non-fatal)", exc_info=True)
