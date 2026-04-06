"""
app/engine/adjudication.py - Adjudication Orchestration

Coordinates severity adjudication of verified findings.
Mirrors the pattern of app/engine/chains.py for chain analysis.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from app.agents.adjudicator import AdjudicatorAgent
from app.config import get_config
from app.models import AdjudicationApproach, OperatorContext

if TYPE_CHECKING:
    from app.state import AppState

# Optional YAML support
try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


def load_operator_context() -> OperatorContext | None:
    """
    Load operator context from ~/.chainsmith/adjudicator_context.yaml.

    Returns None if file doesn't exist or can't be parsed.
    This is expected and normal — adjudication works without it.
    """
    cfg = get_config()
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


def resolve_approach(
    api_param: str | None = None,
) -> AdjudicationApproach:
    """
    Resolve adjudication approach from layered config.

    Priority: api_param > config default_approach > "auto"
    """
    if api_param:
        try:
            return AdjudicationApproach(api_param)
        except ValueError:
            logger.warning("Invalid approach '%s', falling back to config", api_param)

    cfg = get_config()
    try:
        return AdjudicationApproach(cfg.adjudicator.default_approach)
    except ValueError:
        return AdjudicationApproach.AUTO


async def run_adjudication(
    state: "AppState",
    approach: str | None = None,
) -> None:
    """
    Run adjudication on verified findings.

    Updates state.adjudication_status and state.adjudication_results.
    Persists results if auto_persist is enabled.

    Args:
        state: The application state with findings to adjudicate.
        approach: Optional approach override for this invocation.
    """
    from app.models import Finding, FindingStatus

    state.adjudication_status = "adjudicating"
    state.adjudication_results = []
    state.adjudication_error = None

    try:
        # Check if adjudicator is enabled
        cfg = get_config()
        if not cfg.adjudicator.enabled:
            state.adjudication_status = "complete"
            state.adjudication_error = "Adjudicator is disabled in config"
            logger.info("Adjudicator disabled — skipping")
            return

        # Convert dict findings to Finding models if needed
        findings = []
        for f in state.findings:
            if isinstance(f, dict):
                findings.append(Finding(
                    id=f.get("id", "unknown"),
                    finding_type=f.get("check_name", f.get("finding_type", "unknown")),
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "info"),
                    status=f.get("verification_status", f.get("status", "pending")),
                    confidence=f.get("confidence", 0.5),
                    discovered_by=f.get("discovered_by", "scout"),
                    discovered_at=f.get("discovered_at", f.get("created_at", "2000-01-01T00:00:00")),
                    target_url=f.get("target_url"),
                    target_service=f.get("host"),
                    evidence_summary=f.get("evidence"),
                ))
            else:
                findings.append(f)

        verified = [f for f in findings if f.status == FindingStatus.VERIFIED]
        if not verified:
            state.adjudication_status = "complete"
            logger.info("No verified findings to adjudicate")
            return

        # Load operator context
        operator_context = load_operator_context()

        # Resolve approach
        resolved_approach = resolve_approach(approach)

        # Create agent and run
        agent = AdjudicatorAgent(approach=resolved_approach)
        results = await agent.adjudicate_findings(verified, operator_context)

        # Store results as dicts for state/API compatibility
        state.adjudication_results = [r.model_dump(mode="json") for r in results]
        state.adjudication_status = "complete"

        logger.info(
            "Adjudication complete: %d results (%d adjusted)",
            len(results),
            sum(1 for r in results if r.original_severity != r.adjudicated_severity),
        )

        # Persist to DB
        from app.db.persist import on_adjudication_complete

        # Try to get scan_id from state (set during scan persistence)
        scan_id = getattr(state, "_last_scan_id", None)
        await on_adjudication_complete(state, scan_id)

    except Exception as e:
        logger.exception("Adjudication failed: %s", e)
        state.adjudication_status = "error"
        state.adjudication_error = str(e)
