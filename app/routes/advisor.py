"""
app/routes/advisor.py - Scan Advisor Routes

Endpoints for:
- ScanAnalysisAdvisor: post-scan recommendation retrieval (from DB)
- ScanPlannerAdvisor: pre-scan planning analysis (live, no DB)
"""

import logging

from fastapi import APIRouter, Query

from app.config import get_config
from app.db.repositories import AdvisorRepository, ScanRepository
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_advisor_repo = AdvisorRepository()
_scan_repo = ScanRepository()


async def _resolve_scan_id(scan_id: str | None) -> str | None:
    """Resolve scan_id: explicit param > active scan > most recent completed scan in DB."""
    sid = scan_id or state.active_scan_id or state._last_scan_id
    if sid:
        return sid
    return await _scan_repo.get_most_recent_scan_id()


@router.get("/api/v1/scan-advisor/recommendations")
async def get_recommendations(
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """
    Get scan advisor recommendations.

    Returns empty list if advisor is disabled or no scan has completed.
    """
    cfg = get_config()
    sid = await _resolve_scan_id(scan_id)

    if not sid:
        return {
            "enabled": cfg.scan_analysis_advisor.enabled,
            "recommendations": [],
            "count": 0,
        }

    recommendations = await _advisor_repo.get_recommendations(sid)
    return {
        "enabled": cfg.scan_analysis_advisor.enabled,
        "recommendations": recommendations,
        "count": len(recommendations),
    }


@router.get("/api/v1/scan-advisor/config")
async def get_advisor_config():
    """Get current scan analysis advisor configuration."""
    cfg = get_config()
    return {
        "enabled": cfg.scan_analysis_advisor.enabled,
        "mode": cfg.scan_analysis_advisor.mode,
        "auto_seed_urls": cfg.scan_analysis_advisor.auto_seed_urls,
        "require_approval": cfg.scan_analysis_advisor.require_approval,
    }


# ── ScanPlannerAdvisor Routes ────────────────────────────────────


@router.get("/api/v1/scan-planner/analyze")
async def get_planner_recommendations():
    """
    Run pre-scan planning analysis against the current scope.

    Returns recommendations for scope completeness, check selection,
    and engagement readiness. Runs live (not from DB).
    """
    from app.advisors.scan_planner_advisor import ScanPlannerAdvisor
    from app.engine.scanner import AVAILABLE_CHECKS
    from app.models import ScopeDefinition

    if not state.target:
        return {
            "recommendations": [],
            "count": 0,
            "message": "No scope defined. Set target and scope first.",
        }

    scope = ScopeDefinition(
        in_scope_domains=[state.target] if state.target else [],
        out_of_scope_domains=state.exclude or [],
        time_window=getattr(state.proof_settings, "engagement_window", None)
        and state.proof_settings.engagement_window.start,
    )
    proof_config = {
        "enabled": getattr(state.proof_settings, "traffic_logging", False),
    }

    advisor = ScanPlannerAdvisor(
        scope=scope,
        available_checks=set(AVAILABLE_CHECKS.keys()),
        check_metadata=AVAILABLE_CHECKS,
        proof_of_scope_config=proof_config,
    )
    recommendations = advisor.analyze()

    return {
        "recommendations": [r.to_dict() for r in recommendations],
        "count": len(recommendations),
    }
