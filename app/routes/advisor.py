"""
app/routes/advisor.py - Scan Advisor Routes

Endpoints for retrieving post-scan advisor recommendations.

All reads go through the database. If no scan_id is provided,
the active scan is used.
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
            "enabled": cfg.scan_advisor.enabled,
            "recommendations": [],
            "count": 0,
        }

    recommendations = await _advisor_repo.get_recommendations(sid)
    return {
        "enabled": cfg.scan_advisor.enabled,
        "recommendations": recommendations,
        "count": len(recommendations),
    }


@router.get("/api/v1/scan-advisor/config")
async def get_advisor_config():
    """Get current scan advisor configuration."""
    cfg = get_config()
    return {
        "enabled": cfg.scan_advisor.enabled,
        "mode": cfg.scan_advisor.mode,
        "auto_seed_urls": cfg.scan_advisor.auto_seed_urls,
        "require_approval": cfg.scan_advisor.require_approval,
    }
