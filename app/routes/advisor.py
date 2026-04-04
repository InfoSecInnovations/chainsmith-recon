"""
app/routes/advisor.py - Scan Advisor Routes

Endpoints for retrieving post-scan advisor recommendations.
"""

import logging

from fastapi import APIRouter

from app.config import get_config
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/v1/scan-advisor/recommendations")
async def get_recommendations():
    """
    Get scan advisor recommendations from the most recent scan.

    Returns empty list if advisor is disabled or no scan has completed.
    """
    cfg = get_config()
    return {
        "enabled": cfg.scan_advisor.enabled,
        "recommendations": state.advisor_recommendations,
        "count": len(state.advisor_recommendations),
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
