"""
app/routes/checks.py - Check Info Routes

Endpoints for:
- Listing available checks
- Check metadata and details
"""

import logging

from fastapi import APIRouter, HTTPException

from app.engine.scanner import get_check_info, AVAILABLE_CHECKS
from app.scenarios import get_scenario_manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/v1/checks")
@router.get("/api/checks")
async def get_available_checks():
    """Get info about all available checks (reflects scenario mode).

    When a scenario is active, simulated checks overlay the real check
    registry (matched by name).  Real checks without a simulation are
    still included so the full suite is always visible.
    """
    mgr = get_scenario_manager()
    if mgr.is_active:
        simulations = mgr.get_simulations()
        # Build merged list: real checks + simulated overlays
        merged = dict(AVAILABLE_CHECKS)          # copy real checks
        for sim in simulations:
            info = get_check_info(sim)
            info["simulated"] = True
            merged[sim.name] = info               # replace real with sim
        return {
            "checks": list(merged.values()),
            "scenario": mgr.active.name,
            "simulated": bool(simulations),
        }
    return {"checks": list(AVAILABLE_CHECKS.values()), "simulated": False}


@router.get("/api/v1/checks/{check_name}")
@router.get("/api/checks/{check_name}")
async def get_check_details(check_name: str):
    """Get detailed info about a specific check."""
    mgr = get_scenario_manager()
    if mgr.is_active:
        # Look in simulated checks first
        for check in mgr.get_simulations():
            if check.name == check_name:
                return get_check_info(check)
    if check_name not in AVAILABLE_CHECKS:
        raise HTTPException(404, f"Check '{check_name}' not found")
    return AVAILABLE_CHECKS[check_name]
