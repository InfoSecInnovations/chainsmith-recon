"""
app/routes/scenarios.py - Scenario Management Routes

Endpoints for:
- Listing available scenarios
- Loading/clearing scenarios
- Current scenario info
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.scenarios import get_scenario_manager, ScenarioLoadError

logger = logging.getLogger(__name__)

router = APIRouter()


class ScenarioLoadRequest(BaseModel):
    """Request to load a scenario."""
    name: str


@router.get("/api/v1/scenarios")
async def list_scenarios():
    """List all available scenarios."""
    mgr = get_scenario_manager()
    return {
        "scenarios": mgr.list_available(),
        "active": mgr.active.to_dict() if mgr.active else None,
    }


@router.post("/api/v1/scenarios/load")
async def load_scenario_endpoint(req: ScenarioLoadRequest):
    """Load a scenario by name. Replaces any currently active scenario."""
    mgr = get_scenario_manager()
    try:
        scenario = mgr.load(req.name)
        return {
            "loaded": True,
            "scenario": scenario.to_dict(),
            "simulation_count": len(mgr.get_simulations()),
        }
    except ScenarioLoadError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load scenario: {e}")


@router.post("/api/v1/scenarios/clear")
async def clear_scenario():
    """Deactivate the current scenario (return to real checks)."""
    mgr = get_scenario_manager()
    prev = mgr.active.name if mgr.active else None
    mgr.clear()
    return {"cleared": True, "previous": prev}


@router.get("/api/v1/scenarios/current")
async def get_current_scenario():
    """Get the currently active scenario, or null if none."""
    mgr = get_scenario_manager()
    if not mgr.active:
        return {"active": None}
    return {
        "active": mgr.active.to_dict(),
        "simulation_count": len(mgr.get_simulations()),
    }
