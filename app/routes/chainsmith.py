"""
app/routes/chainsmith.py - Chainsmith Agent Routes

Endpoints for check ecosystem validation, custom check management,
and upstream diff detection. All routes delegate to the engine layer.
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()


class ScaffoldRequest(BaseModel):
    name: str
    description: str
    suite: str
    conditions: list[dict] | None = None
    produces: list[str] | None = None
    service_types: list[str] | None = None
    intrusive: bool = False


class DisableImpactRequest(BaseModel):
    check_names: list[str]


@router.post("/api/v1/chainsmith/validate", status_code=202)
async def validate_checks():
    """Run full check ecosystem validation (async — poll status endpoint)."""
    if state.chainsmith_status == "validating":
        raise HTTPException(409, "Validation already in progress")

    from app.engine.chainsmith import run_validation

    asyncio.create_task(run_validation(state))
    return {"status": "accepted", "message": "Validation started. Poll /api/v1/chainsmith/status."}


@router.get("/api/v1/chainsmith/status")
async def chainsmith_status():
    """Poll chainsmith operation status."""
    from app.engine.chainsmith import get_health

    health = await get_health()
    return {
        "status": state.chainsmith_status,
        **health,
    }


@router.get("/api/v1/chainsmith/health")
async def chainsmith_health():
    """Quick health check — returns last validation state."""
    from app.engine.chainsmith import get_health

    return await get_health()


@router.post("/api/v1/chainsmith/disable-impact")
async def disable_impact(request: DisableImpactRequest):
    """Show impact of disabling specific checks."""
    from app.engine.chainsmith import get_disable_impact

    return await get_disable_impact(request.check_names)


@router.get("/api/v1/chainsmith/upstream-diff")
async def upstream_diff():
    """Check if community checks changed since last sync."""
    from app.engine.chainsmith import run_upstream_diff

    return await run_upstream_diff(state)


@router.post("/api/v1/chainsmith/scaffold")
async def scaffold_check(request: ScaffoldRequest):
    """Scaffold a new custom check (preview only — does not write to disk)."""
    from app.engine.chainsmith import scaffold_check as engine_scaffold

    result = await engine_scaffold(
        name=request.name,
        description=request.description,
        suite=request.suite,
        conditions=request.conditions,
        produces=request.produces,
        service_types=request.service_types,
        intrusive=request.intrusive,
    )
    if result.get("error"):
        raise HTTPException(409, result["error"])
    return result


@router.post("/api/v1/chainsmith/create-check")
async def create_check(request: ScaffoldRequest):
    """Scaffold, write, and register a new custom check."""
    from app.engine.chainsmith import create_check as engine_create

    result = await engine_create(
        name=request.name,
        description=request.description,
        suite=request.suite,
        conditions=request.conditions,
        produces=request.produces,
        service_types=request.service_types,
        intrusive=request.intrusive,
    )
    if result.get("error"):
        raise HTTPException(409, result["error"])
    return result


@router.get("/api/v1/chainsmith/custom-checks")
async def list_custom_checks():
    """List all registered custom checks."""
    from app.engine.chainsmith import get_custom_checks

    return {"custom_checks": await get_custom_checks()}
