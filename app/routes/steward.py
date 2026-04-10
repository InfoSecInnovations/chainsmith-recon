"""
app/routes/steward.py - Steward Agent Routes

Endpoints for check ecosystem validation, custom check management,
and upstream diff detection.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

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


@router.get("/api/v1/steward/validate")
async def validate_checks():
    """Run full check ecosystem validation (graph + chain patterns)."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    result = await agent.validate()
    return result.to_dict()


@router.get("/api/v1/steward/health")
async def steward_health():
    """Quick health check — returns last validation state from manifest."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    manifest = agent._load_manifest()
    return {
        "last_validation": manifest.get("last_validation"),
        "issues_count": len(manifest.get("validation_issues", [])),
        "custom_checks_count": len(manifest.get("custom_checks", [])),
        "last_community_hash": manifest.get("last_community_hash"),
    }


@router.post("/api/v1/steward/disable-impact")
async def disable_impact(request: DisableImpactRequest):
    """Show impact of disabling specific checks."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    impact = await agent.suggest_disable_impact(request.check_names)
    return {"impact": impact}


@router.get("/api/v1/steward/upstream-diff")
async def upstream_diff():
    """Check if community checks changed since last sync."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    diff = await agent.diff_upstream()
    return {"diff": diff}


@router.post("/api/v1/steward/scaffold")
async def scaffold_check(request: ScaffoldRequest):
    """Scaffold a new custom check (preview only — does not write to disk)."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    result = await agent.scaffold_check(
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


@router.post("/api/v1/steward/create-check")
async def create_check(request: ScaffoldRequest):
    """Scaffold, write, and register a new custom check."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    result = await agent.write_and_register_check(
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


@router.get("/api/v1/steward/custom-checks")
async def list_custom_checks():
    """List all registered custom checks."""
    from app.agents.chainsmith import ChainsmithAgent

    agent = ChainsmithAgent()
    manifest = agent._load_manifest()
    return {"custom_checks": manifest.get("custom_checks", [])}
