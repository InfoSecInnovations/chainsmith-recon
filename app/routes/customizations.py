"""
app/routes/customizations.py - Pre-Run Severity Override Routes

Endpoints for managing severity overrides stored in
~/.chainsmith/customizations/severity_overrides.yaml.

These overrides are applied during check execution, before findings
are persisted. They let users set policy-level severity adjustments
at the check level or check+title level.
"""

import logging

from fastapi import APIRouter, HTTPException

from app.api_models import (
    PreRunCheckOverrideInput,
    PreRunSeverityOverridesInput,
    PreRunTitleOverrideInput,
)
from app.customizations import (
    get_severity_overrides_raw,
    reload_severity_overrides,
    remove_check_level_override,
    remove_check_title_override,
    save_severity_overrides_raw,
    set_check_level_override,
    set_check_title_override,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Full Config ────────────────────────────────────────────────────────────


@router.get("/api/v1/customizations/severity-overrides")
@router.get("/api/customizations/severity-overrides")
async def get_severity_overrides():
    """Get the current pre-run severity override configuration."""
    return get_severity_overrides_raw()


@router.put("/api/v1/customizations/severity-overrides")
@router.put("/api/customizations/severity-overrides")
async def put_severity_overrides(body: PreRunSeverityOverridesInput):
    """Replace the entire pre-run severity override configuration."""
    data = {}
    if body.check_level:
        data["check_level"] = body.check_level
    if body.check_title_level:
        data["check_title_level"] = body.check_title_level
    save_severity_overrides_raw(data)
    return {"message": "Severity overrides saved", "config": data}


# ─── Check-Level Overrides ──────────────────────────────────────────────────


@router.put("/api/v1/customizations/severity-overrides/check/{check_name}")
@router.put("/api/customizations/severity-overrides/check/{check_name}")
async def put_check_level_override(check_name: str, body: PreRunCheckOverrideInput):
    """Set or update a check-level severity override."""
    try:
        result = set_check_level_override(check_name, body.severity)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


@router.delete("/api/v1/customizations/severity-overrides/check/{check_name}")
@router.delete("/api/customizations/severity-overrides/check/{check_name}")
async def delete_check_level_override(check_name: str):
    """Remove a check-level severity override."""
    removed = remove_check_level_override(check_name)
    if not removed:
        raise HTTPException(404, f"No check-level override found for '{check_name}'")
    return {"check_name": check_name, "message": "Override removed"}


# ─── Check+Title Overrides ──────────────────────────────────────────────────


@router.put("/api/v1/customizations/severity-overrides/check/{check_name}/title")
@router.put("/api/customizations/severity-overrides/check/{check_name}/title")
async def put_check_title_override(check_name: str, body: PreRunTitleOverrideInput):
    """Set or update a check+title severity override."""
    try:
        result = set_check_title_override(check_name, body.title, body.severity)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


@router.delete("/api/v1/customizations/severity-overrides/check/{check_name}/title/{title:path}")
@router.delete("/api/customizations/severity-overrides/check/{check_name}/title/{title:path}")
async def delete_check_title_override(check_name: str, title: str):
    """Remove a check+title severity override."""
    removed = remove_check_title_override(check_name, title)
    if not removed:
        raise HTTPException(404, f"No title override found for '{check_name}' / '{title}'")
    return {"check_name": check_name, "title": title, "message": "Override removed"}


# ─── Reload ──────────────────────────────────────────────────────────────────


@router.post("/api/v1/customizations/severity-overrides/reload")
@router.post("/api/customizations/severity-overrides/reload")
async def reload_overrides():
    """Reload severity overrides from disk (useful after manual file edits)."""
    config = reload_severity_overrides()
    return {
        "message": "Severity overrides reloaded",
        "check_level_count": len(config.check_level),
        "check_title_count": sum(len(v) for v in config.check_title_level.values()),
    }
