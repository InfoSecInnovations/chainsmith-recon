"""
app/routes/preferences.py - Preferences and Profiles Routes

Endpoints for:
- Getting/updating preferences
- Profile CRUD operations
- Profile activation and resolution
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.preferences import (
    activate_profile as activate_profile_internal,
)
from app.preferences import (
    create_profile as create_profile_internal,
)
from app.preferences import (
    delete_profile as delete_profile_internal,
)
from app.preferences import (
    get_profile as get_profile_internal,
)
from app.preferences import (
    get_profile_store,
    save_profile_store,
)
from app.preferences import (
    list_profiles as list_profiles_internal,
)
from app.preferences import (
    reset_profile as reset_profile_internal,
)
from app.preferences import (
    resolve_profile as resolve_profile_internal,
)
from app.preferences import (
    update_profile as update_profile_internal,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Models ───────────────────────────────────────────────────


class PreferencesUpdateInput(BaseModel):
    """Input for updating preferences."""

    network: dict | None = None
    rate_limiting: dict | None = None
    checks: dict | None = None
    proof_of_scope: dict | None = None
    advanced: dict | None = None
    check_overrides: dict | None = None


class ProfileCreateInput(BaseModel):
    """Input for creating a new profile."""

    name: str
    description: str = ""
    base: str | None = None
    overrides: dict | None = None


class ProfileUpdateInput(BaseModel):
    """Input for updating a profile."""

    description: str | None = None
    overrides: dict | None = None
    merge: bool = True


# ─── Preferences ──────────────────────────────────────────────


@router.get("/api/v1/preferences")
async def get_preferences_endpoint():
    """Get the active profile's resolved preferences."""
    store = get_profile_store(reload=True)
    prefs = store.get_active_preferences()
    return {
        "active_profile": store.active_profile,
        "preferences": prefs.to_dict(),
    }


@router.put("/api/v1/preferences")
async def update_preferences_endpoint(updates: PreferencesUpdateInput):
    """Update preferences in the active profile."""
    store = get_profile_store(reload=True)

    # Build overrides from the update
    overrides = {}
    if updates.network:
        overrides["network"] = updates.network
    if updates.rate_limiting:
        overrides["rate_limiting"] = updates.rate_limiting
    if updates.checks:
        overrides["checks"] = updates.checks
    if updates.proof_of_scope:
        overrides["proof_of_scope"] = updates.proof_of_scope
    if updates.advanced:
        overrides["advanced"] = updates.advanced
    if updates.check_overrides:
        overrides["check_overrides"] = updates.check_overrides

    if overrides:
        try:
            store.update_profile(store.active_profile, overrides=overrides, merge=True)
            save_profile_store(store)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    prefs = store.get_active_preferences()
    return {
        "active_profile": store.active_profile,
        "preferences": prefs.to_dict(),
    }


# ─── Profiles ─────────────────────────────────────────────────


@router.get("/api/v1/profiles")
async def list_profiles_endpoint():
    """List all available profiles."""
    profiles = list_profiles_internal()
    return {
        "profiles": profiles,
        "count": len(profiles),
    }


@router.get("/api/v1/profiles/{name}")
async def get_profile_endpoint(name: str):
    """Get a specific profile by name."""
    profile = get_profile_internal(name)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")

    # Also return resolved preferences
    prefs = profile.resolve()

    return {
        "profile": profile.to_dict(),
        "resolved_preferences": prefs.to_dict(),
    }


@router.post("/api/v1/profiles")
async def create_profile_endpoint(input: ProfileCreateInput):
    """Create a new profile."""
    try:
        profile = create_profile_internal(
            name=input.name,
            description=input.description,
            base=input.base,
            overrides=input.overrides,
            save=True,
        )
        return {
            "created": True,
            "profile": profile.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.put("/api/v1/profiles/{name}")
async def update_profile_endpoint(name: str, input: ProfileUpdateInput):
    """Update an existing profile."""
    profile = get_profile_internal(name)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")

    try:
        updated = update_profile_internal(
            name=name,
            description=input.description,
            overrides=input.overrides,
            merge=input.merge,
            save=True,
        )
        return {
            "updated": True,
            "profile": updated.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.delete("/api/v1/profiles/{name}")
async def delete_profile_endpoint(name: str):
    """Delete a profile. Built-in profiles are reset instead of deleted."""
    profile = get_profile_internal(name)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")

    try:
        delete_profile_internal(name, save=True)

        # Check if it was a built-in (still exists after delete = was reset)
        still_exists = get_profile_internal(name) is not None

        return {
            "deleted": not still_exists,
            "reset": still_exists and profile.built_in,
            "name": name,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.put("/api/v1/profiles/{name}/activate")
async def activate_profile_endpoint(name: str):
    """Set a profile as the active profile."""
    profile = get_profile_internal(name)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")

    try:
        activate_profile_internal(name, save=True)
        prefs = resolve_profile_internal(name)

        return {
            "activated": True,
            "active_profile": name,
            "preferences": prefs.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/api/v1/profiles/{name}/reset")
async def reset_profile_endpoint(name: str):
    """Reset a profile to its default state."""
    profile = get_profile_internal(name)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")

    try:
        reset = reset_profile_internal(name, save=True)
        return {
            "reset": True,
            "profile": reset.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/api/v1/profiles/{name}/resolve")
async def resolve_profile_endpoint(name: str):
    """
    Resolve a profile to full preferences without activating it.

    Useful for previewing profile settings or for temporary use in scans.
    """
    try:
        prefs = resolve_profile_internal(name)
        return {
            "profile": name,
            "preferences": prefs.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
