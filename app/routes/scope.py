"""
app/routes/scope.py - Scope and Settings Routes

Endpoints for:
- Target scope configuration
- Engagement window management
- Scan settings
- State reset
"""

import logging
from datetime import datetime

from fastapi import APIRouter

from app.api_models import ExtendedScopeInput, ScanSettings
from app.preferences import (
    SUITES_WITH_ON_CRITICAL,
    VALID_ON_CRITICAL_VALUES,
    get_profile_store,
    save_profile_store,
)
from app.proof_of_scope import EngagementWindow, ScopeChecker, violation_logger
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Reset ────────────────────────────────────────────────────


@router.post("/api/v1/reset")
@router.post("/api/reset")
async def reset():
    """Reset all state."""
    state.reset()
    logger.info(f"Reset. New session: {state.session_id}")
    return {"status": "ok", "session_id": state.session_id}


# ─── Scope ────────────────────────────────────────────────────


@router.post("/api/v1/scope")
@router.post("/api/scope")
async def set_scope(scope: ExtendedScopeInput):
    """Set the scan scope with optional engagement window and proof settings."""
    state.target = scope.target
    state.exclude = scope.exclude
    state.techniques = (
        scope.techniques if scope.techniques else state.settings["default_techniques"]
    )

    # Initialize scope checker for in-scope validation
    state.scope_checker = ScopeChecker(scope.target, scope.exclude)

    # Handle engagement window
    if scope.engagement_window:
        state.proof_settings.engagement_window = EngagementWindow(
            start=scope.engagement_window.start, end=scope.engagement_window.end
        )

    # Handle proof of scope settings
    if scope.proof_of_scope:
        state.proof_settings.traffic_logging = scope.proof_of_scope.traffic_logging
        if hasattr(scope.proof_of_scope, "block_exclusions"):
            state.proof_settings.block_exclusions = scope.proof_of_scope.block_exclusions
        if hasattr(scope.proof_of_scope, "log_violations"):
            state.proof_settings.log_violations = scope.proof_of_scope.log_violations

    # Handle outside window acknowledgment
    if hasattr(scope, "outside_window_acknowledged") and scope.outside_window_acknowledged:
        state.proof_settings.outside_window_acknowledged = True
        state.proof_settings.outside_window_acknowledged_at = datetime.utcnow().isoformat() + "Z"

        # Log the acknowledgment as a violation record
        if state.proof_settings.log_violations:
            violation_logger.log_violation(
                violation_type="outside_window",
                reason="User acknowledged scanning outside engagement window",
                user_acknowledged=True,
            )

    # Handle scan behavior settings (on_critical + intrusive)
    scan_behavior_response = {"on_critical": "annotate", "intrusive_web": False}
    if scope.scan_behavior:
        try:
            store = get_profile_store()
            active = store.get_active_profile()
            prefs = active.resolve()

            # Apply on_critical settings
            if scope.scan_behavior.on_critical:
                oc = scope.scan_behavior.on_critical
                if oc.default in VALID_ON_CRITICAL_VALUES:
                    prefs.checks.on_critical = oc.default
                for suite in SUITES_WITH_ON_CRITICAL:
                    suite_val = getattr(oc, suite, None)
                    if suite_val is not None and suite_val in VALID_ON_CRITICAL_VALUES:
                        setattr(prefs.checks, f"on_critical_{suite}", suite_val)
                    else:
                        setattr(prefs.checks, f"on_critical_{suite}", None)

            # Apply intrusive_web
            prefs.checks.intrusive_web = scope.scan_behavior.intrusive_web

            # Persist to active profile overrides
            from app.preferences import Preferences, _calculate_overrides

            active.overrides = _calculate_overrides(Preferences(), prefs)
            save_profile_store(store)

            scan_behavior_response = {
                "on_critical": prefs.checks.on_critical,
                "on_critical_overrides": {
                    suite: getattr(prefs.checks, f"on_critical_{suite}")
                    for suite in SUITES_WITH_ON_CRITICAL
                    if getattr(prefs.checks, f"on_critical_{suite}") is not None
                },
                "intrusive_web": prefs.checks.intrusive_web,
            }
        except Exception as e:
            logger.warning(f"Failed to apply scan_behavior settings: {e}")

    logger.info(
        f"Scope set: target={scope.target}, exclude={scope.exclude}, "
        f"window_configured={state.proof_settings.engagement_window.is_configured()}"
    )

    return {
        "status": "ok",
        "target": state.target,
        "exclude": state.exclude,
        "techniques": state.techniques,
        "engagement_window": {
            "start": state.proof_settings.engagement_window.start,
            "end": state.proof_settings.engagement_window.end,
            "is_within_window": state.proof_settings.engagement_window.is_within_window(),
        },
        "proof_of_scope": {
            "traffic_logging": state.proof_settings.traffic_logging,
            "block_exclusions": getattr(state.proof_settings, "block_exclusions", False),
            "log_violations": getattr(state.proof_settings, "log_violations", True),
        },
        "scan_behavior": scan_behavior_response,
    }


@router.get("/api/v1/scope")
@router.get("/api/scope")
async def get_scope():
    """Get current scope including engagement window status."""
    window = state.proof_settings.engagement_window
    proof = state.proof_settings

    # Read current scan behavior from preferences
    try:
        from app.preferences import get_preferences

        prefs = get_preferences()
        scan_behavior = {
            "on_critical": prefs.checks.on_critical,
            "on_critical_overrides": {
                suite: getattr(prefs.checks, f"on_critical_{suite}")
                for suite in SUITES_WITH_ON_CRITICAL
                if getattr(prefs.checks, f"on_critical_{suite}") is not None
            },
            "intrusive_web": prefs.checks.intrusive_web,
        }
    except Exception:
        scan_behavior = {"on_critical": "annotate", "intrusive_web": False}

    return {
        "target": state.target,
        "exclude": state.exclude,
        "techniques": state.techniques,
        "engagement_window": {
            "start": window.start,
            "end": window.end,
            "is_within_window": window.is_within_window(),
            "is_configured": window.is_configured(),
        },
        "proof_of_scope": {
            "traffic_logging": proof.traffic_logging,
            "block_exclusions": getattr(proof, "block_exclusions", False),
            "log_violations": getattr(proof, "log_violations", True),
            "outside_window_acknowledged": proof.outside_window_acknowledged,
        },
        "scan_behavior": scan_behavior,
    }


@router.get("/api/v1/scope/window-check")
@router.get("/api/scope/window-check")
async def check_engagement_window():
    """Check if current time is within engagement window."""
    window = state.proof_settings.engagement_window

    return {
        "is_within_window": window.is_within_window(),
        "is_configured": window.is_configured(),
        "start": window.start,
        "end": window.end,
        "current_time": datetime.utcnow().isoformat() + "Z",
        "outside_window_acknowledged": state.proof_settings.outside_window_acknowledged,
    }


# ─── Settings ─────────────────────────────────────────────────


@router.get("/api/v1/settings")
@router.get("/api/settings")
async def get_settings():
    """Get current settings."""
    return {
        "parallel": state.settings["parallel"],
        "rate_limit": state.settings["rate_limit"],
        "default_techniques": state.settings["default_techniques"],
        "verification_level": state.settings["verification_level"],
    }


@router.post("/api/v1/settings")
@router.post("/api/settings")
async def update_settings(settings: ScanSettings):
    """Update scan settings."""
    state.settings["parallel"] = settings.parallel
    state.settings["rate_limit"] = settings.rate_limit
    state.settings["default_techniques"] = settings.default_techniques
    state.settings["verification_level"] = settings.verification_level

    logger.info(f"Settings updated: {state.settings}")
    return {"status": "ok", "settings": state.settings}
