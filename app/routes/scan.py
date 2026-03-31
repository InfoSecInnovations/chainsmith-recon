"""
app/routes/scan.py - Scan Execution Routes

Endpoints for:
- Starting scans
- Scan status and progress
- Check execution status
- Scan logs
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException

from app.state import state
from app.api_models import ScanStatus, ScanStartInput
from app.engine.scanner import get_check_info, run_scan, AVAILABLE_CHECKS
from app.scenarios import get_scenario_manager

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Scan Execution ───────────────────────────────────────────

@router.post("/api/v1/scan", status_code=202)
@router.post("/api/scan", status_code=202)
async def start_scan(body: ScanStartInput = ScanStartInput()):
    """Start the web reconnaissance scan.

    Optional body fields:
      - checks: list of check names to run (empty = all)
      - suites: list of suite names to run (empty = all)
    """
    if not state.target:
        raise HTTPException(400, "Scope not set. POST to /api/scope first.")

    if state.status == "running" or state.status == "verifying":
        raise HTTPException(409, "Scan already running.")

    state.status = "running"
    state.phase = "scanning"
    state.findings = []
    state.error_message = None
    state.checks_completed = 0
    state.current_check = None
    state.check_statuses = {}
    state.check_log = []
    state.verified_count = 0
    state.verification_total = 0
    state.engagement_id = body.engagement_id

    # Launch scan in background with optional filters
    asyncio.create_task(run_scan(
        state,
        check_names=body.checks or None,
        suites=body.suites or None,
        port_profile=body.port_profile or None,
    ))

    logger.info(f"Scan started (checks={body.checks or 'all'}, suites={body.suites or 'all'})")
    return {
        "status": "accepted",
        "message": "Scan started. Poll GET /api/scan for status."
    }


@router.get("/api/v1/scan")
@router.get("/api/scan")
async def get_scan_status():
    """Get scan status with progress."""
    return ScanStatus(
        status=state.status,
        phase=state.phase,
        findings_count=len(state.findings),
        checks_total=state.checks_total,
        checks_completed=state.checks_completed,
        current_check=state.current_check,
        error=state.error_message
    )


@router.get("/api/v1/scan/checks")
@router.get("/api/scan/checks")
async def get_check_statuses():
    """Get status of all checks that are registered for the current scan."""
    mgr = get_scenario_manager()
    checks = []
    
    # If we have a runner/launcher with registered checks, use those (reflects actual scan)
    if state.runner and state.runner.checks:
        sim_names = set()
        if mgr.is_active:
            sim_names = {s.name for s in mgr.get_simulations()}
        
        # Handle checks as dict (CheckLauncher) or list (CheckRunner)
        check_items = state.runner.checks
        if isinstance(check_items, dict):
            check_items = check_items.values()
        
        for check in check_items:
            info = get_check_info(check)
            info["simulated"] = check.name in sim_names
            status = state.check_statuses.get(check.name, "pending")
            # Include suite info for UI grouping
            info["suite"] = getattr(check, 'suite', None) or _infer_suite(check.name)
            checks.append({**info, "status": status})
    elif mgr.is_active:
        # No scan running, but scenario active - show what would run
        for check in mgr.get_simulations():
            info = get_check_info(check)
            info["simulated"] = True
            info["suite"] = getattr(check, 'suite', None) or _infer_suite(check.name)
            status = state.check_statuses.get(check.name, "pending")
            checks.append({**info, "status": status})
    else:
        # No scan, no scenario - show available checks
        for name, info in AVAILABLE_CHECKS.items():
            status = state.check_statuses.get(name, "pending")
            info_copy = {**info, "suite": _infer_suite(name)}
            checks.append({**info_copy, "status": status})
    
    return {"checks": checks, "scenario": mgr.active.name if mgr.is_active else None}


def _infer_suite(check_name: str) -> str:
    """Infer suite from check name for UI grouping."""
    name_lower = check_name.lower()
    suite_patterns = {
        "network": ["dns", "wildcard_dns", "geoip", "reverse_dns", "port_scan",
                    "tls_analysis", "service_probe", "http_method_enum",
                    "banner_grab"],
        "web": ["header", "robots", "path", "openapi", "cors",
                "webdav", "vcs_exposure", "config_exposure", "directory_listing",
                "default_creds", "debug_endpoints",
                "cookie_security", "auth_detection", "waf_detection",
                "sitemap", "redirect_chain", "error_page", "ssrf_indicator",
                "favicon", "http2_detection", "hsts_preload", "sri_check",
                "mass_assignment"],
        "ai": ["llm", "embedding", "model_info", "fingerprint", "error",
                "tool_discovery", "prompt", "rate_limit", "filter", "context"],
        "mcp": ["mcp"],
        "agent": ["agent", "goal"],
        "rag": ["rag", "indirect"],
        "cag": ["cag", "cache"],
    }
    for suite, patterns in suite_patterns.items():
        if any(p in name_lower for p in patterns):
            return suite
    return "other"


@router.get("/api/v1/scan/log")
@router.get("/api/scan/log")
async def get_check_log():
    """Get history of check executions."""
    return {"log": state.check_log}
