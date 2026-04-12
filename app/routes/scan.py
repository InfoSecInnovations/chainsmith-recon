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

from app.api_models import ScanStartInput, ScanStatus
from app.check_resolver import infer_suite as _infer_suite
from app.db.repositories import CheckLogRepository
from app.engine.scanner import AVAILABLE_CHECKS, get_check_info, run_scan
from app.scenarios import get_scenario_manager
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_check_log_repo = CheckLogRepository()
_scan_lock = asyncio.Lock()


# ─── Scan Execution ───────────────────────────────────────────


@router.post("/api/v1/scan", status_code=202)
async def start_scan(body: ScanStartInput = ScanStartInput()):
    """Start the web reconnaissance scan.

    Optional body fields:
      - checks: list of check names to run (empty = all)
      - suites: list of suite names to run (empty = all)
    """
    if not state.target:
        raise HTTPException(400, "Scope not set. POST to /api/scope first.")

    async with _scan_lock:
        if state.status == "running":
            raise HTTPException(409, "Scan already running.")
        state.status = "running"
    state.phase = "scanning"
    state.error_message = None
    state.checks_completed = 0
    state.current_check = None
    state.check_statuses = {}
    state.skip_reasons = {}
    state.engagement_id = body.engagement_id

    # Launch scan in background with optional filters
    asyncio.create_task(
        run_scan(
            state,
            check_names=body.checks or None,
            suites=body.suites or None,
            port_profile=body.port_profile or None,
        )
    )

    logger.info(f"Scan started (checks={body.checks or 'all'}, suites={body.suites or 'all'})")
    return {"status": "accepted", "message": "Scan started. Poll GET /api/scan for status."}


@router.post("/api/v1/scan/pause", status_code=202)
async def pause_scan():
    """Pause the running scan at the next check boundary."""
    if state.status != "running":
        raise HTTPException(409, f"Cannot pause: scan status is '{state.status}'.")
    state.pause_event.clear()
    state.status = "paused"
    logger.info("Scan pause requested")
    return {"status": "paused"}


@router.post("/api/v1/scan/resume", status_code=202)
async def resume_scan():
    """Resume a paused scan."""
    if state.status != "paused":
        raise HTTPException(409, f"Cannot resume: scan status is '{state.status}'.")
    state.status = "running"
    state.pause_event.set()
    logger.info("Scan resumed")
    return {"status": "running"}


@router.post("/api/v1/scan/stop", status_code=202)
async def stop_scan():
    """Stop the scan; runner aborts at the next check boundary."""
    if state.status not in ("running", "paused"):
        raise HTTPException(409, f"Cannot stop: scan status is '{state.status}'.")
    state.stop_requested = True
    # Unblock the runner if it's paused so it can observe the stop flag.
    state.pause_event.set()
    logger.info("Scan stop requested")
    return {"status": "stopping"}


@router.get("/api/v1/scan")
async def get_scan_status():
    """Get scan status with progress."""
    # Get live observation count from the writer via the runner
    obs_count = 0
    if state.runner:
        writer = getattr(state.runner, "observation_writer", None)
        if writer:
            obs_count = writer.count

    return ScanStatus(
        status=state.status,
        phase=state.phase,
        observations_count=obs_count,
        checks_total=state.checks_total,
        checks_completed=state.checks_completed,
        current_check=state.current_check,
        error=state.error_message,
    )


@router.get("/api/v1/scan/checks")
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
            info["suite"] = getattr(check, "suite", None) or _infer_suite(check.name)
            entry = {**info, "status": status}
            skip_reason = state.skip_reasons.get(check.name)
            if skip_reason:
                entry["skip_reason"] = skip_reason
            checks.append(entry)
    elif mgr.is_active:
        # No scan running, but scenario active - show what would run
        for check in mgr.get_simulations():
            info = get_check_info(check)
            info["simulated"] = True
            info["suite"] = getattr(check, "suite", None) or _infer_suite(check.name)
            status = state.check_statuses.get(check.name, "pending")
            entry = {**info, "status": status}
            skip_reason = state.skip_reasons.get(check.name)
            if skip_reason:
                entry["skip_reason"] = skip_reason
            checks.append(entry)
    else:
        # No scan, no scenario - show available checks
        for name, info in AVAILABLE_CHECKS.items():
            status = state.check_statuses.get(name, "pending")
            info_copy = {**info, "suite": _infer_suite(name)}
            entry = {**info_copy, "status": status}
            skip_reason = state.skip_reasons.get(name)
            if skip_reason:
                entry["skip_reason"] = skip_reason
            checks.append(entry)

    return {"checks": checks, "scenario": mgr.active.name if mgr.is_active else None}


@router.get("/api/v1/scan/log")
async def get_check_log():
    """Get history of check executions from the database."""
    sid = state.active_scan_id
    if not sid:
        return {"log": []}

    log = await _check_log_repo.get_log(sid)
    return {"log": log}
