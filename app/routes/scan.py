"""
app/routes/scan.py - Scan Execution Routes

Endpoints for:
- Starting scans
- Scan status and progress
- Check execution status
- Scan logs

Phase B of the concurrent-scans overhaul: all per-scan reads resolve a
ScanSession via `resolve_session(scan_id)` (falls back to the current
non-terminal session). State still holds the operator's scope-prep
fields (target, exclude, techniques, settings, proof_settings).
"""

import asyncio
import logging
import uuid

from fastapi import APIRouter, HTTPException, Query

from app.api_models import ScanStartInput, ScanStatus
from app.capture.settings import CaptureSettings
from app.check_resolver import infer_suite as _infer_suite
from app.config import get_config
from app.db.repositories import CheckLogRepository
from app.engine.scanner import AVAILABLE_CHECKS, get_check_info, run_scan
from app.gates.guardian import Guardian
from app.lib.timeutils import iso_utc
from app.proof_of_scope import ProofOfScopeSettings, ScanWindow
from app.scan_context import resolve_session
from app.scan_presets import get_preset, list_presets, preset_names
from app.scan_registry import get_registry
from app.scan_session import ScanSession
from app.scenarios import get_scenario_manager
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_check_log_repo = CheckLogRepository()
_scan_lock = asyncio.Lock()


# ─── Scan Execution ───────────────────────────────────────────


@router.post("/api/v1/scan", status_code=202)
async def start_scan(body: ScanStartInput = ScanStartInput()):
    """Start a scan. The scope travels with the request (B-1).

    Required: `target`. Optional scope fields: `exclude`, `techniques`,
    `scan_window`, `proof_of_scope`, `scan_behavior`. Plus the run selection:
    `checks`, `suites`, `port_profile`, `preset`, `check_overrides`, `capture`,
    `acknowledge_outside_window`.

    The scan is built from this body alone. It never reads the operator's scope
    prep (`POST /api/v1/scope`), so a second client changing scope cannot change
    what this scan targets.
    """
    target = (body.target or "").strip()
    if not target:
        raise HTTPException(
            400,
            "`target` is required: scope is part of the scan request "
            "(POST /api/v1/scan with target, exclude, scan_window, ...).",
        )
    exclude = list(body.exclude or [])
    techniques = list(body.techniques) or list(state.settings.get("default_techniques") or [])

    # Validate the preset name up front so an unknown name is a clean 400 rather
    # than a silently-ignored scan. Resolution itself happens in run_scan.
    if body.preset and get_preset(body.preset) is None:
        raise HTTPException(
            400,
            f"Unknown preset '{body.preset}'. Available: {', '.join(preset_names())}",
        )

    # This scan's own proof-of-scope settings, from the request. Fresh, never a
    # copy of the operator's prep, which another client may be changing.
    proof_settings = ProofOfScopeSettings()
    if body.scan_window:
        proof_settings.scan_window = ScanWindow(
            start=body.scan_window.start, end=body.scan_window.end
        )
    if body.proof_of_scope:
        proof_settings.traffic_logging = body.proof_of_scope.traffic_logging
        proof_settings.block_exclusions = body.proof_of_scope.block_exclusions
        proof_settings.log_violations = body.proof_of_scope.log_violations

    scan_id = uuid.uuid4().hex[:16]

    # Scan-window gate: delegated to Guardian so all scan allow/block decisions
    # stay in one chokepoint. Stamped with the scan id, so an acknowledged or
    # blocked window is on this scan's compliance record.
    gate_guardian = Guardian.from_scope(target, exclude=exclude, scan_id=scan_id)
    allowed, reason = gate_guardian.check_scan_window(
        proof_settings.scan_window,
        acknowledged=body.acknowledge_outside_window,
    )
    if not allowed:
        raise HTTPException(409, reason)
    proof_settings.outside_window_acknowledged = body.acknowledge_outside_window
    if body.acknowledge_outside_window:
        proof_settings.outside_window_acknowledged_at = iso_utc()

    if body.scan_behavior:
        from app.routes.scope import apply_scan_behavior

        apply_scan_behavior(body.scan_behavior)

    # Concurrent-scan cap. Returns 429 when the cap is reached (caller retries).
    # Pre-register the session under the cap-hold so the scan_id is visible
    # to pollers before the background task starts — this closes the race
    # where scan.html polled during the gap between create_task() and
    # run_scan() reaching registry.register(), which used to return "idle"
    # (or a previous scan's state) and leave the UI frozen.
    cfg = get_config()
    max_scans = cfg.concurrency.max_concurrent_scans
    guardian = Guardian.from_scope(target, exclude=exclude, scan_id=scan_id)
    session = ScanSession(
        id=scan_id,
        target=target,
        exclude=exclude,
        techniques=techniques,
        status="queued",
        phase="queued",
        guardian=guardian,
        settings=dict(state.settings),
        proof_settings=proof_settings,
        operator_session_id=state.session_id,
    )
    async with _scan_lock:
        active = get_registry().active_count()
        if active >= max_scans:
            # D-5: reject rather than queue, so a scan's traffic starts when the
            # operator asked for it or not at all. Retry-After tells clients
            # when to try again.
            raise HTTPException(
                429,
                f"Concurrent scan limit reached ({active}/{max_scans}). Retry later.",
                headers={"Retry-After": str(max(1, cfg.concurrency.retry_after_seconds))},
            )
        get_registry().register(session)

    # Mirror this scan's scope into the operator prep, which chat and the scan
    # planner advisor read as "the current scope". Display only: no scan reads
    # it (see the docstring).
    state.target = target
    state.exclude = exclude
    state.techniques = techniques

    # Launch scan in background with the pre-registered session.
    asyncio.create_task(
        run_scan(
            state,
            check_names=body.checks or None,
            suites=body.suites or None,
            port_profile=body.port_profile or None,
            session=session,
            preset=body.preset or None,
            check_overrides=body.check_overrides or None,
            capture=CaptureSettings.from_request(**body.capture.model_dump())
            if body.capture
            else None,
        )
    )

    logger.info(
        f"Scan queued (id={scan_id}, checks={body.checks or 'all'}, "
        f"suites={body.suites or 'all'}, preset={body.preset or 'none'})"
    )
    return {
        "status": "accepted",
        "scan_id": scan_id,
        "message": "Scan started. Poll GET /api/v1/scan for status.",
    }


def _require_session(scan_id: str | None, *, for_path: bool = False):
    """Resolve a session or raise. Path routes 404 on unknown id; unscoped
    routes fall back to `resolve_session` (current/most-recent)."""
    if for_path:
        from app.scan_registry import get_registry

        session = get_registry().get(scan_id) if scan_id else None
        if session is None:
            raise HTTPException(404, f"Scan '{scan_id}' not found")
        return session
    return resolve_session(scan_id)


def _do_pause(session):
    if session is None or session.status != "running":
        current = session.status if session else "idle"
        raise HTTPException(409, f"Cannot pause: scan status is '{current}'.")
    session.pause_event.clear()
    session.status = "paused"
    logger.info(f"Scan pause requested (id={session.id})")
    return {"status": "paused", "scan_id": session.id}


def _do_resume(session):
    if session is None or session.status != "paused":
        current = session.status if session else "idle"
        raise HTTPException(409, f"Cannot resume: scan status is '{current}'.")
    session.status = "running"
    session.pause_event.set()
    logger.info(f"Scan resumed (id={session.id})")
    return {"status": "running", "scan_id": session.id}


def _do_stop(session):
    if session is None or session.status not in ("queued", "running", "paused"):
        current = session.status if session else "idle"
        raise HTTPException(409, f"Cannot stop: scan status is '{current}'.")
    session.stop_requested = True
    session.pause_event.set()
    logger.info(f"Scan stop requested (id={session.id})")
    return {"status": "stopping", "scan_id": session.id}


def _status_payload(session) -> ScanStatus:
    # Advertise SSE support only when the operator has opted in
    # via `scan_stream.enabled`. The route itself stays live regardless —
    # this flag only controls what clients are told, so the UI falls back
    # to polling until the operator flips it on.
    stream_enabled = get_config().scan_stream.enabled
    if session is None:
        return ScanStatus(
            status="idle",
            phase="idle",
            observations_count=0,
            checks_total=0,
            checks_completed=0,
            current_check=None,
            error=None,
            capabilities={"stream": stream_enabled},
        )
    obs_count = 0
    if session.runner is not None:
        writer = getattr(session.runner, "observation_writer", None)
        if writer:
            obs_count = writer.count
    return ScanStatus(
        status=session.status,
        phase=session.phase,
        observations_count=obs_count,
        checks_total=session.checks_total,
        checks_completed=session.checks_completed,
        current_check=session.current_check,
        error=session.error_message,
        capabilities={"stream": stream_enabled},
    )


# ─── Scoped control endpoints (preferred; per-scan addressable) ───────


@router.post("/api/v1/scans/{scan_id}/pause", status_code=202)
async def pause_scan_scoped(scan_id: str):
    """Pause the named scan at the next check boundary."""
    return _do_pause(_require_session(scan_id, for_path=True))


@router.post("/api/v1/scans/{scan_id}/resume", status_code=202)
async def resume_scan_scoped(scan_id: str):
    """Resume the named paused scan."""
    return _do_resume(_require_session(scan_id, for_path=True))


@router.post("/api/v1/scans/{scan_id}/stop", status_code=202)
async def stop_scan_scoped(scan_id: str):
    """Stop the named scan; runner aborts at the next check boundary."""
    return _do_stop(_require_session(scan_id, for_path=True))


@router.get("/api/v1/scans/{scan_id}/status")
async def get_scan_status_scoped(scan_id: str):
    """Live status of a registry-tracked scan (404 if unknown)."""
    return _status_payload(_require_session(scan_id, for_path=True))


# ─── Unscoped back-compat aliases (default to current scan) ───────────


@router.post("/api/v1/scan/pause", status_code=202)
async def pause_scan(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Pause the running scan at the next check boundary."""
    return _do_pause(resolve_session(scan_id))


@router.post("/api/v1/scan/resume", status_code=202)
async def resume_scan(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Resume a paused scan."""
    return _do_resume(resolve_session(scan_id))


@router.post("/api/v1/scan/stop", status_code=202)
async def stop_scan(scan_id: str | None = Query(None, description="Scan ID (defaults to current)")):
    """Stop the scan; runner aborts at the next check boundary."""
    return _do_stop(resolve_session(scan_id))


@router.get("/api/v1/scan")
async def get_scan_status(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Get scan status with progress."""
    return _status_payload(resolve_session(scan_id))


@router.get("/api/v1/scan/checks")
async def get_check_statuses(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Get status of all checks that are registered for the current scan."""
    mgr = get_scenario_manager()
    checks = []
    session = resolve_session(scan_id)

    # If we have a runner/launcher with registered checks, use those (reflects actual scan)
    if session is not None and session.runner and session.runner.checks:
        sim_names = set()
        if mgr.is_active:
            sim_names = {s.name for s in mgr.get_simulations()}

        # Handle checks as dict (CheckLauncher) or list (CheckRunner)
        check_items = session.runner.checks
        if isinstance(check_items, dict):
            check_items = check_items.values()

        for check in check_items:
            info = get_check_info(check)
            info["simulated"] = check.name in sim_names
            status = session.check_statuses.get(check.name, "pending")
            # Include suite info for UI grouping
            info["suite"] = getattr(check, "suite", None) or _infer_suite(check.name)
            entry = {**info, "status": status}
            skip_reason = session.skip_reasons.get(check.name)
            if skip_reason:
                entry["skip_reason"] = skip_reason
            checks.append(entry)
    elif mgr.is_active:
        # No scan running, but scenario active - show what would run
        for check in mgr.get_simulations():
            info = get_check_info(check)
            info["simulated"] = True
            info["suite"] = getattr(check, "suite", None) or _infer_suite(check.name)
            entry = {**info, "status": "pending"}
            checks.append(entry)
    else:
        # No scan, no scenario - show available checks
        for name, info in AVAILABLE_CHECKS.items():
            info_copy = {**info, "suite": _infer_suite(name)}
            entry = {**info_copy, "status": "pending"}
            checks.append(entry)

    return {"checks": checks, "scenario": mgr.active.name if mgr.is_active else None}


@router.get("/api/v1/scan/presets")
async def get_scan_presets():
    """List the available scan presets (name → description) for the CLI/WebUI."""
    presets = list_presets()
    return {"presets": [{"name": name, "description": desc} for name, desc in presets.items()]}


@router.get("/api/v1/scan/log")
async def get_check_log(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Get history of check executions from the database."""
    session = resolve_session(scan_id)
    sid = session.id if session is not None else None
    if not sid:
        return {"log": []}

    log = await _check_log_repo.get_log(sid)
    return {"log": log}
