"""
app/routes/adjudication.py - Severity Adjudication Routes

Endpoints for:
- Starting adjudication on verified observations
- Adjudication status and results
- Per-observation adjudication detail

All reads go through the database. Adjudication status is read from the
Scan record. If no scan_id is provided, the current/most-recent session
is used via resolve_session().
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import AdjudicationRepository, ObservationRepository, ScanRepository
from app.engine.adjudication import run_adjudication
from app.scan_context import resolve_session

logger = logging.getLogger(__name__)

router = APIRouter()

_adjudication_lock = asyncio.Lock()
_adjudication_repo = AdjudicationRepository()
_observation_repo = ObservationRepository()
_scan_repo = ScanRepository()


async def _resolve_scan_id(scan_id: str | None) -> str | None:
    if scan_id:
        return scan_id
    session = resolve_session()
    if session is not None:
        return session.id
    return await _scan_repo.get_most_recent_scan_id()


@router.post("/api/v1/adjudicate", status_code=202)
async def start_adjudication(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Start severity adjudication on verified observations using evidence rubric scoring."""
    session = resolve_session(scan_id)
    if session is None:
        raise HTTPException(400, "No observations to adjudicate. Run a scan first.")

    obs = await _observation_repo.get_observations(session.id)
    if not obs:
        raise HTTPException(400, "No observations to adjudicate. Run a scan first.")

    async with _adjudication_lock:
        if session.adjudication_status == "adjudicating":
            raise HTTPException(409, "Adjudication already running.")
        session.adjudication_status = "adjudicating"

    asyncio.create_task(run_adjudication(session))

    return {
        "status": "accepted",
        "message": "Adjudication started. Poll GET /api/v1/adjudication for status.",
    }


@router.get("/api/v1/adjudication")
async def get_adjudication_status(
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Get adjudication status and results."""
    sid = await _resolve_scan_id(scan_id)
    if not sid:
        return {
            "status": "idle",
            "total": 0,
            "upheld": 0,
            "adjusted": 0,
            "results": [],
            "error": None,
        }

    results = await _adjudication_repo.get_results(sid)
    upheld = sum(1 for r in results if r["original_severity"] == r["adjudicated_severity"])
    adjusted = len(results) - upheld

    scan = await _scan_repo.get_scan(sid)
    adj_status = scan.get("adjudication_status", "idle") if scan else "idle"
    adj_error = scan.get("adjudication_error") if scan else None

    # If the session is live and adjudication is running, prefer live status.
    session = resolve_session(sid)
    if session is not None and session.adjudication_status == "adjudicating":
        adj_status = session.adjudication_status

    return {
        "status": adj_status,
        "total": len(results),
        "upheld": upheld,
        "adjusted": adjusted,
        "results": results,
        "error": adj_error,
    }


@router.get("/api/v1/adjudication/{observation_id}")
async def get_observation_adjudication(
    observation_id: str,
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Get adjudication result for a specific observation."""
    sid = await _resolve_scan_id(scan_id)
    if not sid:
        raise HTTPException(404, f"No adjudication result for observation '{observation_id}'")

    result = await _adjudication_repo.get_result_for_observation(sid, observation_id)
    if not result:
        raise HTTPException(404, f"No adjudication result for observation '{observation_id}'")
    return result
