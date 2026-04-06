"""
app/routes/adjudication.py - Severity Adjudication Routes

Endpoints for:
- Starting adjudication on verified findings
- Adjudication status and results
- Per-finding adjudication detail

When an optional `scan_id` query parameter is provided, results are
read from the database (historical). Otherwise, the active session's
in-memory data is returned.
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query

from app.api_models import AdjudicateRequest
from app.db.repositories import AdjudicationRepository
from app.engine.adjudication import run_adjudication
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_adjudication_repo = AdjudicationRepository()


@router.post("/api/v1/adjudicate", status_code=202)
@router.post("/api/adjudicate", status_code=202)
async def start_adjudication(body: AdjudicateRequest = AdjudicateRequest()):
    """Start severity adjudication on verified findings.

    Optional body fields:
      - approach: structured_challenge, adversarial_debate, evidence_rubric, auto
    """
    if len(state.findings) == 0:
        raise HTTPException(400, "No findings to adjudicate. Run a scan first.")

    if state.adjudication_status == "adjudicating":
        raise HTTPException(409, "Adjudication already running.")

    state.adjudication_status = "adjudicating"
    state.adjudication_results = []
    state.adjudication_error = None

    asyncio.create_task(run_adjudication(state, approach=body.approach))

    return {
        "status": "accepted",
        "message": "Adjudication started. Poll GET /api/adjudication for status.",
    }


@router.get("/api/v1/adjudication")
@router.get("/api/adjudication")
async def get_adjudication_status(
    scan_id: str | None = Query(None, description="Historical scan ID"),
):
    """Get adjudication status and results. Pass scan_id for historical data."""
    if scan_id:
        results = await _adjudication_repo.get_results(scan_id)
        upheld = sum(1 for r in results if r["original_severity"] == r["adjudicated_severity"])
        adjusted = len(results) - upheld
        return {
            "status": "complete",
            "total": len(results),
            "upheld": upheld,
            "adjusted": adjusted,
            "results": results,
            "error": None,
        }

    upheld = sum(
        1
        for r in state.adjudication_results
        if r.get("original_severity") == r.get("adjudicated_severity")
    )
    adjusted = len(state.adjudication_results) - upheld

    return {
        "status": state.adjudication_status,
        "total": len(state.adjudication_results),
        "upheld": upheld,
        "adjusted": adjusted,
        "results": state.adjudication_results,
        "error": state.adjudication_error,
    }


@router.get("/api/v1/adjudication/{finding_id}")
@router.get("/api/adjudication/{finding_id}")
async def get_finding_adjudication(
    finding_id: str,
    scan_id: str | None = Query(None, description="Historical scan ID"),
):
    """Get adjudication result for a specific finding."""
    if scan_id:
        result = await _adjudication_repo.get_result_for_finding(scan_id, finding_id)
        if not result:
            raise HTTPException(404, f"No adjudication result for finding '{finding_id}'")
        return result

    result = next(
        (r for r in state.adjudication_results if r.get("finding_id") == finding_id),
        None,
    )
    if not result:
        raise HTTPException(404, f"No adjudication result for finding '{finding_id}'")
    return result
