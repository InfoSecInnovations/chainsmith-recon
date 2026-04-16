"""
app/routes/chains.py - Attack Chain Routes

Endpoints for:
- Starting chain analysis
- Chain status and results
- Chain details

All reads go through the database. Chain status is read from the Scan
record. If no scan_id is provided, the current/most-recent session is
used via resolve_session().
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import ChainRepository, ObservationRepository, ScanRepository
from app.engine.chains import run_chain_analysis
from app.scan_context import resolve_session

logger = logging.getLogger(__name__)

router = APIRouter()

_chain_lock = asyncio.Lock()
_chain_repo = ChainRepository()
_scan_repo = ScanRepository()
_observation_repo = ObservationRepository()


async def _resolve_scan_id(scan_id: str | None) -> str | None:
    """Resolve scan_id: explicit param > current session > most recent DB scan."""
    if scan_id:
        return scan_id
    session = resolve_session()
    if session is not None:
        return session.id
    return await _scan_repo.get_most_recent_scan_id()


@router.post("/api/v1/chains/analyze", status_code=202)
async def analyze_chains(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Start chain analysis (rule-based + LLM)."""
    session = resolve_session(scan_id)
    if session is None:
        raise HTTPException(400, "No observations to analyze. Run a scan first.")

    obs = await _observation_repo.get_observations(session.id)
    if not obs:
        raise HTTPException(400, "No observations to analyze. Run a scan first.")

    async with _chain_lock:
        if session.chain_status == "analyzing":
            raise HTTPException(409, "Chain analysis already running.")
        session.chain_status = "analyzing"

    # Launch analysis in background
    asyncio.create_task(run_chain_analysis(session))

    return {
        "status": "accepted",
        "message": "Chain analysis started. Poll GET /api/v1/chains for status.",
    }


@router.get("/api/v1/chains")
async def get_chains(
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Get chain analysis status and results."""
    sid = await _resolve_scan_id(scan_id)
    if not sid:
        return {
            "status": "idle",
            "chains_count": 0,
            "rule_based_count": 0,
            "llm_count": 0,
            "chains": [],
            "message": None,
            "llm_analysis": None,
        }

    # Get chains from DB
    chains = await _chain_repo.get_chains(sid)
    rule_based = [c for c in chains if c.get("source") == "rule-based"]
    llm_chains = [c for c in chains if c.get("source") in ("llm", "both")]

    # Get status from Scan record
    scan = await _scan_repo.get_scan(sid)
    chain_status = scan.get("chain_status", "idle") if scan else "idle"
    chain_error = scan.get("chain_error") if scan else None
    chain_llm_analysis = scan.get("chain_llm_analysis") if scan else None

    # If this scan's session is still live and analysis is running, prefer
    # the in-memory status (DB is updated on completion).
    session = resolve_session(sid)
    if session is not None and session.chain_status == "analyzing":
        chain_status = session.chain_status

    return {
        "status": chain_status,
        "chains_count": len(chains),
        "rule_based_count": len(rule_based),
        "llm_count": len(llm_chains),
        "chains": chains,
        "message": chain_error,
        "llm_analysis": chain_llm_analysis,
    }


@router.post("/api/v1/chains/retry", status_code=202)
async def retry_chain_analysis(
    scan_id: str | None = Query(None, description="Scan ID (defaults to current)"),
):
    """Re-run LLM chain analysis only (keeps existing rule-based chains)."""
    session = resolve_session(scan_id)
    if session is None:
        raise HTTPException(400, "No observations to analyze. Run a scan first.")

    obs = await _observation_repo.get_observations(session.id)
    if not obs:
        raise HTTPException(400, "No observations to analyze. Run a scan first.")

    if session.chain_status == "analyzing":
        raise HTTPException(409, "Chain analysis already running.")

    session.chain_status = "analyzing"

    asyncio.create_task(run_chain_analysis(session, llm_only=True))

    return {
        "status": "accepted",
        "message": "LLM chain re-analysis started. Poll GET /api/v1/chains for status.",
    }


@router.get("/api/v1/chains/{chain_id}")
async def get_chain_detail(
    chain_id: str,
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Get details of a specific chain."""
    sid = await _resolve_scan_id(scan_id)
    if not sid:
        raise HTTPException(404, f"Chain '{chain_id}' not found")

    chains = await _chain_repo.get_chains(sid)
    chain = next((c for c in chains if c.get("id") == chain_id), None)
    if not chain:
        raise HTTPException(404, f"Chain '{chain_id}' not found")

    # Include the actual observation objects
    chain_with_observations = chain.copy()
    obs_ids = chain.get("observation_ids", [])
    if obs_ids:
        all_observations = await _observation_repo.get_observations(sid)
        chain_with_observations["observations"] = [
            f for f in all_observations if f.get("id") in obs_ids
        ]
    else:
        chain_with_observations["observations"] = []

    return chain_with_observations
