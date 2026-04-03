"""
app/routes/chains.py - Attack Chain Routes

Endpoints for:
- Starting chain analysis
- Chain status and results
- Chain details

When an optional `scan_id` query parameter is provided, chains are
read from the database (historical). Otherwise, the active scan's
in-memory data is returned.
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import ChainRepository
from app.state import state
from app.engine.chains import run_chain_analysis

logger = logging.getLogger(__name__)

router = APIRouter()

_chain_repo = ChainRepository()


@router.post("/api/v1/chains/analyze", status_code=202)
@router.post("/api/chains/analyze", status_code=202)
async def analyze_chains():
    """Start chain analysis (rule-based + LLM)."""
    if len(state.findings) == 0:
        raise HTTPException(400, "No findings to analyze. Run a scan first.")
    
    if state.chain_status == "analyzing":
        raise HTTPException(409, "Chain analysis already running.")
    
    state.chain_status = "analyzing"
    state.chains = []
    state.chain_error = None
    
    # Launch analysis in background
    asyncio.create_task(run_chain_analysis(state))
    
    return {
        "status": "accepted",
        "message": "Chain analysis started. Poll GET /api/chains for status."
    }


@router.get("/api/v1/chains")
@router.get("/api/chains")
async def get_chains(
    scan_id: Optional[str] = Query(None, description="Historical scan ID"),
):
    """Get chain analysis status and results. Pass scan_id for historical data."""
    if scan_id:
        chains = await _chain_repo.get_chains(scan_id)
        rule_based = [c for c in chains if c.get("source") == "rule-based"]
        llm_chains = [c for c in chains if c.get("source") in ("llm", "both")]
        return {
            "status": "complete",
            "chains_count": len(chains),
            "rule_based_count": len(rule_based),
            "llm_count": len(llm_chains),
            "chains": chains,
            "message": None,
            "llm_analysis": None,
        }

    rule_based = [c for c in state.chains if c.get("source") == "rule-based"]
    llm_chains = [c for c in state.chains if c.get("source") in ["llm", "both"]]

    return {
        "status": state.chain_status,
        "chains_count": len(state.chains),
        "rule_based_count": len(rule_based),
        "llm_count": len(llm_chains),
        "chains": state.chains,
        "message": state.chain_error,
        "llm_analysis": state.chain_llm_analysis,
    }


@router.post("/api/v1/chains/retry", status_code=202)
@router.post("/api/chains/retry", status_code=202)
async def retry_chain_analysis():
    """Re-run LLM chain analysis only (keeps existing rule-based chains)."""
    if len(state.findings) == 0:
        raise HTTPException(400, "No findings to analyze. Run a scan first.")

    if state.chain_status == "analyzing":
        raise HTTPException(409, "Chain analysis already running.")

    state.chain_status = "analyzing"
    state.chain_error = None
    state.chain_llm_analysis = None

    asyncio.create_task(run_chain_analysis(state, llm_only=True))

    return {
        "status": "accepted",
        "message": "LLM chain re-analysis started. Poll GET /api/chains for status.",
    }


@router.get("/api/v1/chains/{chain_id}")
@router.get("/api/chains/{chain_id}")
async def get_chain_detail(chain_id: str):
    """Get details of a specific chain."""
    chain = next((c for c in state.chains if c["id"] == chain_id), None)
    if not chain:
        raise HTTPException(404, f"Chain '{chain_id}' not found")
    
    # Include the actual finding objects
    chain_with_findings = chain.copy()
    chain_with_findings["findings"] = [
        f for f in state.findings if f["id"] in chain["finding_ids"]
    ]
    return chain_with_findings
