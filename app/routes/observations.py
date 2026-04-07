"""
app/routes/observations.py - Observations Routes

Endpoints for:
- Listing observations
- Observation details
- Observation grouping by host

All reads go through the database. If no scan_id is provided, the
active scan (state.active_scan_id) is used.
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import ObservationRepository, ScanRepository
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_observation_repo = ObservationRepository()
_scan_repo = ScanRepository()


def _resolve_scan_id(scan_id: str | None) -> str | None:
    """Resolve scan_id from parameter or active scan."""
    return scan_id or state.active_scan_id


@router.get("/api/v1/observations")
async def get_observations(
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
    severity: str | None = Query(None, description="Filter by severity"),
    host: str | None = Query(None, description="Filter by host"),
):
    """Get all observations for a scan."""
    sid = _resolve_scan_id(scan_id)
    if not sid:
        return {"total": 0, "observations": []}

    observations = await _observation_repo.get_observations(sid, severity=severity, host=host)
    return {"total": len(observations), "observations": observations}


@router.get("/api/v1/observations/by-host")
async def get_observations_by_host(
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Get observations grouped by host."""
    sid = _resolve_scan_id(scan_id)
    if not sid:
        return {"target": state.target or "unknown", "hosts": []}

    hosts = await _observation_repo.get_observations_by_host(sid)
    scan = await _scan_repo.get_scan(sid)
    target = scan["target_domain"] if scan else state.target or "unknown"
    return {"target": target, "hosts": hosts}


@router.get("/api/v1/observations/{observation_id}")
async def get_observation_detail(
    observation_id: str,
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Get detailed info about a specific observation."""
    sid = _resolve_scan_id(scan_id)
    if not sid:
        raise HTTPException(404, f"Observation '{observation_id}' not found")

    observations = await _observation_repo.get_observations(sid)
    observation = next((f for f in observations if f.get("id") == observation_id), None)
    if not observation:
        raise HTTPException(404, f"Observation '{observation_id}' not found")
    return observation
