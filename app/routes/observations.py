"""
app/routes/observations.py - Observations Routes

Endpoints for:
- Listing observations
- Observation details
- Observation grouping by host

When an optional `scan_id` query parameter is provided, observations are
read from the database (historical). Otherwise, the active scan's
in-memory data is returned (current behavior).
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import ObservationRepository
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_observation_repo = ObservationRepository()


@router.get("/api/v1/observations")
async def get_observations(
    scan_id: str | None = Query(None, description="Historical scan ID"),
    severity: str | None = Query(None, description="Filter by severity"),
    host: str | None = Query(None, description="Filter by host"),
):
    """Get all observations. Pass scan_id to read from a historical scan."""
    if scan_id:
        observations = await _observation_repo.get_observations(scan_id, severity=severity, host=host)
        return {"total": len(observations), "observations": observations}

    return {"total": len(state.observations), "observations": state.observations}


@router.get("/api/v1/observations/by-host")
async def get_observations_by_host(
    scan_id: str | None = Query(None, description="Historical scan ID"),
):
    """Get observations grouped by host. Pass scan_id for historical data."""
    if scan_id:
        hosts = await _observation_repo.get_observations_by_host(scan_id)
        # Determine target from scan record
        from app.db.repositories import ScanRepository

        scan = await ScanRepository().get_scan(scan_id)
        target = scan["target_domain"] if scan else "unknown"
        return {"target": target, "hosts": hosts}

    hosts = {}
    for f in state.observations:
        # Try to extract host from various fields
        host = None

        # First try target_url
        target_url = f.get("target_url")
        if target_url and target_url != "None":
            if "://" in target_url:
                host = target_url.split("://")[1].split("/")[0]
            else:
                host = target_url.split("/")[0]

        # Fall back to extracting from observation ID (format: checkname-hostname-...)
        if not host:
            observation_id = f.get("id", "")
            parts = observation_id.split("-")
            if len(parts) >= 2:
                # Skip the check name prefix, grab potential hostname
                potential_host = parts[1]
                # Check if it looks like a hostname (has a dot or is an IP)
                if "." in potential_host:
                    host = potential_host

        # Last resort
        if not host:
            host = state.target or "unknown"

        if host not in hosts:
            hosts[host] = []
        hosts[host].append(f)

    return {
        "target": state.target,
        "hosts": [{"name": host, "observations": observations} for host, observations in hosts.items()],
    }


@router.get("/api/v1/observations/{observation_id}")
async def get_observation_detail(observation_id: str):
    """Get detailed info about a specific observation."""
    observation = next((f for f in state.observations if f["id"] == observation_id), None)
    if not observation:
        raise HTTPException(404, f"Observation '{observation_id}' not found")
    return observation
