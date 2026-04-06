"""
app/routes/engagements.py - Engagement Management Routes (Phase 3)

Endpoints for managing engagements (groups of related scans).

- GET    /api/engagements              List engagements
- POST   /api/engagements              Create engagement
- GET    /api/engagements/{id}         Get engagement details
- PUT    /api/engagements/{id}         Update engagement
- DELETE /api/engagements/{id}         Delete engagement
- GET    /api/engagements/{id}/scans   List scans in engagement
"""

import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.db.repositories import EngagementRepository, ScanRepository, TrendRepository

logger = logging.getLogger(__name__)

router = APIRouter()

_engagement_repo = EngagementRepository()
_scan_repo = ScanRepository()
_trend_repo = TrendRepository()


class EngagementCreateInput(BaseModel):
    name: str
    target_domain: str
    description: str | None = None
    client_name: str | None = None


class EngagementUpdateInput(BaseModel):
    name: str | None = None
    description: str | None = None
    client_name: str | None = None
    status: str | None = None


@router.get("/api/v1/engagements")
async def list_engagements(
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List engagements."""
    return await _engagement_repo.list_engagements(status=status, limit=limit, offset=offset)


@router.post("/api/v1/engagements", status_code=201)
async def create_engagement(body: EngagementCreateInput):
    """Create a new engagement."""
    return await _engagement_repo.create_engagement(
        name=body.name,
        target_domain=body.target_domain,
        description=body.description,
        client_name=body.client_name,
    )


@router.get("/api/v1/engagements/{engagement_id}")
async def get_engagement(engagement_id: str):
    """Get engagement details."""
    eng = await _engagement_repo.get_engagement(engagement_id)
    if eng is None:
        raise HTTPException(404, f"Engagement '{engagement_id}' not found")
    return eng


@router.put("/api/v1/engagements/{engagement_id}")
async def update_engagement(engagement_id: str, body: EngagementUpdateInput):
    """Update an engagement."""
    eng = await _engagement_repo.update_engagement(
        engagement_id,
        name=body.name,
        description=body.description,
        client_name=body.client_name,
        status=body.status,
    )
    if eng is None:
        raise HTTPException(404, f"Engagement '{engagement_id}' not found")
    return eng


@router.delete("/api/v1/engagements/{engagement_id}")
async def delete_engagement(engagement_id: str):
    """Delete an engagement (scans are unlinked, not deleted)."""
    deleted = await _engagement_repo.delete_engagement(engagement_id)
    if not deleted:
        raise HTTPException(404, f"Engagement '{engagement_id}' not found")
    return {"message": f"Engagement '{engagement_id}' deleted", "deleted": True}


@router.get("/api/v1/engagements/{engagement_id}/scans")
async def get_engagement_scans(
    engagement_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List scans belonging to an engagement."""
    eng = await _engagement_repo.get_engagement(engagement_id)
    if eng is None:
        raise HTTPException(404, f"Engagement '{engagement_id}' not found")
    return await _scan_repo.list_scans(engagement_id=engagement_id, limit=limit, offset=offset)


@router.get("/api/v1/engagements/{engagement_id}/trend")
async def get_engagement_trend(
    engagement_id: str,
    since: str | None = None,
    until: str | None = None,
    last_n: int | None = None,
):
    """Get trend data for all completed scans in an engagement.

    Filters (all optional, combinable):
      - since: ISO date string, include scans from this date onward
      - until: ISO date string, include scans up to this date
      - last_n: only return the most recent N scans
    """
    eng = await _engagement_repo.get_engagement(engagement_id)
    if eng is None:
        raise HTTPException(404, f"Engagement '{engagement_id}' not found")
    return await _trend_repo.get_engagement_trend(
        engagement_id,
        since=since,
        until=until,
        last_n=last_n,
    )
