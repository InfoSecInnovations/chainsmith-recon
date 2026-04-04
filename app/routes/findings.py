"""
app/routes/findings.py - Findings Routes

Endpoints for:
- Listing findings
- Finding details
- Finding grouping by host

When an optional `scan_id` query parameter is provided, findings are
read from the database (historical). Otherwise, the active scan's
in-memory data is returned (current behavior).
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import FindingRepository
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_finding_repo = FindingRepository()


@router.get("/api/v1/findings")
@router.get("/api/findings")
async def get_findings(
    scan_id: str | None = Query(None, description="Historical scan ID"),
    severity: str | None = Query(None, description="Filter by severity"),
    host: str | None = Query(None, description="Filter by host"),
):
    """Get all findings. Pass scan_id to read from a historical scan."""
    if scan_id:
        findings = await _finding_repo.get_findings(scan_id, severity=severity, host=host)
        return {"total": len(findings), "findings": findings}

    return {"total": len(state.findings), "findings": state.findings}


@router.get("/api/v1/findings/by-host")
@router.get("/api/findings/by-host")
async def get_findings_by_host(
    scan_id: str | None = Query(None, description="Historical scan ID"),
):
    """Get findings grouped by host. Pass scan_id for historical data."""
    if scan_id:
        hosts = await _finding_repo.get_findings_by_host(scan_id)
        # Determine target from scan record
        from app.db.repositories import ScanRepository

        scan = await ScanRepository().get_scan(scan_id)
        target = scan["target_domain"] if scan else "unknown"
        return {"target": target, "hosts": hosts}

    hosts = {}
    for f in state.findings:
        # Try to extract host from various fields
        host = None

        # First try target_url
        target_url = f.get("target_url")
        if target_url and target_url != "None":
            if "://" in target_url:
                host = target_url.split("://")[1].split("/")[0]
            else:
                host = target_url.split("/")[0]

        # Fall back to extracting from finding ID (format: checkname-hostname-...)
        if not host:
            finding_id = f.get("id", "")
            parts = finding_id.split("-")
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
        "hosts": [{"name": host, "findings": findings} for host, findings in hosts.items()],
    }


@router.get("/api/v1/findings/{finding_id}")
@router.get("/api/findings/{finding_id}")
async def get_finding_detail(finding_id: str):
    """Get detailed info about a specific finding."""
    finding = next((f for f in state.findings if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(404, f"Finding '{finding_id}' not found")
    return finding
