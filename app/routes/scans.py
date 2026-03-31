"""
app/routes/scans.py - Scan History Routes (Phase 2)

Endpoints for browsing and managing historical scan data
stored in the database. The active scan is still served
by routes/scan.py from AppState.

Endpoints:
- GET    /api/scans                   List past scans
- GET    /api/scans/{id}              Get scan details
- GET    /api/scans/{id}/findings     Get scan's findings
- GET    /api/scans/{id}/chains       Get scan's chains
- GET    /api/scans/{id}/log          Get scan's check log
- DELETE /api/scans/{id}              Delete a scan and its data
- GET    /api/scans/{id}/compare/{id2} Compare two scans
- GET    /api/findings/{fp}/history    Finding history across scans
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from pydantic import BaseModel

from app.db.repositories import (
    ChainRepository,
    CheckLogRepository,
    ComparisonRepository,
    FindingOverrideRepository,
    FindingRepository,
    ScanRepository,
    TrendRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_scan_repo = ScanRepository()
_finding_repo = FindingRepository()
_chain_repo = ChainRepository()
_check_log_repo = CheckLogRepository()
_comparison_repo = ComparisonRepository()
_override_repo = FindingOverrideRepository()
_trend_repo = TrendRepository()


@router.get("/api/v1/scans")
@router.get("/api/scans")
async def list_scans(
    target: Optional[str] = Query(None, description="Filter by target domain"),
    status: Optional[str] = Query(None, description="Filter by status"),
    engagement_id: Optional[str] = Query(None, description="Filter by engagement"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """List historical scans with optional filters."""
    return await _scan_repo.list_scans(
        target=target, status=status, engagement_id=engagement_id,
        limit=limit, offset=offset,
    )


@router.get("/api/v1/scans/{scan_id}")
@router.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get details of a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return scan


@router.get("/api/v1/scans/{scan_id}/findings")
@router.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    host: Optional[str] = Query(None, description="Filter by host"),
):
    """Get findings from a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    findings = await _finding_repo.get_findings(
        scan_id, severity=severity, host=host
    )
    return {"total": len(findings), "findings": findings}


@router.get("/api/v1/scans/{scan_id}/findings/by-host")
@router.get("/api/scans/{scan_id}/findings/by-host")
async def get_scan_findings_by_host(scan_id: str):
    """Get findings from a historical scan grouped by host."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    hosts = await _finding_repo.get_findings_by_host(scan_id)
    return {"target": scan["target_domain"], "hosts": hosts}


@router.get("/api/v1/scans/{scan_id}/chains")
@router.get("/api/scans/{scan_id}/chains")
async def get_scan_chains(scan_id: str):
    """Get attack chains from a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    chains = await _chain_repo.get_chains(scan_id)
    rule_based = [c for c in chains if c.get("source") == "rule-based"]
    llm_chains = [c for c in chains if c.get("source") in ("llm", "both")]
    return {
        "chains_count": len(chains),
        "rule_based_count": len(rule_based),
        "llm_count": len(llm_chains),
        "chains": chains,
    }


@router.get("/api/v1/scans/{scan_id}/log")
@router.get("/api/scans/{scan_id}/log")
async def get_scan_log(scan_id: str):
    """Get check execution log from a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    log = await _check_log_repo.get_log(scan_id)
    return {"log": log}


@router.delete("/api/v1/scans/{scan_id}")
@router.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a historical scan and all its associated data."""
    deleted = await _scan_repo.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return {"message": f"Scan '{scan_id}' deleted", "deleted": True}


@router.get("/api/v1/scans/{scan_a_id}/compare/{scan_b_id}")
@router.get("/api/scans/{scan_a_id}/compare/{scan_b_id}")
async def compare_scans(scan_a_id: str, scan_b_id: str):
    """Compare two scans by finding fingerprints."""
    # Verify both scans exist
    scan_a = await _scan_repo.get_scan(scan_a_id)
    if scan_a is None:
        raise HTTPException(404, f"Scan '{scan_a_id}' not found")
    scan_b = await _scan_repo.get_scan(scan_b_id)
    if scan_b is None:
        raise HTTPException(404, f"Scan '{scan_b_id}' not found")

    return await _comparison_repo.compare_scans(scan_a_id, scan_b_id)


@router.get("/api/v1/targets/{domain}/trend")
@router.get("/api/targets/{domain}/trend")
async def get_target_trend(
    domain: str,
    since: Optional[str] = None,
    until: Optional[str] = None,
    last_n: Optional[int] = None,
):
    """Get trend data for all completed scans of a target domain.

    Filters (all optional, combinable):
      - since: ISO date string, include scans from this date onward
      - until: ISO date string, include scans up to this date
      - last_n: only return the most recent N scans
    """
    return await _trend_repo.get_target_trend(
        domain, since=since, until=until, last_n=last_n,
    )


@router.get("/api/v1/findings/{fingerprint}/history")
@router.get("/api/findings/{fingerprint}/history")
async def get_finding_history(fingerprint: str):
    """Get the status history of a finding across scans, including any manual override."""
    history = await _comparison_repo.get_finding_history(fingerprint)
    override = await _override_repo.get_override(fingerprint)
    return {"fingerprint": fingerprint, "history": history, "override": override}


# ─── Finding Override Endpoints ──────────────────────────────────────────────


class FindingOverrideInput(BaseModel):
    status: str  # accepted, false_positive
    reason: Optional[str] = None


@router.get("/api/v1/findings/overrides")
@router.get("/api/findings/overrides")
async def list_finding_overrides(
    status: Optional[str] = Query(None, description="Filter by status (accepted, false_positive)"),
):
    """List all finding overrides."""
    return await _override_repo.list_overrides(status=status)


@router.put("/api/v1/findings/{fingerprint}/override")
@router.put("/api/findings/{fingerprint}/override")
async def set_finding_override(fingerprint: str, body: FindingOverrideInput):
    """Set a manual override on a finding (accepted risk or false positive)."""
    if body.status not in ("accepted", "false_positive"):
        raise HTTPException(400, f"Invalid status '{body.status}'. Must be 'accepted' or 'false_positive'.")
    return await _override_repo.set_override(
        fingerprint=fingerprint, status=body.status, reason=body.reason,
    )


@router.delete("/api/v1/findings/{fingerprint}/override")
@router.delete("/api/findings/{fingerprint}/override")
async def remove_finding_override(fingerprint: str):
    """Remove a finding override (reopen the finding)."""
    removed = await _override_repo.remove_override(fingerprint)
    if not removed:
        raise HTTPException(404, f"No override found for fingerprint '{fingerprint}'")
    return {"fingerprint": fingerprint, "message": "Override removed", "reopened": True}


# ─── Capabilities ────────────────────────────────────────────────────────────


@router.get("/api/v1/capabilities")
@router.get("/api/capabilities")
async def get_capabilities():
    """Return server capabilities (e.g. which optional features are available)."""
    pdf_available = False
    try:
        from xhtml2pdf import pisa  # noqa: F401
        pdf_available = True
    except ImportError:
        pass
    return {
        "pdf": pdf_available,
        "sarif": True,
        "formats": ["md", "json", "html", "sarif"] + (["pdf"] if pdf_available else []),
    }


# ─── Report Generation Endpoints ─────────────────────────────────────────────


VALID_FORMATS = ("md", "json", "html", "pdf", "sarif")


def _pdf_response(result: dict) -> Response:
    """Return a binary PDF response with download headers."""
    return Response(
        content=result["content"],
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{result["filename"]}"'},
    )


def _binary_response(result: dict, fmt: str) -> Response | None:
    """Return special response for binary/download formats, or None for JSON-able."""
    if fmt == "pdf":
        return _pdf_response(result)
    return None


class TechnicalReportInput(BaseModel):
    scan_id: str
    format: Optional[str] = "md"


class DeltaReportInput(BaseModel):
    scan_a_id: str
    scan_b_id: str
    format: Optional[str] = "md"


class ExecutiveReportInput(BaseModel):
    scan_id: str
    format: Optional[str] = "md"
    engagement_id: Optional[str] = None


class ComplianceReportInput(BaseModel):
    scan_id: str
    format: Optional[str] = "md"
    engagement_id: Optional[str] = None


class TrendReportInput(BaseModel):
    format: Optional[str] = "md"
    engagement_id: Optional[str] = None
    target: Optional[str] = None


@router.post("/api/v1/reports/technical")
@router.post("/api/reports/technical")
async def generate_technical_report_endpoint(body: TechnicalReportInput):
    """Generate a technical report for a historical scan."""
    from app.reports import generate_technical_report
    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_technical_report(body.scan_id, body.format)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/api/v1/reports/delta")
@router.post("/api/reports/delta")
async def generate_delta_report_endpoint(body: DeltaReportInput):
    """Generate a delta (comparison) report between two scans."""
    from app.reports import generate_delta_report
    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_delta_report(body.scan_a_id, body.scan_b_id, body.format)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/api/v1/reports/executive")
@router.post("/api/reports/executive")
async def generate_executive_report_endpoint(body: ExecutiveReportInput):
    """Generate an executive summary report for a scan."""
    from app.reports import generate_executive_report
    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_executive_report(body.scan_id, body.format, body.engagement_id)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/api/v1/reports/compliance")
@router.post("/api/reports/compliance")
async def generate_compliance_report_endpoint(body: ComplianceReportInput):
    """Generate a compliance report for a scan."""
    from app.reports import generate_compliance_report
    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_compliance_report(body.scan_id, body.format, body.engagement_id)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/api/v1/reports/trend")
@router.post("/api/reports/trend")
async def generate_trend_report_endpoint(body: TrendReportInput):
    """Generate a trend report across multiple scans."""
    from app.reports import generate_trend_report
    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_trend_report(body.format, body.engagement_id, body.target)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e))


# ─── Targeted Export ─────────────────────────────────────────────────────────


class TargetedExportInput(BaseModel):
    fingerprints: list[str]
    format: Optional[str] = "md"
    title: Optional[str] = None


@router.post("/api/v1/reports/targeted")
@router.post("/api/reports/targeted")
async def generate_targeted_export_endpoint(body: TargetedExportInput):
    """Generate a report from a curated set of findings identified by fingerprint."""
    from app.reports import generate_targeted_export
    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    if not body.fingerprints:
        raise HTTPException(400, "At least one fingerprint is required")
    try:
        result = await generate_targeted_export(
            body.fingerprints, body.format, body.title,
        )
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e))
