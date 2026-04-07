"""
app/routes/scan_history.py - Scan History Routes (Phase 2)

Endpoints for browsing and managing historical scan data
stored in the database. The active scan is still served
by routes/scan.py from AppState.

Endpoints:
- GET    /api/scans                   List past scans
- GET    /api/scans/{id}              Get scan details
- GET    /api/scans/{id}/observations Get scan's observations
- GET    /api/scans/{id}/chains       Get scan's chains
- GET    /api/scans/{id}/log          Get scan's check log
- DELETE /api/scans/{id}              Delete a scan and its data
- GET    /api/scans/{id}/compare/{id2} Compare two scans
- GET    /api/observations/{fp}/history Observation history across scans
"""

import logging

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from app.api_models import ScanSeverityOverrideDeleteInput, ScanSeverityOverrideInput
from app.db.repositories import (
    ChainRepository,
    CheckLogRepository,
    ComparisonRepository,
    ObservationOverrideRepository,
    ObservationRepository,
    ScanRepository,
    TrendRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_scan_repo = ScanRepository()
_observation_repo = ObservationRepository()
_chain_repo = ChainRepository()
_check_log_repo = CheckLogRepository()
_comparison_repo = ComparisonRepository()
_override_repo = ObservationOverrideRepository()
_trend_repo = TrendRepository()


@router.get("/api/v1/scans")
async def list_scans(
    target: str | None = Query(None, description="Filter by target domain"),
    status: str | None = Query(None, description="Filter by status"),
    engagement_id: str | None = Query(None, description="Filter by engagement"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """List historical scans with optional filters."""
    return await _scan_repo.list_scans(
        target=target,
        status=status,
        engagement_id=engagement_id,
        limit=limit,
        offset=offset,
    )


@router.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get details of a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return scan


@router.get("/api/v1/scans/{scan_id}/observations")
async def get_scan_observations(
    scan_id: str,
    severity: str | None = Query(None, description="Filter by severity"),
    host: str | None = Query(None, description="Filter by host"),
):
    """Get observations from a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    observations = await _observation_repo.get_observations(scan_id, severity=severity, host=host)
    return {"total": len(observations), "observations": observations}


@router.get("/api/v1/scans/{scan_id}/observations/by-host")
async def get_scan_observations_by_host(scan_id: str):
    """Get observations from a historical scan grouped by host."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    hosts = await _observation_repo.get_observations_by_host(scan_id)
    return {"target": scan["target_domain"], "hosts": hosts}


@router.get("/api/v1/scans/{scan_id}/chains")
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
async def get_scan_log(scan_id: str):
    """Get check execution log from a historical scan."""
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    log = await _check_log_repo.get_log(scan_id)
    return {"log": log}


@router.delete("/api/v1/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a historical scan and all its associated data."""
    deleted = await _scan_repo.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return {"message": f"Scan '{scan_id}' deleted", "deleted": True}


@router.get("/api/v1/scans/{scan_a_id}/compare/{scan_b_id}")
async def compare_scans(scan_a_id: str, scan_b_id: str):
    """Compare two scans by observation fingerprints."""
    # Verify both scans exist
    scan_a = await _scan_repo.get_scan(scan_a_id)
    if scan_a is None:
        raise HTTPException(404, f"Scan '{scan_a_id}' not found")
    scan_b = await _scan_repo.get_scan(scan_b_id)
    if scan_b is None:
        raise HTTPException(404, f"Scan '{scan_b_id}' not found")

    return await _comparison_repo.compare_scans(scan_a_id, scan_b_id)


@router.get("/api/v1/targets/{domain}/trend")
async def get_target_trend(
    domain: str,
    since: str | None = None,
    until: str | None = None,
    last_n: int | None = None,
):
    """Get trend data for all completed scans of a target domain.

    Filters (all optional, combinable):
      - since: ISO date string, include scans from this date onward
      - until: ISO date string, include scans up to this date
      - last_n: only return the most recent N scans
    """
    return await _trend_repo.get_target_trend(
        domain,
        since=since,
        until=until,
        last_n=last_n,
    )


@router.get("/api/v1/observations/{fingerprint}/history")
async def get_observation_history(fingerprint: str):
    """Get the status history of an observation across scans, including any manual override."""
    history = await _comparison_repo.get_observation_history(fingerprint)
    override = await _override_repo.get_override(fingerprint)
    return {"fingerprint": fingerprint, "history": history, "override": override}


# ─── Observation Override Endpoints ──────────────────────────────────────────────


class ObservationOverrideInput(BaseModel):
    status: str  # accepted, false_positive
    reason: str | None = None


@router.get("/api/v1/observations/overrides")
async def list_observation_overrides(
    status: str | None = Query(None, description="Filter by status (accepted, false_positive)"),
):
    """List all observation overrides."""
    return await _override_repo.list_overrides(status=status)


@router.put("/api/v1/observations/{fingerprint}/override")
async def set_observation_override(fingerprint: str, body: ObservationOverrideInput):
    """Set a manual override on an observation (accepted risk or false positive)."""
    if body.status not in ("accepted", "false_positive"):
        raise HTTPException(
            400, f"Invalid status '{body.status}'. Must be 'accepted' or 'false_positive'."
        )
    return await _override_repo.set_override(
        fingerprint=fingerprint,
        status=body.status,
        reason=body.reason,
    )


@router.delete("/api/v1/observations/{fingerprint}/override")
async def remove_observation_override(fingerprint: str):
    """Remove an observation override (reopen the observation)."""
    removed = await _override_repo.remove_override(fingerprint)
    if not removed:
        raise HTTPException(404, f"No override found for fingerprint '{fingerprint}'")
    return {"fingerprint": fingerprint, "message": "Override removed", "reopened": True}


# ─── Scan Severity Overrides ─────────────────────────────────────────────────


@router.get("/api/v1/scans/{scan_id}/severity-overrides")
async def list_scan_severity_overrides(scan_id: str):
    """List all severity overrides for a scan."""
    from app.customizations import get_scan_overrides_raw

    return get_scan_overrides_raw(scan_id)


@router.put("/api/v1/scans/{scan_id}/severity-overrides")
async def set_scan_severity_override(scan_id: str, body: ScanSeverityOverrideInput):
    """Add or update a severity override for observations in a scan.

    The scope determines which observations are affected:
    - {check_name, title}: observations matching both
    - {title}: all observations with this title
    - {check_name}: all observations from this check
    """
    scope = body.scope.model_dump(exclude_none=True)
    if not scope:
        raise HTTPException(400, "Scope must include at least check_name or title")

    # Validate scan exists
    scan = await _scan_repo.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    from app.customizations import add_scan_override

    try:
        result = add_scan_override(scan_id, scope, body.severity, body.reason)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return result


@router.delete("/api/v1/scans/{scan_id}/severity-overrides")
async def delete_scan_severity_override(scan_id: str, body: ScanSeverityOverrideDeleteInput):
    """Remove a severity override from a scan by scope."""
    scope = body.scope.model_dump(exclude_none=True)
    if not scope:
        raise HTTPException(400, "Scope must include at least check_name or title")

    from app.customizations import remove_scan_override

    removed = remove_scan_override(scan_id, scope)
    if not removed:
        raise HTTPException(404, "No override found matching the given scope")
    return {"scan_id": scan_id, "scope": scope, "message": "Override removed"}


@router.post("/api/v1/scans/{scan_id}/severity-overrides/preview")
async def preview_scan_severity_override(scan_id: str, body: ScanSeverityOverrideInput):
    """Preview which observations would be affected by an override without persisting.

    Returns a list of observations with their current and proposed severity.
    """
    scope = body.scope.model_dump(exclude_none=True)
    if not scope:
        raise HTTPException(400, "Scope must include at least check_name or title")

    # Get raw observations (without existing scan overrides, to show true current state)
    observations = await _observation_repo.get_observations(scan_id)

    from app.customizations import preview_scan_override

    try:
        affected = preview_scan_override(observations, scope, body.severity)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    return {"affected_count": len(affected), "observations": affected}


# ─── Capabilities ────────────────────────────────────────────────────────────


@router.get("/api/v1/capabilities")
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
    format: str | None = "md"


class DeltaReportInput(BaseModel):
    scan_a_id: str
    scan_b_id: str
    format: str | None = "md"


class ExecutiveReportInput(BaseModel):
    scan_id: str
    format: str | None = "md"
    engagement_id: str | None = None


class ComplianceReportInput(BaseModel):
    scan_id: str
    format: str | None = "md"
    engagement_id: str | None = None


class TrendReportInput(BaseModel):
    format: str | None = "md"
    engagement_id: str | None = None
    target: str | None = None


@router.post("/api/v1/reports/technical")
async def generate_technical_report_endpoint(body: TechnicalReportInput):
    """Generate a technical report for a historical scan."""
    from app.reports import generate_technical_report

    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_technical_report(body.scan_id, body.format)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/api/v1/reports/delta")
async def generate_delta_report_endpoint(body: DeltaReportInput):
    """Generate a delta (comparison) report between two scans."""
    from app.reports import generate_delta_report

    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_delta_report(body.scan_a_id, body.scan_b_id, body.format)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/api/v1/reports/executive")
async def generate_executive_report_endpoint(body: ExecutiveReportInput):
    """Generate an executive summary report for a scan."""
    from app.reports import generate_executive_report

    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_executive_report(body.scan_id, body.format, body.engagement_id)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/api/v1/reports/compliance")
async def generate_compliance_report_endpoint(body: ComplianceReportInput):
    """Generate a compliance report for a scan."""
    from app.reports import generate_compliance_report

    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_compliance_report(body.scan_id, body.format, body.engagement_id)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/api/v1/reports/trend")
async def generate_trend_report_endpoint(body: TrendReportInput):
    """Generate a trend report across multiple scans."""
    from app.reports import generate_trend_report

    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    try:
        result = await generate_trend_report(body.format, body.engagement_id, body.target)
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


# ─── Targeted Export ─────────────────────────────────────────────────────────


class TargetedExportInput(BaseModel):
    fingerprints: list[str]
    format: str | None = "md"
    title: str | None = None


@router.post("/api/v1/reports/targeted")
async def generate_targeted_export_endpoint(body: TargetedExportInput):
    """Generate a report from a curated set of observations identified by fingerprint."""
    from app.reports import generate_targeted_export

    if body.format not in VALID_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(VALID_FORMATS)}")
    if not body.fingerprints:
        raise HTTPException(400, "At least one fingerprint is required")
    try:
        result = await generate_targeted_export(
            body.fingerprints,
            body.format,
            body.title,
        )
        return _pdf_response(result) if body.format == "pdf" else result
    except ValueError as e:
        raise HTTPException(404, str(e)) from e
