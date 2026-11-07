"""
app/routes/compliance.py - Compliance and Proof of Scope Routes

Endpoints for:
- Traffic logging
- Scope violations
- Compliance reports
- Export

Compliance/scope config stays in state (not result data).
Export reads observations and chains from the database.
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from app.db.repositories import ChainRepository, ObservationRepository, ScanRepository
from app.lib.timeutils import iso_utc
from app.proof_of_scope import compliance_reporter, traffic_logger, violation_logger
from app.scan_context import resolve_session
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()

_observation_repo = ObservationRepository()
_chain_repo = ChainRepository()
_scan_repo = ScanRepository()


async def _resolve_scan_id(scan_id: str | None) -> str | None:
    """Resolve scan_id: explicit param > current session > most recent DB scan."""
    if scan_id:
        return scan_id
    session = resolve_session()
    if session is not None:
        return session.id
    return await _scan_repo.get_most_recent_scan_id()


# ─── Traffic Logging ──────────────────────────────────────────


@router.get("/api/v1/compliance/traffic")
async def get_traffic_log(limit: int = 100, scan_id: str | None = Query(None)):
    """Get traffic log entries, optionally only one scan's.

    Phase 57.2 put a `scan_id` on every record. Without the filter the log is
    workspace-wide, which is the right default for an operator reviewing what
    the tool has done, and the wrong one for "what did this scan send".
    """
    entries = traffic_logger.get_entries(limit=limit, scan_id=scan_id)
    return {"entries": entries, "total": len(entries), "scan_id": scan_id}


# ─── Violations ───────────────────────────────────────────────


@router.get("/api/v1/compliance/violations")
async def get_violations(scan_id: str | None = Query(None)):
    """Get the scope violation log, optionally only one scan's."""
    violations = violation_logger.get_violations(scan_id=scan_id)
    return {
        "violations": [v.model_dump() for v in violations],
        "total": len(violations),
        "scan_id": scan_id,
    }


# ─── Compliance Reports ───────────────────────────────────────


@router.post("/api/v1/compliance/report")
async def generate_compliance_report(scan_id: str | None = Query(None)):
    """Generate a compliance report.

    Reports on a specific scan when `scan_id` is given (or when a scan can be
    resolved as current). The scope recorded is that scan's own snapshot —
    reading live operator state here made the report describe whatever scope
    happened to be set at generation time, which is wrong for any scan that
    has already finished and for every concurrent scan.

    With no resolvable scan, falls back to the operator's current scope prep
    and leaves `scan_id` null so the report says which it is.
    """
    session = resolve_session(scan_id)

    if session is not None:
        report = compliance_reporter.generate_report(
            session_id=session.operator_session_id or state.session_id,
            target=session.target,
            exclusions=session.exclude,
            proof_settings=session.proof_settings or state.proof_settings,
            scan_id=session.id,
        )
        return report.model_dump()

    if scan_id:
        raise HTTPException(404, f"Unknown scan '{scan_id}'")
    if not state.target:
        raise HTTPException(400, "No scope defined")

    report = compliance_reporter.generate_report(
        session_id=state.session_id,
        target=state.target,
        exclusions=state.exclude,
        proof_settings=state.proof_settings,
    )

    return report.model_dump()


@router.get("/api/v1/compliance/report")
async def get_compliance_report():
    """Get the latest compliance report."""
    report = compliance_reporter.get_latest_report()
    if not report:
        raise HTTPException(404, "No compliance report generated yet")

    return report.model_dump()


# ─── Export ───────────────────────────────────────────────────


def _count_by_severity(observations: list) -> dict:
    """Count observations by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in observations:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


@router.post("/api/v1/export")
async def export_report(
    scan_id: str | None = Query(None, description="Scan ID (defaults to active scan)"),
):
    """Export full scan report (observations + chains + compliance)."""
    if not state.target:
        raise HTTPException(400, "No scope defined")

    sid = await _resolve_scan_id(scan_id)

    # Get observations and chains from DB
    observations = await _observation_repo.get_observations(sid) if sid else []
    chains = await _chain_repo.get_chains(sid) if sid else []

    window = state.proof_settings.scan_window

    report = {
        "metadata": {
            "session_id": state.session_id,
            "target": state.target,
            "exclude": state.exclude,
            "generated_at": iso_utc(),
            "status": (resolve_session(sid).status if resolve_session(sid) else "complete"),
        },
        "scope": {
            "target": state.target,
            "exclusions": state.exclude,
            "techniques": state.techniques,
        },
        "observations": {
            "total": len(observations),
            "by_severity": _count_by_severity(observations),
            "items": observations,
        },
        "chains": {"total": len(chains), "items": chains},
        "compliance": {
            "scan_window": {
                "start": window.start,
                "end": window.end,
                "is_configured": window.is_configured(),
            },
            "traffic_logged": state.proof_settings.traffic_logging,
            "violations_count": len(violation_logger.get_violations()),
        },
    }

    return report
