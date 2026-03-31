"""
app/routes/compliance.py - Compliance and Proof of Scope Routes

Endpoints for:
- Traffic logging
- Scope violations
- Compliance reports
- Export
"""

import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException

from app.state import state
from app.proof_of_scope import (
    traffic_logger, violation_logger, compliance_reporter
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Traffic Logging ──────────────────────────────────────────

@router.get("/api/v1/compliance/traffic")
@router.get("/api/compliance/traffic")
async def get_traffic_log(limit: int = 100):
    """Get traffic log entries."""
    entries = traffic_logger.get_entries(limit=limit)
    return {
        "entries": entries,
        "total": len(entries)
    }


# ─── Violations ───────────────────────────────────────────────

@router.get("/api/v1/compliance/violations")
@router.get("/api/compliance/violations")
async def get_violations():
    """Get scope violation log."""
    violations = violation_logger.get_violations()
    return {
        "violations": [v.model_dump() for v in violations],
        "total": len(violations)
    }


# ─── Compliance Reports ───────────────────────────────────────

@router.post("/api/v1/compliance/report")
@router.post("/api/compliance/report")
async def generate_compliance_report():
    """Generate a compliance report."""
    if not state.target:
        raise HTTPException(400, "No scope defined")
    
    report = compliance_reporter.generate_report(
        session_id=state.session_id,
        target=state.target,
        exclusions=state.exclude,
        proof_settings=state.proof_settings
    )
    
    return report.model_dump()


@router.get("/api/v1/compliance/report")
@router.get("/api/compliance/report")
async def get_compliance_report():
    """Get the latest compliance report."""
    report = compliance_reporter.get_latest_report()
    if not report:
        raise HTTPException(404, "No compliance report generated yet")
    
    return report.model_dump()


# ─── Export ───────────────────────────────────────────────────

def _count_by_severity(findings: list) -> dict:
    """Count findings by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


@router.post("/api/v1/export")
@router.post("/api/export")
async def export_report():
    """Export full scan report (findings + chains + compliance)."""
    if not state.target:
        raise HTTPException(400, "No scope defined")
    
    window = state.proof_settings.engagement_window
    
    report = {
        "metadata": {
            "session_id": state.session_id,
            "target": state.target,
            "exclude": state.exclude,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "status": state.status
        },
        "scope": {
            "target": state.target,
            "exclusions": state.exclude,
            "techniques": state.techniques
        },
        "findings": {
            "total": len(state.findings),
            "by_severity": _count_by_severity(state.findings),
            "items": state.findings
        },
        "chains": {
            "total": len(state.chains),
            "items": state.chains
        },
        "compliance": {
            "engagement_window": {
                "start": window.start,
                "end": window.end,
                "is_configured": window.is_configured()
            },
            "traffic_logged": state.proof_settings.traffic_logging,
            "violations_count": len(violation_logger.get_violations())
        }
    }
    
    return report
