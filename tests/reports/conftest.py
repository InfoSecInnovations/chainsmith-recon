"""Fixtures for report tests."""

from pathlib import Path

import pytest

from app.db.engine import close_db, init_db
from app.db.repositories import (
    ChainRepository,
    CheckLogRepository,
    ComparisonRepository,
    EngagementRepository,
    FindingOverrideRepository,
    FindingRepository,
    ScanRepository,
    TrendRepository,
)

# --- Shared path constants for viz tests ------------------------------------

STATIC_DIR = Path(__file__).parent.parent.parent / "static"
FINDINGS_HTML = STATIC_DIR / "findings.html"
VIZ_CSS = STATIC_DIR / "css" / "viz.css"
VIZ_JS_DIR = STATIC_DIR / "js" / "viz"


def _all_viz_content():
    """Return combined text of findings.html + all viz JS + viz CSS for assertion checks."""
    parts = [FINDINGS_HTML.read_text()]
    if VIZ_CSS.exists():
        parts.append(VIZ_CSS.read_text())
    if VIZ_JS_DIR.exists():
        for f in sorted(VIZ_JS_DIR.glob("*.js")):
            parts.append(f.read_text())
    return "\n".join(parts)


# --- Database fixture -------------------------------------------------------


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


# --- Repository fixtures ----------------------------------------------------


@pytest.fixture
def scan_repo():
    return ScanRepository()


@pytest.fixture
def finding_repo():
    return FindingRepository()


@pytest.fixture
def chain_repo():
    return ChainRepository()


@pytest.fixture
def check_log_repo():
    return CheckLogRepository()


@pytest.fixture
def comparison_repo():
    return ComparisonRepository()


@pytest.fixture
def override_repo():
    return FindingOverrideRepository()


@pytest.fixture
def engagement_repo():
    return EngagementRepository()


@pytest.fixture
def trend_repo():
    return TrendRepository()


# --- Shared test helpers ----------------------------------------------------


async def _create_populated_scan(
    scan_repo, finding_repo, chain_repo, check_log_repo, scan_id="report-scan", target="example.com"
):
    """Create a scan with findings, chains, and log entries."""
    await scan_repo.create_scan(
        scan_id=scan_id,
        session_id=f"s-{scan_id}",
        target_domain=target,
    )
    await finding_repo.bulk_create(
        scan_id,
        [
            {
                "title": "XSS in Search",
                "severity": "high",
                "check_name": "xss_reflected",
                "host": "example.com",
                "suite": "web",
                "target_url": "http://example.com/search",
                "evidence": "<script>alert(1)</script>",
                "description": "Reflected XSS via q param",
                "references": ["https://owasp.org/xss"],
            },
            {
                "title": "SQL Injection",
                "severity": "critical",
                "check_name": "sqli",
                "host": "example.com",
                "suite": "web",
                "target_url": "http://example.com/api/users",
                "evidence": "Error-based SQLi confirmed",
                "description": "SQL injection in user endpoint",
            },
            {
                "title": "Missing CSP",
                "severity": "medium",
                "check_name": "header_analysis",
                "host": "example.com",
                "suite": "web",
                "description": "No CSP header found",
            },
            {
                "title": "Server Info Leak",
                "severity": "info",
                "check_name": "server_header",
                "host": "example.com",
                "suite": "network",
                "evidence": "Server: Apache/2.4.41",
            },
        ],
    )
    await chain_repo.bulk_create(
        scan_id,
        [
            {
                "title": "XSS to Session Hijack",
                "severity": "critical",
                "source": "rule-based",
                "description": "XSS enables session theft",
                "finding_ids": ["f1", "f2"],
            },
        ],
    )
    await check_log_repo.bulk_create(
        scan_id,
        [
            {"check": "xss_reflected", "suite": "web", "event": "started"},
            {
                "check": "xss_reflected",
                "suite": "web",
                "event": "completed",
                "findings": 1,
                "duration_ms": 500,
            },
            {"check": "sqli", "suite": "web", "event": "started"},
            {
                "check": "sqli",
                "suite": "web",
                "event": "completed",
                "findings": 1,
                "duration_ms": 800,
            },
            {"check": "header_analysis", "suite": "web", "event": "started"},
            {
                "check": "header_analysis",
                "suite": "web",
                "event": "completed",
                "findings": 1,
                "duration_ms": 200,
            },
            {"check": "server_header", "suite": "network", "event": "started"},
            {
                "check": "server_header",
                "suite": "network",
                "event": "completed",
                "findings": 1,
                "duration_ms": 100,
            },
            {"check": "port_scan", "suite": "network", "event": "started"},
            {
                "check": "port_scan",
                "suite": "network",
                "event": "failed",
                "error_message": "Timeout",
            },
        ],
    )
    await scan_repo.complete_scan(
        scan_id,
        status="complete",
        findings_count=4,
        checks_total=5,
        checks_completed=4,
        duration_ms=2000,
    )


PDF_MAGIC = b"%PDF"
