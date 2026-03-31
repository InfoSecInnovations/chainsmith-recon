"""
Tests for report generation (Phases 4d + 4e).

Covers technical, delta, executive, compliance, and trend reports
in markdown, JSON, and HTML formats.
"""

import json

import pytest

from app.db.engine import init_db, close_db, get_session
from app.db.models import Finding
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
from app.reports import (
    generate_technical_report,
    generate_delta_report,
    generate_executive_report,
    generate_compliance_report,
    generate_trend_report,
)


# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


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


async def _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo,
                                  scan_id="report-scan", target="example.com"):
    """Create a scan with findings, chains, and log entries."""
    await scan_repo.create_scan(
        scan_id=scan_id, session_id=f"s-{scan_id}", target_domain=target,
    )
    await finding_repo.bulk_create(scan_id, [
        {"title": "XSS in Search", "severity": "high", "check_name": "xss_reflected",
         "host": "example.com", "suite": "web", "target_url": "http://example.com/search",
         "evidence": "<script>alert(1)</script>", "description": "Reflected XSS via q param",
         "references": ["https://owasp.org/xss"]},
        {"title": "SQL Injection", "severity": "critical", "check_name": "sqli",
         "host": "example.com", "suite": "web", "target_url": "http://example.com/api/users",
         "evidence": "Error-based SQLi confirmed", "description": "SQL injection in user endpoint"},
        {"title": "Missing CSP", "severity": "medium", "check_name": "header_analysis",
         "host": "example.com", "suite": "web", "description": "No CSP header found"},
        {"title": "Server Info Leak", "severity": "info", "check_name": "server_header",
         "host": "example.com", "suite": "network", "evidence": "Server: Apache/2.4.41"},
    ])
    await chain_repo.bulk_create(scan_id, [
        {"title": "XSS to Session Hijack", "severity": "critical",
         "source": "rule-based", "description": "XSS enables session theft",
         "finding_ids": ["f1", "f2"]},
    ])
    await check_log_repo.bulk_create(scan_id, [
        {"check": "xss_reflected", "suite": "web", "event": "started"},
        {"check": "xss_reflected", "suite": "web", "event": "completed", "findings": 1, "duration_ms": 500},
        {"check": "sqli", "suite": "web", "event": "started"},
        {"check": "sqli", "suite": "web", "event": "completed", "findings": 1, "duration_ms": 800},
        {"check": "header_analysis", "suite": "web", "event": "started"},
        {"check": "header_analysis", "suite": "web", "event": "completed", "findings": 1, "duration_ms": 200},
        {"check": "server_header", "suite": "network", "event": "started"},
        {"check": "server_header", "suite": "network", "event": "completed", "findings": 1, "duration_ms": 100},
        {"check": "port_scan", "suite": "network", "event": "started"},
        {"check": "port_scan", "suite": "network", "event": "failed", "error_message": "Timeout"},
    ])
    await scan_repo.complete_scan(scan_id, status="complete", findings_count=4,
                                   checks_total=5, checks_completed=4,
                                   duration_ms=2000)


# --- Technical Report Tests ---------------------------------------------------


class TestTechnicalReportMarkdown:

    @pytest.mark.asyncio
    async def test_basic_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")

        assert result["format"] == "md"
        assert result["filename"].startswith("technical-example.com")
        assert result["filename"].endswith(".md")

        content = result["content"]
        assert "# Technical Security Report" in content
        assert "**Target:** example.com" in content
        assert "**Scan ID:** report-scan" in content

    @pytest.mark.asyncio
    async def test_severity_summary(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "| Critical | 1 |" in content
        assert "| High | 1 |" in content
        assert "| Medium | 1 |" in content
        assert "| Info | 1 |" in content

    @pytest.mark.asyncio
    async def test_findings_listed(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "XSS in Search" in content
        assert "SQL Injection" in content
        assert "Missing CSP" in content
        assert "Server Info Leak" in content
        assert "xss_reflected" in content
        assert "<script>alert(1)</script>" in content

    @pytest.mark.asyncio
    async def test_chains_included(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "Attack Chains" in content
        assert "XSS to Session Hijack" in content
        assert "rule-based" in content

    @pytest.mark.asyncio
    async def test_check_coverage(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "Check Coverage" in content
        assert "Completed: 4/5" in content
        assert "Failed: 1" in content

    @pytest.mark.asyncio
    async def test_risk_score(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        # 1 critical(10) + 1 high(5) + 1 medium(2) + 1 info(0) = 17
        assert "**Risk Score:** 17" in content


class TestTechnicalReportJSON:

    @pytest.mark.asyncio
    async def test_json_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "json")

        assert result["format"] == "json"
        assert result["filename"].endswith(".json")

        report = json.loads(result["content"])
        assert report["report_type"] == "technical"
        assert report["scan"]["id"] == "report-scan"
        assert report["summary"]["total_findings"] == 4
        assert report["summary"]["risk_score"] == 17
        assert len(report["findings"]) == 4
        assert len(report["chains"]) == 1
        assert report["check_coverage"]["completed"] == 4
        assert report["check_coverage"]["failed"] == 1


class TestTechnicalReportOverrides:

    @pytest.mark.asyncio
    async def test_overridden_findings_annotated(
        self, db, scan_repo, finding_repo, chain_repo, check_log_repo, override_repo,
    ):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)

        # Get a fingerprint and override it
        from sqlalchemy import select
        async with get_session() as session:
            result = await session.execute(
                select(Finding.fingerprint).where(Finding.title == "Missing CSP")
            )
            fp = result.scalar_one()

        await override_repo.set_override(fp, "accepted", reason="Known risk")

        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "*[ACCEPTED]*" in content


class TestTechnicalReportErrors:

    @pytest.mark.asyncio
    async def test_scan_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_technical_report("nonexistent", "md")

    @pytest.mark.asyncio
    async def test_empty_scan(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        """Report generates even with no findings."""
        await scan_repo.create_scan(
            scan_id="empty-scan", session_id="s1", target_domain="empty.com",
        )
        await scan_repo.complete_scan("empty-scan", status="complete", findings_count=0)

        result = await generate_technical_report("empty-scan", "md")
        assert "# Technical Security Report" in result["content"]
        assert "**Findings:** 0" in result["content"]


# --- Delta Report Tests -------------------------------------------------------


class TestDeltaReportMarkdown:

    @pytest.fixture
    async def two_scans(self, db, scan_repo, finding_repo, comparison_repo):
        """Two scans with known overlap for comparison."""
        await scan_repo.create_scan(
            scan_id="delta-a", session_id="s1", target_domain="example.com",
        )
        await finding_repo.bulk_create("delta-a", [
            {"title": "XSS", "severity": "high", "check_name": "xss", "host": "example.com"},
            {"title": "SQLi", "severity": "critical", "check_name": "sqli", "host": "example.com"},
            {"title": "Open Port", "severity": "info", "check_name": "port_scan", "host": "example.com"},
        ])
        await scan_repo.complete_scan("delta-a", status="complete", findings_count=3)

        await scan_repo.create_scan(
            scan_id="delta-b", session_id="s2", target_domain="example.com",
        )
        await finding_repo.bulk_create("delta-b", [
            {"title": "XSS", "severity": "high", "check_name": "xss", "host": "example.com"},
            {"title": "CSRF", "severity": "medium", "check_name": "csrf", "host": "example.com"},
        ])
        await scan_repo.complete_scan("delta-b", status="complete", findings_count=2)

    @pytest.mark.asyncio
    async def test_basic_structure(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")

        assert result["format"] == "md"
        assert "delta-" in result["filename"]

        content = result["content"]
        assert "# Delta Report" in content
        assert "delta-a" in content
        assert "delta-b" in content
        assert "**Target:** example.com" in content

    @pytest.mark.asyncio
    async def test_summary_counts(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        # 1 new (CSRF), 2 resolved (SQLi, Open Port), 1 recurring (XSS)
        assert "| New |" in content
        assert "| Resolved |" in content
        assert "| Recurring |" in content

    @pytest.mark.asyncio
    async def test_new_findings_listed(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        assert "New Findings" in content
        assert "CSRF" in content

    @pytest.mark.asyncio
    async def test_resolved_findings_listed(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        assert "Resolved Findings" in content
        assert "SQLi" in content

    @pytest.mark.asyncio
    async def test_severity_comparison(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        assert "Severity Comparison" in content
        assert "Scan A" in content
        assert "Scan B" in content

    @pytest.mark.asyncio
    async def test_risk_score_change(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        # Scan A: 1 critical(10) + 1 high(5) + 1 info(0) = 15
        # Scan B: 1 high(5) + 1 medium(2) = 7
        assert "15 -> 7" in content
        assert "decreased" in content


class TestDeltaReportJSON:

    @pytest.fixture
    async def two_scans(self, db, scan_repo, finding_repo):
        await scan_repo.create_scan(
            scan_id="dj-a", session_id="s1", target_domain="json.com",
        )
        await finding_repo.bulk_create("dj-a", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "json.com"},
        ])
        await scan_repo.complete_scan("dj-a", status="complete", findings_count=1)

        await scan_repo.create_scan(
            scan_id="dj-b", session_id="s2", target_domain="json.com",
        )
        await finding_repo.bulk_create("dj-b", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "json.com"},
            {"title": "F2", "severity": "low", "check_name": "c2", "host": "json.com"},
        ])
        await scan_repo.complete_scan("dj-b", status="complete", findings_count=2)

    @pytest.mark.asyncio
    async def test_json_structure(self, two_scans):
        result = await generate_delta_report("dj-a", "dj-b", "json")

        report = json.loads(result["content"])
        assert report["report_type"] == "delta"
        assert report["scan_a"]["id"] == "dj-a"
        assert report["scan_b"]["id"] == "dj-b"
        assert "summary" in report
        assert "new_findings" in report
        assert "resolved_findings" in report


class TestDeltaReportErrors:

    @pytest.mark.asyncio
    async def test_scan_a_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_delta_report("nonexistent", "also-bad", "md")

    @pytest.mark.asyncio
    async def test_scan_b_not_found(self, db, scan_repo):
        await scan_repo.create_scan(
            scan_id="exists", session_id="s1", target_domain="x.com",
        )
        with pytest.raises(ValueError, match="not found"):
            await generate_delta_report("exists", "nonexistent", "md")


# --- HTML Format Tests (applies to technical + delta) -------------------------


class TestTechnicalReportHTML:

    @pytest.mark.asyncio
    async def test_html_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")

        assert result["format"] == "html"
        assert result["filename"].endswith(".html")

        content = result["content"]
        assert "<!DOCTYPE html>" in content
        assert "Technical Security Report" in content
        assert "example.com" in content
        assert "XSS in Search" in content
        assert "SQL Injection" in content
        assert "Chainsmith Recon" in content  # footer

    @pytest.mark.asyncio
    async def test_html_severity_badges(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")
        content = result["content"]

        assert "badge-critical" in content
        assert "badge-high" in content
        assert "badge-medium" in content

    @pytest.mark.asyncio
    async def test_html_chains(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")
        assert "Attack Chains" in result["content"]
        assert "XSS to Session Hijack" in result["content"]

    @pytest.mark.asyncio
    async def test_html_coverage(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")
        assert "Check Coverage" in result["content"]
        assert "Completed: 4/5" in result["content"]


class TestDeltaReportHTML:

    @pytest.fixture
    async def two_scans(self, db, scan_repo, finding_repo):
        await scan_repo.create_scan(scan_id="dh-a", session_id="s1", target_domain="html.com")
        await finding_repo.bulk_create("dh-a", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "html.com"},
        ])
        await scan_repo.complete_scan("dh-a", status="complete", findings_count=1)

        await scan_repo.create_scan(scan_id="dh-b", session_id="s2", target_domain="html.com")
        await finding_repo.bulk_create("dh-b", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "html.com"},
            {"title": "F2", "severity": "medium", "check_name": "c2", "host": "html.com"},
        ])
        await scan_repo.complete_scan("dh-b", status="complete", findings_count=2)

    @pytest.mark.asyncio
    async def test_html_structure(self, two_scans):
        result = await generate_delta_report("dh-a", "dh-b", "html")
        assert result["format"] == "html"
        assert result["filename"].endswith(".html")
        content = result["content"]
        assert "<!DOCTYPE html>" in content
        assert "Delta Report" in content
        assert "dh-a" in content
        assert "dh-b" in content

    @pytest.mark.asyncio
    async def test_html_new_findings(self, two_scans):
        result = await generate_delta_report("dh-a", "dh-b", "html")
        assert "New Findings" in result["content"]
        assert "F2" in result["content"]


# --- Executive Report Tests ---------------------------------------------------


@pytest.fixture
def engagement_repo():
    return EngagementRepository()


class TestExecutiveReportMarkdown:

    @pytest.mark.asyncio
    async def test_basic_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")

        assert result["format"] == "md"
        assert result["filename"].startswith("executive-example.com")
        assert result["filename"].endswith(".md")

        content = result["content"]
        assert "# Executive Summary" in content
        assert "**Target:** example.com" in content
        assert "Risk Overview" in content
        assert "Top Findings" in content

    @pytest.mark.asyncio
    async def test_risk_score(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")
        # 1 critical(10) + 1 high(5) + 1 medium(2) + 1 info(0) = 17
        assert "**Risk Score:** 17" in result["content"]

    @pytest.mark.asyncio
    async def test_top_findings(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")
        content = result["content"]
        assert "SQL Injection" in content
        assert "XSS in Search" in content

    @pytest.mark.asyncio
    async def test_severity_table(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")
        content = result["content"]
        assert "| Critical | 1 |" in content
        assert "| High | 1 |" in content

    @pytest.mark.asyncio
    async def test_with_previous_scan(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        """When a previous scan exists, show risk trend."""
        # First scan (previous)
        await _create_populated_scan(
            scan_repo, finding_repo, chain_repo, check_log_repo,
            scan_id="exec-prev", target="trend.com",
        )
        # Second scan (current) - fewer findings
        await scan_repo.create_scan(
            scan_id="exec-curr", session_id="s2", target_domain="trend.com",
        )
        await finding_repo.bulk_create("exec-curr", [
            {"title": "Low Finding", "severity": "low", "check_name": "c1", "host": "trend.com"},
        ])
        await scan_repo.complete_scan("exec-curr", status="complete", findings_count=1)

        result = await generate_executive_report("exec-curr", "md")
        content = result["content"]
        assert "previously" in content
        assert "improved" in content


class TestExecutiveReportJSON:

    @pytest.mark.asyncio
    async def test_json_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "json")

        assert result["format"] == "json"
        assert result["filename"].endswith(".json")

        report = json.loads(result["content"])
        assert report["report_type"] == "executive"
        assert report["summary"]["risk_score"] == 17
        assert report["summary"]["active_findings"] == 4
        assert len(report["top_findings"]) <= 5


class TestExecutiveReportHTML:

    @pytest.mark.asyncio
    async def test_html_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "html")

        assert result["format"] == "html"
        assert result["filename"].endswith(".html")

        content = result["content"]
        assert "<!DOCTYPE html>" in content
        assert "Executive Summary" in content
        assert "stat-grid" in content
        assert "Top Findings" in content

    @pytest.mark.asyncio
    async def test_html_badges(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "html")
        assert "badge-critical" in result["content"]


class TestExecutiveReportErrors:

    @pytest.mark.asyncio
    async def test_scan_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_executive_report("nonexistent", "md")


# --- Compliance Report Tests --------------------------------------------------


class TestComplianceReportMarkdown:

    @pytest.mark.asyncio
    async def test_basic_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")

        assert result["format"] == "md"
        assert result["filename"].startswith("compliance-example.com")

        content = result["content"]
        assert "# Compliance Report" in content
        assert "**Target:** example.com" in content
        assert "Scope and Coverage" in content
        assert "Finding Summary" in content

    @pytest.mark.asyncio
    async def test_check_coverage(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "**Checks Executed:** 5" in content
        assert "**Completed:** 4" in content
        assert "**Failed:** 1" in content

    @pytest.mark.asyncio
    async def test_checks_performed_table(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "Checks Performed" in content
        assert "| xss_reflected | web |" in content
        assert "| port_scan | network |" in content

    @pytest.mark.asyncio
    async def test_severity_summary(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "**Total Findings:** 4" in content

    @pytest.mark.asyncio
    async def test_with_engagement(self, db, scan_repo, finding_repo, chain_repo, check_log_repo, engagement_repo):
        eng = await engagement_repo.create_engagement(
            name="Q1 Pentest", target_domain="example.com",
            description="Test engagement", client_name="Acme Corp",
        )
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)

        result = await generate_compliance_report("report-scan", "md", engagement_id=eng["id"])
        content = result["content"]
        assert "## Engagement" in content
        assert "Q1 Pentest" in content
        assert "Acme Corp" in content

    @pytest.mark.asyncio
    async def test_override_audit_trail(
        self, db, scan_repo, finding_repo, chain_repo, check_log_repo, override_repo,
    ):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)

        from sqlalchemy import select
        async with get_session() as session:
            result = await session.execute(
                select(Finding.fingerprint).where(Finding.title == "Missing CSP")
            )
            fp = result.scalar_one()

        await override_repo.set_override(fp, "false_positive", reason="Test endpoint only")

        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "Override Audit Trail" in content
        assert "Missing CSP" in content
        assert "false_positive" in content
        assert "Test endpoint only" in content


class TestComplianceReportJSON:

    @pytest.mark.asyncio
    async def test_json_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "json")

        report = json.loads(result["content"])
        assert report["report_type"] == "compliance"
        assert report["scope"]["checks_executed"] == 5
        assert report["scope"]["completed"] == 4
        assert report["findings"]["total"] == 4
        assert len(report["scope"]["checks_run"]) == 5


class TestComplianceReportHTML:

    @pytest.mark.asyncio
    async def test_html_structure(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "html")

        assert result["format"] == "html"
        assert result["filename"].endswith(".html")

        content = result["content"]
        assert "<!DOCTYPE html>" in content
        assert "Compliance Report" in content
        assert "Scope and Coverage" in content


class TestComplianceReportErrors:

    @pytest.mark.asyncio
    async def test_scan_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_compliance_report("nonexistent", "md")


# --- Trend Report Tests -------------------------------------------------------


@pytest.fixture
def trend_repo():
    return TrendRepository()


class TestTrendReportMarkdown:

    @pytest.fixture
    async def target_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        """Create two completed scans for the same target."""
        await _create_populated_scan(
            scan_repo, finding_repo, chain_repo, check_log_repo,
            scan_id="trend-1", target="trend.com",
        )
        await scan_repo.create_scan(
            scan_id="trend-2", session_id="s2", target_domain="trend.com",
        )
        await finding_repo.bulk_create("trend-2", [
            {"title": "XSS", "severity": "high", "check_name": "xss", "host": "trend.com", "suite": "web"},
            {"title": "SQLi", "severity": "critical", "check_name": "sqli", "host": "trend.com", "suite": "web"},
        ])
        await scan_repo.complete_scan("trend-2", status="complete", findings_count=2)

    @pytest.mark.asyncio
    async def test_basic_structure(self, target_scans):
        result = await generate_trend_report("md", target="trend.com")

        assert result["format"] == "md"
        assert "trend" in result["filename"]

        content = result["content"]
        assert "# Trend Report" in content
        assert "trend.com" in content
        assert "Risk Score Trend" in content

    @pytest.mark.asyncio
    async def test_data_table(self, target_scans):
        result = await generate_trend_report("md", target="trend.com")
        content = result["content"]
        assert "trend-1" in content
        assert "trend-2" in content
        assert "Risk Score" in content

    @pytest.mark.asyncio
    async def test_overall_trend_direction(self, target_scans):
        result = await generate_trend_report("md", target="trend.com")
        content = result["content"]
        assert "Overall trend" in content

    @pytest.mark.asyncio
    async def test_suite_breakdown(self, target_scans):
        result = await generate_trend_report("md", target="trend.com")
        content = result["content"]
        assert "Suite Breakdown" in content

    @pytest.mark.asyncio
    async def test_empty_target(self, db):
        result = await generate_trend_report("md", target="nodata.com")
        assert "No completed scans" in result["content"]


class TestTrendReportJSON:

    @pytest.fixture
    async def target_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo, finding_repo, chain_repo, check_log_repo,
            scan_id="tj-1", target="json-trend.com",
        )

    @pytest.mark.asyncio
    async def test_json_structure(self, target_scans):
        result = await generate_trend_report("json", target="json-trend.com")
        report = json.loads(result["content"])
        assert report["report_type"] == "trend"
        assert report["scan_count"] >= 1
        assert "data_points" in report
        assert "averages" in report


class TestTrendReportHTML:

    @pytest.fixture
    async def target_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo, finding_repo, chain_repo, check_log_repo,
            scan_id="th-1", target="html-trend.com",
        )

    @pytest.mark.asyncio
    async def test_html_structure(self, target_scans):
        result = await generate_trend_report("html", target="html-trend.com")

        assert result["format"] == "html"
        assert result["filename"].endswith(".html")

        content = result["content"]
        assert "<!DOCTYPE html>" in content
        assert "Trend Report" in content

    @pytest.mark.asyncio
    async def test_html_empty_target(self, db):
        result = await generate_trend_report("html", target="empty.com")
        assert "No completed scans" in result["content"]


class TestTrendReportEngagement:

    @pytest.fixture
    async def engagement_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo, engagement_repo):
        eng = await engagement_repo.create_engagement(
            name="Trend Engagement", target_domain="eng-trend.com",
        )
        await scan_repo.create_scan(
            scan_id="te-1", session_id="s1", target_domain="eng-trend.com",
            engagement_id=eng["id"],
        )
        await finding_repo.bulk_create("te-1", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "eng-trend.com", "suite": "web"},
        ])
        await scan_repo.complete_scan("te-1", status="complete", findings_count=1)
        return eng["id"]

    @pytest.mark.asyncio
    async def test_engagement_trend(self, engagement_scans):
        eid = engagement_scans
        result = await generate_trend_report("md", engagement_id=eid)
        content = result["content"]
        assert "# Trend Report" in content
        assert "Trend Engagement" in content


class TestTrendReportErrors:

    @pytest.mark.asyncio
    async def test_no_scope(self, db):
        with pytest.raises(ValueError, match="Either engagement_id or target"):
            await generate_trend_report("md")

    @pytest.mark.asyncio
    async def test_engagement_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_trend_report("md", engagement_id="nonexistent")


# --- PDF Report Tests ---------------------------------------------------------


PDF_MAGIC = b"%PDF"


class TestTechnicalReportPDF:

    @pytest.mark.asyncio
    async def test_pdf_output(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert result["filename"].startswith("technical-example.com")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC

    @pytest.mark.asyncio
    async def test_pdf_not_empty(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "pdf")
        assert len(result["content"]) > 1000


class TestDeltaReportPDF:

    @pytest.fixture
    async def two_scans(self, db, scan_repo, finding_repo):
        await scan_repo.create_scan(scan_id="dp-a", session_id="s1", target_domain="pdf.com")
        await finding_repo.bulk_create("dp-a", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "pdf.com", "suite": "web"},
        ])
        await scan_repo.complete_scan("dp-a", status="complete", findings_count=1)

        await scan_repo.create_scan(scan_id="dp-b", session_id="s2", target_domain="pdf.com")
        await finding_repo.bulk_create("dp-b", [
            {"title": "F1", "severity": "high", "check_name": "c1", "host": "pdf.com", "suite": "web"},
            {"title": "F2", "severity": "critical", "check_name": "c2", "host": "pdf.com", "suite": "web"},
        ])
        await scan_repo.complete_scan("dp-b", status="complete", findings_count=2)

    @pytest.mark.asyncio
    async def test_pdf_output(self, two_scans):
        result = await generate_delta_report("dp-a", "dp-b", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC


class TestExecutiveReportPDF:

    @pytest.mark.asyncio
    async def test_pdf_output(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert result["filename"].startswith("executive-example.com")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC


class TestComplianceReportPDF:

    @pytest.mark.asyncio
    async def test_pdf_output(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, finding_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert result["filename"].startswith("compliance-example.com")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC


class TestTrendReportPDF:

    @pytest.fixture
    async def target_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo, finding_repo, chain_repo, check_log_repo,
            scan_id="tp-1", target="pdf-trend.com",
        )

    @pytest.mark.asyncio
    async def test_pdf_output(self, target_scans):
        result = await generate_trend_report("pdf", target="pdf-trend.com")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC

    @pytest.mark.asyncio
    async def test_pdf_empty_target(self, db):
        result = await generate_trend_report("pdf", target="empty-pdf.com")
        assert result["format"] == "pdf"
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC
