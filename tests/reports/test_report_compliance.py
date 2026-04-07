"""Tests for compliance report generation."""

import json

import pytest

from app.db.models import ObservationRecord
from app.reports import generate_compliance_report

from .conftest import PDF_MAGIC, _create_populated_scan

pytestmark = pytest.mark.integration


class TestComplianceReportMarkdown:
    @pytest.mark.asyncio
    async def test_basic_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")

        assert result["format"] == "md"
        assert result["filename"].startswith("compliance-example.com")

        content = result["content"]
        assert "# Compliance Report" in content
        assert "**Target:** example.com" in content
        assert "Scope and Coverage" in content
        assert "Observation Summary" in content

    @pytest.mark.asyncio
    async def test_check_coverage(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "**Checks Executed:** 5" in content
        assert "**Completed:** 4" in content
        assert "**Failed:** 1" in content

    @pytest.mark.asyncio
    async def test_checks_performed_table(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "Checks Performed" in content
        assert "| xss_reflected | web |" in content
        assert "| port_scan | network |" in content

    @pytest.mark.asyncio
    async def test_severity_summary(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "md")
        content = result["content"]
        assert "**Total Observations:** 4" in content

    @pytest.mark.asyncio
    async def test_with_engagement(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo, engagement_repo
    ):
        eng = await engagement_repo.create_engagement(
            name="Q1 Pentest",
            target_domain="example.com",
            description="Test engagement",
            client_name="Acme Corp",
        )
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)

        result = await generate_compliance_report("report-scan", "md", engagement_id=eng["id"])
        content = result["content"]
        assert "## Engagement" in content
        assert "Q1 Pentest" in content
        assert "Acme Corp" in content

    @pytest.mark.asyncio
    async def test_override_audit_trail(
        self,
        db,
        scan_repo,
        observation_repo,
        chain_repo,
        check_log_repo,
        override_repo,
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)

        from sqlalchemy import select

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(
                    ObservationRecord.title == "Missing CSP"
                )
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
    async def test_json_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "json")

        report = json.loads(result["content"])
        assert report["report_type"] == "compliance"
        assert report["scope"]["checks_executed"] == 5
        assert report["scope"]["completed"] == 4
        assert report["observations"]["total"] == 4
        assert len(report["scope"]["checks_run"]) == 5


class TestComplianceReportHTML:
    @pytest.mark.asyncio
    async def test_html_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
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


class TestComplianceReportPDF:
    xhtml2pdf = pytest.importorskip("xhtml2pdf")

    @pytest.mark.asyncio
    async def test_pdf_output(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("report-scan", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert result["filename"].startswith("compliance-example.com")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC
