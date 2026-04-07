"""Tests for technical report generation."""

import json

import pytest

from app.db.models import ObservationRecord
from app.reports import generate_technical_report

from .conftest import PDF_MAGIC, _create_populated_scan

pytestmark = pytest.mark.integration


# --- Technical Report Tests ---------------------------------------------------


class TestTechnicalReportMarkdown:
    @pytest.mark.asyncio
    async def test_basic_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")

        assert result["format"] == "md"
        assert result["filename"].startswith("technical-example.com")
        assert result["filename"].endswith(".md")

        content = result["content"]
        assert "# Technical Security Report" in content
        assert "**Target:** example.com" in content
        assert "**Scan ID:** report-scan" in content

    @pytest.mark.asyncio
    async def test_severity_summary(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "| Critical | 1 |" in content
        assert "| High | 1 |" in content
        assert "| Medium | 1 |" in content
        assert "| Info | 1 |" in content

    @pytest.mark.asyncio
    async def test_observations_listed(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "XSS in Search" in content
        assert "SQL Injection" in content
        assert "Missing CSP" in content
        assert "Server Info Leak" in content
        assert "xss_reflected" in content
        assert "<script>alert(1)</script>" in content

    @pytest.mark.asyncio
    async def test_chains_included(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "Attack Chains" in content
        assert "XSS to Session Hijack" in content
        assert "rule-based" in content

    @pytest.mark.asyncio
    async def test_check_coverage(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        assert "Check Coverage" in content
        assert "Completed: 4/5" in content
        assert "Failed: 1" in content

    @pytest.mark.asyncio
    async def test_risk_score(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "md")
        content = result["content"]

        # 1 critical(10) + 1 high(5) + 1 medium(2) + 1 info(0) = 17
        assert "**Risk Score:** 17" in content


class TestTechnicalReportJSON:
    @pytest.mark.asyncio
    async def test_json_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "json")

        assert result["format"] == "json"
        assert result["filename"].endswith(".json")

        report = json.loads(result["content"])
        assert report["report_type"] == "technical"
        assert report["scan"]["id"] == "report-scan"
        assert report["summary"]["total_observations"] == 4
        assert report["summary"]["risk_score"] == 17
        assert len(report["observations"]) == 4
        assert len(report["chains"]) == 1
        assert report["check_coverage"]["completed"] == 4
        assert report["check_coverage"]["failed"] == 1


class TestTechnicalReportOverrides:
    @pytest.mark.asyncio
    async def test_overridden_observations_annotated(
        self,
        db,
        scan_repo,
        observation_repo,
        chain_repo,
        check_log_repo,
        override_repo,
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)

        # Get a fingerprint and override it
        from sqlalchemy import select

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(
                    ObservationRecord.title == "Missing CSP"
                )
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
    async def test_empty_scan(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        """Report generates even with no observations."""
        await scan_repo.create_scan(
            scan_id="empty-scan",
            session_id="s1",
            target_domain="empty.com",
        )
        await scan_repo.complete_scan("empty-scan", status="complete", observations_count=0)

        result = await generate_technical_report("empty-scan", "md")
        assert "# Technical Security Report" in result["content"]
        assert "**Observations:** 0" in result["content"]


class TestTechnicalReportHTML:
    @pytest.mark.asyncio
    async def test_html_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
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
    async def test_html_severity_badges(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")
        content = result["content"]

        assert "badge-critical" in content
        assert "badge-high" in content
        assert "badge-medium" in content

    @pytest.mark.asyncio
    async def test_html_chains(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")
        assert "Attack Chains" in result["content"]
        assert "XSS to Session Hijack" in result["content"]

    @pytest.mark.asyncio
    async def test_html_coverage(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "html")
        assert "Check Coverage" in result["content"]
        assert "Completed: 4/5" in result["content"]


class TestTechnicalReportPDF:
    xhtml2pdf = pytest.importorskip("xhtml2pdf")

    @pytest.mark.asyncio
    async def test_pdf_output(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert result["filename"].startswith("technical-example.com")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC

    @pytest.mark.asyncio
    async def test_pdf_not_empty(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("report-scan", "pdf")
        assert len(result["content"]) > 1000
