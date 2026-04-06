"""Tests for trend report generation."""

import json

import pytest

from app.reports import generate_trend_report

from .conftest import PDF_MAGIC, _create_populated_scan


pytestmark = pytest.mark.integration


class TestTrendReportMarkdown:
    @pytest.fixture
    async def target_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        """Create two completed scans for the same target."""
        await _create_populated_scan(
            scan_repo,
            finding_repo,
            chain_repo,
            check_log_repo,
            scan_id="trend-1",
            target="trend.com",
        )
        await scan_repo.create_scan(
            scan_id="trend-2",
            session_id="s2",
            target_domain="trend.com",
        )
        await finding_repo.bulk_create(
            "trend-2",
            [
                {
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "trend.com",
                    "suite": "web",
                },
                {
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "trend.com",
                    "suite": "web",
                },
            ],
        )
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
            scan_repo,
            finding_repo,
            chain_repo,
            check_log_repo,
            scan_id="tj-1",
            target="json-trend.com",
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
            scan_repo,
            finding_repo,
            chain_repo,
            check_log_repo,
            scan_id="th-1",
            target="html-trend.com",
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
    async def engagement_scans(
        self, db, scan_repo, finding_repo, chain_repo, check_log_repo, engagement_repo
    ):
        eng = await engagement_repo.create_engagement(
            name="Trend Engagement",
            target_domain="eng-trend.com",
        )
        await scan_repo.create_scan(
            scan_id="te-1",
            session_id="s1",
            target_domain="eng-trend.com",
            engagement_id=eng["id"],
        )
        await finding_repo.bulk_create(
            "te-1",
            [
                {
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "eng-trend.com",
                    "suite": "web",
                },
            ],
        )
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


class TestTrendReportPDF:
    xhtml2pdf = pytest.importorskip("xhtml2pdf")

    @pytest.fixture
    async def target_scans(self, db, scan_repo, finding_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo,
            finding_repo,
            chain_repo,
            check_log_repo,
            scan_id="tp-1",
            target="pdf-trend.com",
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
