"""Tests for trend report generation."""

import json

import pytest

from app.reports import generate_trend_report

from .conftest import PDF_MAGIC, _create_populated_scan

pytestmark = pytest.mark.integration


class TestTrendReportMarkdown:
    @pytest.fixture
    async def target_scans(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        """Create two completed scans for the same target."""
        await _create_populated_scan(
            scan_repo,
            observation_repo,
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
        await observation_repo.bulk_create(
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
        await scan_repo.complete_scan("trend-2", status="complete", observations_count=2)

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
    async def target_scans(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo,
            observation_repo,
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
    async def target_scans(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo,
            observation_repo,
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


class TestTrendReportPDF:
    xhtml2pdf = pytest.importorskip("xhtml2pdf")

    @pytest.fixture
    async def target_scans(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo,
            observation_repo,
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
