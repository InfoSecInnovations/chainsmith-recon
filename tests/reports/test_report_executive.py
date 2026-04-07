"""Tests for executive report generation."""

import json

import pytest

from app.reports import generate_executive_report

from .conftest import PDF_MAGIC, _create_populated_scan

pytestmark = pytest.mark.integration


class TestExecutiveReportMarkdown:
    @pytest.mark.asyncio
    async def test_basic_structure(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")

        assert result["format"] == "md"
        assert result["filename"].startswith("executive-example.com")
        assert result["filename"].endswith(".md")

        content = result["content"]
        assert "# Executive Summary" in content
        assert "**Target:** example.com" in content
        assert "Risk Overview" in content
        assert "Top Observations" in content

    @pytest.mark.asyncio
    async def test_risk_score(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")
        # 1 critical(10) + 1 high(5) + 1 medium(2) + 1 info(0) = 17
        assert "**Risk Score:** 17" in result["content"]

    @pytest.mark.asyncio
    async def test_top_observations(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")
        content = result["content"]
        assert "SQL Injection" in content
        assert "XSS in Search" in content

    @pytest.mark.asyncio
    async def test_severity_table(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "md")
        content = result["content"]
        assert "| Critical | 1 |" in content
        assert "| High | 1 |" in content

    @pytest.mark.asyncio
    async def test_with_previous_scan(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        """When a previous scan exists, show risk trend."""
        # First scan (previous)
        await _create_populated_scan(
            scan_repo,
            observation_repo,
            chain_repo,
            check_log_repo,
            scan_id="exec-prev",
            target="trend.com",
        )
        # Second scan (current) - fewer observations
        await scan_repo.create_scan(
            scan_id="exec-curr",
            session_id="s2",
            target_domain="trend.com",
        )
        await observation_repo.bulk_create(
            "exec-curr",
            [
                {
                    "title": "Low Observation",
                    "severity": "low",
                    "check_name": "c1",
                    "host": "trend.com",
                },
            ],
        )
        await scan_repo.complete_scan("exec-curr", status="complete", observations_count=1)

        result = await generate_executive_report("exec-curr", "md")
        content = result["content"]
        assert "previously" in content
        assert "improved" in content


class TestExecutiveReportJSON:
    @pytest.mark.asyncio
    async def test_json_structure(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "json")

        assert result["format"] == "json"
        assert result["filename"].endswith(".json")

        report = json.loads(result["content"])
        assert report["report_type"] == "executive"
        assert report["summary"]["risk_score"] == 17
        assert report["summary"]["active_observations"] == 4
        assert len(report["top_observations"]) <= 5


class TestExecutiveReportHTML:
    @pytest.mark.asyncio
    async def test_html_structure(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "html")

        assert result["format"] == "html"
        assert result["filename"].endswith(".html")

        content = result["content"]
        assert "<!DOCTYPE html>" in content
        assert "Executive Summary" in content
        assert "stat-grid" in content
        assert "Top Observations" in content

    @pytest.mark.asyncio
    async def test_html_badges(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "html")
        assert "badge-critical" in result["content"]


class TestExecutiveReportErrors:
    @pytest.mark.asyncio
    async def test_scan_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_executive_report("nonexistent", "md")


class TestExecutiveReportPDF:
    xhtml2pdf = pytest.importorskip("xhtml2pdf")

    @pytest.mark.asyncio
    async def test_pdf_output(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("report-scan", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert result["filename"].startswith("executive-example.com")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC
