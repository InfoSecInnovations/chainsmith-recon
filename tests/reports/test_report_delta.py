"""Tests for delta report generation."""

import json

import pytest

from app.reports import generate_delta_report

from .conftest import PDF_MAGIC

pytestmark = pytest.mark.integration


# --- Delta Report Tests -------------------------------------------------------


class TestDeltaReportMarkdown:
    @pytest.fixture
    async def two_scans(self, db, scan_repo, observation_repo, comparison_repo):
        """Two scans with known overlap for comparison."""
        await scan_repo.create_scan(
            scan_id="delta-a",
            session_id="s1",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "delta-a",
            [
                {"title": "XSS", "severity": "high", "check_name": "xss", "host": "example.com"},
                {
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "example.com",
                },
                {
                    "title": "Open Port",
                    "severity": "info",
                    "check_name": "port_scan",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("delta-a", status="complete", observations_count=3)

        await scan_repo.create_scan(
            scan_id="delta-b",
            session_id="s2",
            target_domain="example.com",
        )
        await observation_repo.bulk_create(
            "delta-b",
            [
                {"title": "XSS", "severity": "high", "check_name": "xss", "host": "example.com"},
                {
                    "title": "CSRF",
                    "severity": "medium",
                    "check_name": "csrf",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("delta-b", status="complete", observations_count=2)

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
    async def test_new_observations_listed(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        assert "New Observations" in content
        assert "CSRF" in content

    @pytest.mark.asyncio
    async def test_resolved_observations_listed(self, two_scans):
        result = await generate_delta_report("delta-a", "delta-b", "md")
        content = result["content"]

        assert "Resolved Observations" in content
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
    async def two_scans(self, db, scan_repo, observation_repo):
        await scan_repo.create_scan(
            scan_id="dj-a",
            session_id="s1",
            target_domain="json.com",
        )
        await observation_repo.bulk_create(
            "dj-a",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "json.com"},
            ],
        )
        await scan_repo.complete_scan("dj-a", status="complete", observations_count=1)

        await scan_repo.create_scan(
            scan_id="dj-b",
            session_id="s2",
            target_domain="json.com",
        )
        await observation_repo.bulk_create(
            "dj-b",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "json.com"},
                {"title": "F2", "severity": "low", "check_name": "c2", "host": "json.com"},
            ],
        )
        await scan_repo.complete_scan("dj-b", status="complete", observations_count=2)

    @pytest.mark.asyncio
    async def test_json_structure(self, two_scans):
        result = await generate_delta_report("dj-a", "dj-b", "json")

        report = json.loads(result["content"])
        assert report["report_type"] == "delta"
        assert report["scan_a"]["id"] == "dj-a"
        assert report["scan_b"]["id"] == "dj-b"
        assert "summary" in report
        assert "new_observations" in report
        assert "resolved_observations" in report


class TestDeltaReportErrors:
    @pytest.mark.asyncio
    async def test_scan_a_not_found(self, db):
        with pytest.raises(ValueError, match="not found"):
            await generate_delta_report("nonexistent", "also-bad", "md")

    @pytest.mark.asyncio
    async def test_scan_b_not_found(self, db, scan_repo):
        await scan_repo.create_scan(
            scan_id="exists",
            session_id="s1",
            target_domain="x.com",
        )
        with pytest.raises(ValueError, match="not found"):
            await generate_delta_report("exists", "nonexistent", "md")


class TestDeltaReportHTML:
    @pytest.fixture
    async def two_scans(self, db, scan_repo, observation_repo):
        await scan_repo.create_scan(scan_id="dh-a", session_id="s1", target_domain="html.com")
        await observation_repo.bulk_create(
            "dh-a",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "html.com"},
            ],
        )
        await scan_repo.complete_scan("dh-a", status="complete", observations_count=1)

        await scan_repo.create_scan(scan_id="dh-b", session_id="s2", target_domain="html.com")
        await observation_repo.bulk_create(
            "dh-b",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "html.com"},
                {"title": "F2", "severity": "medium", "check_name": "c2", "host": "html.com"},
            ],
        )
        await scan_repo.complete_scan("dh-b", status="complete", observations_count=2)

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
    async def test_html_new_observations(self, two_scans):
        result = await generate_delta_report("dh-a", "dh-b", "html")
        assert "New Observations" in result["content"]
        assert "F2" in result["content"]


class TestDeltaReportPDF:
    xhtml2pdf = pytest.importorskip("xhtml2pdf")

    @pytest.fixture
    async def two_scans(self, db, scan_repo, observation_repo):
        await scan_repo.create_scan(scan_id="dp-a", session_id="s1", target_domain="pdf.com")
        await observation_repo.bulk_create(
            "dp-a",
            [
                {
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "pdf.com",
                    "suite": "web",
                },
            ],
        )
        await scan_repo.complete_scan("dp-a", status="complete", observations_count=1)

        await scan_repo.create_scan(scan_id="dp-b", session_id="s2", target_domain="pdf.com")
        await observation_repo.bulk_create(
            "dp-b",
            [
                {
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "pdf.com",
                    "suite": "web",
                },
                {
                    "title": "F2",
                    "severity": "critical",
                    "check_name": "c2",
                    "host": "pdf.com",
                    "suite": "web",
                },
            ],
        )
        await scan_repo.complete_scan("dp-b", status="complete", observations_count=2)

    @pytest.mark.asyncio
    async def test_pdf_output(self, two_scans):
        result = await generate_delta_report("dp-a", "dp-b", "pdf")

        assert result["format"] == "pdf"
        assert result["filename"].endswith(".pdf")
        assert isinstance(result["content"], bytes)
        assert result["content"][:4] == PDF_MAGIC
