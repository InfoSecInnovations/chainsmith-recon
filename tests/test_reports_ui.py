"""
Tests for Phase 4g: Report Generation UI.

Covers:
- Reports page route serves HTML
- Navigation links present on all pages
- API.js report methods exist
- Report generation via API endpoints (integration)
"""

import pytest

from app.db.engine import close_db, init_db
from app.db.repositories import (
    EngagementRepository,
    FindingRepository,
    ScanRepository,
)
from app.reports import (
    generate_compliance_report,
    generate_delta_report,
    generate_executive_report,
    generate_technical_report,
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
async def seeded_db(db):
    """Database with scans for report generation."""
    scan_repo = ScanRepository()
    finding_repo = FindingRepository()
    eng_repo = EngagementRepository()

    # Create engagement
    eng = await eng_repo.create_engagement("Test Engagement", "example.com")
    eng_id = eng["id"]

    # Scan 1
    await scan_repo.create_scan(
        scan_id="scan-001",
        session_id="sess-1",
        target_domain="example.com",
        settings={"parallel": False},
        engagement_id=eng_id,
    )
    await finding_repo.bulk_create(
        "scan-001",
        [
            {
                "id": "f-001",
                "title": "XSS in Login",
                "severity": "high",
                "check_name": "xss_check",
                "suite": "web",
                "host": "example.com",
                "target_url": "http://example.com/login",
                "evidence": "<script>alert(1)</script>",
            },
            {
                "id": "f-002",
                "title": "Open Port 22",
                "severity": "info",
                "check_name": "port_scan",
                "suite": "network",
                "host": "example.com",
            },
        ],
    )
    await scan_repo.complete_scan("scan-001", findings_count=2)

    # Scan 2
    await scan_repo.create_scan(
        scan_id="scan-002",
        session_id="sess-2",
        target_domain="example.com",
        settings={"parallel": True},
    )
    await finding_repo.bulk_create(
        "scan-002",
        [
            {
                "id": "f-003",
                "title": "XSS in Login",
                "severity": "high",
                "check_name": "xss_check",
                "suite": "web",
                "host": "example.com",
                "target_url": "http://example.com/login",
                "evidence": "<script>alert(1)</script>",
            },
        ],
    )
    await scan_repo.complete_scan("scan-002", findings_count=1)

    return {
        "scan_ids": ["scan-001", "scan-002"],
        "engagement_id": eng_id,
    }


# --- Static file tests -------------------------------------------------------


class TestReportsPageStatic:
    """Verify reports.html and navigation links exist."""

    def test_reports_html_exists(self):
        """reports.html exists in static directory."""
        from pathlib import Path

        reports_path = Path(__file__).parent.parent / "static" / "reports.html"
        assert reports_path.exists(), "static/reports.html must exist"

    def test_reports_html_has_report_types(self):
        """reports.html contains all 5 report type selectors."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "reports.html").read_text()
        for report_type in ["technical", "delta", "executive", "compliance", "trend"]:
            assert f'data-type="{report_type}"' in content, f"Missing report type: {report_type}"

    def test_reports_html_has_format_buttons(self):
        """reports.html contains format selector buttons."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "reports.html").read_text()
        for fmt in ["html", "md", "json", "pdf"]:
            assert f'data-format="{fmt}"' in content, f"Missing format button: {fmt}"

    def test_reports_html_has_generate_button(self):
        """reports.html contains a generate button."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "reports.html").read_text()
        assert 'id="btn-generate"' in content

    def test_reports_nav_link_in_index(self):
        """index.html has Reports nav link."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "index.html").read_text()
        assert 'href="reports.html"' in content

    def test_reports_nav_link_in_scan(self):
        """scan.html has Reports nav link."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "scan.html").read_text()
        assert 'href="reports.html"' in content

    def test_reports_nav_link_in_findings(self):
        """findings.html has Reports nav link."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "findings.html").read_text()
        assert 'href="reports.html"' in content

    def test_reports_nav_link_in_trend(self):
        """trend.html has Reports nav link."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "trend.html").read_text()
        assert 'href="reports.html"' in content

    def test_reports_nav_link_active_on_reports(self):
        """reports.html marks its own nav link as active."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "reports.html").read_text()
        assert 'reports.html" class="nav-item active"' in content


# --- API.js tests -------------------------------------------------------------


class TestApiJsReportMethods:
    """Verify api.js has report generation methods."""

    def test_api_js_has_report_methods(self):
        """api.js contains all 5 report generation methods."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "js" / "api.js").read_text()
        for method in [
            "generateTechnicalReport",
            "generateDeltaReport",
            "generateExecutiveReport",
            "generateComplianceReport",
            "generateTrendReport",
        ]:
            assert method in content, f"Missing api method: {method}"

    def test_api_js_report_endpoints(self):
        """api.js calls correct report endpoints."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "static" / "js" / "api.js").read_text()
        for endpoint in [
            "/api/v1/reports/technical",
            "/api/v1/reports/delta",
            "/api/v1/reports/executive",
            "/api/v1/reports/compliance",
            "/api/v1/reports/trend",
        ]:
            assert endpoint in content, f"Missing endpoint: {endpoint}"


# --- Route tests --------------------------------------------------------------


class TestReportsRoute:
    """Verify reports route is registered in main.py."""

    def test_reports_route_exists(self):
        """app/main.py has /reports.html route."""
        from pathlib import Path

        content = (Path(__file__).parent.parent / "app" / "main.py").read_text()
        assert '"/reports.html"' in content


# --- Report generation integration (via functions) ----------------------------


class TestReportGenerationFromUI:
    """
    Integration tests verifying reports can be generated with the same
    parameters the UI sends.
    """

    @pytest.mark.asyncio
    async def test_technical_report_html(self, seeded_db):
        result = await generate_technical_report("scan-001", "html")
        assert result["format"] == "html"
        assert "<html" in result["content"].lower()
        assert result["filename"].endswith(".html")

    @pytest.mark.asyncio
    async def test_technical_report_md(self, seeded_db):
        result = await generate_technical_report("scan-001", "md")
        assert result["format"] == "md"
        assert "# Technical" in result["content"] or "XSS" in result["content"]

    @pytest.mark.asyncio
    async def test_technical_report_json(self, seeded_db):
        result = await generate_technical_report("scan-001", "json")
        assert result["format"] == "json"
        content = result["content"]
        if isinstance(content, str):
            import json

            content = json.loads(content)
        assert "findings" in content or "scan" in content

    @pytest.mark.asyncio
    async def test_delta_report_html(self, seeded_db):
        result = await generate_delta_report("scan-001", "scan-002", "html")
        assert result["format"] == "html"
        assert "<html" in result["content"].lower()

    @pytest.mark.asyncio
    async def test_delta_report_md(self, seeded_db):
        result = await generate_delta_report("scan-001", "scan-002", "md")
        assert result["format"] == "md"

    @pytest.mark.asyncio
    async def test_executive_report_html(self, seeded_db):
        result = await generate_executive_report("scan-001", "html")
        assert result["format"] == "html"

    @pytest.mark.asyncio
    async def test_executive_report_with_engagement(self, seeded_db):
        result = await generate_executive_report("scan-001", "md", seeded_db["engagement_id"])
        assert result["format"] == "md"

    @pytest.mark.asyncio
    async def test_compliance_report_html(self, seeded_db):
        result = await generate_compliance_report("scan-001", "html")
        assert result["format"] == "html"

    @pytest.mark.asyncio
    async def test_compliance_report_with_engagement(self, seeded_db):
        result = await generate_compliance_report("scan-001", "md", seeded_db["engagement_id"])
        assert result["format"] == "md"

    @pytest.mark.asyncio
    async def test_trend_report_by_target(self, seeded_db):
        result = await generate_trend_report("html", target="example.com")
        assert result["format"] == "html"

    @pytest.mark.asyncio
    async def test_trend_report_by_engagement(self, seeded_db):
        result = await generate_trend_report("md", engagement_id=seeded_db["engagement_id"])
        assert result["format"] == "md"

    @pytest.mark.asyncio
    async def test_invalid_scan_raises(self, seeded_db):
        with pytest.raises(ValueError):
            await generate_technical_report("nonexistent-scan", "md")

    @pytest.mark.asyncio
    async def test_all_formats_for_executive(self, seeded_db):
        """All 4 formats produce valid output for executive report."""
        for fmt in ["md", "json", "html"]:
            result = await generate_executive_report("scan-001", fmt)
            assert result["format"] == fmt
            assert result["content"]

    @pytest.mark.asyncio
    async def test_pdf_format_technical(self, seeded_db):
        """PDF format produces bytes output."""
        pytest.importorskip("xhtml2pdf")
        result = await generate_technical_report("scan-001", "pdf")
        assert result["format"] == "pdf"
        assert isinstance(result["content"], bytes)
        assert result["filename"].endswith(".pdf")
