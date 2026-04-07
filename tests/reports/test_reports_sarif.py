"""
Tests for Phase 8B: Reports Hardening + Targeted Export.

Covers:
- SARIF output format for all 5 report types
- Capabilities endpoint (PDF availability detection)
- Targeted export from selected observations
- Report history UI elements (SARIF button, delete button)
"""

import json

import pytest

from app.db.models import ObservationRecord
from app.reports import (
    generate_compliance_report,
    generate_delta_report,
    generate_executive_report,
    generate_targeted_export,
    generate_technical_report,
    generate_trend_report,
)

pytestmark = pytest.mark.integration

# --- Helpers -----------------------------------------------------------------


async def _create_populated_scan(
    scan_repo,
    observation_repo,
    chain_repo,
    check_log_repo,
    scan_id="sarif-scan",
    target="example.com",
):
    """Create a scan with observations, chains, and log entries."""
    await scan_repo.create_scan(
        scan_id=scan_id,
        session_id=f"s-{scan_id}",
        target_domain=target,
    )
    await observation_repo.bulk_create(
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
                "observation_ids": ["f1", "f2"],
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
                "observations": 1,
                "duration_ms": 500,
            },
            {"check": "sqli", "suite": "web", "event": "started"},
            {
                "check": "sqli",
                "suite": "web",
                "event": "completed",
                "observations": 1,
                "duration_ms": 800,
            },
            {"check": "header_analysis", "suite": "web", "event": "started"},
            {
                "check": "header_analysis",
                "suite": "web",
                "event": "completed",
                "observations": 1,
                "duration_ms": 200,
            },
            {"check": "server_header", "suite": "network", "event": "started"},
            {
                "check": "server_header",
                "suite": "network",
                "event": "completed",
                "observations": 1,
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
        observations_count=4,
        checks_total=5,
        checks_completed=4,
        duration_ms=2000,
    )


# =============================================================================
# SARIF Format Tests
# =============================================================================


class TestTechnicalReportSARIF:
    @pytest.mark.asyncio
    async def test_sarif_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")

        assert result["format"] == "sarif"
        assert result["filename"].endswith(".sarif.json")

        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    @pytest.mark.asyncio
    async def test_sarif_results(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        results = sarif["runs"][0]["results"]
        assert len(results) == 4

        # Check severity mapping
        levels = [r["level"] for r in results]
        assert "error" in levels  # critical and high map to error
        assert "warning" in levels  # medium maps to warning
        assert "note" in levels  # info maps to note

    @pytest.mark.asyncio
    async def test_sarif_rules(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "xss_reflected" in rule_ids
        assert "sqli" in rule_ids
        assert "header_analysis" in rule_ids
        assert "server_header" in rule_ids

    @pytest.mark.asyncio
    async def test_sarif_tool_info(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Chainsmith Recon"
        assert driver["version"] == "1.3.0"

    @pytest.mark.asyncio
    async def test_sarif_locations(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        # XSS observation should have a location with target_url
        results = sarif["runs"][0]["results"]
        xss_result = next(r for r in results if r["ruleId"] == "xss_reflected")
        assert "locations" in xss_result
        assert (
            xss_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "http://example.com/search"
        )

    @pytest.mark.asyncio
    async def test_sarif_fingerprints(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        # All observations should have fingerprints
        for r in sarif["runs"][0]["results"]:
            assert "fingerprints" in r
            assert "chainsmith/v1" in r["fingerprints"]

    @pytest.mark.asyncio
    async def test_sarif_evidence_attachments(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        # XSS observation has evidence
        results = sarif["runs"][0]["results"]
        xss_result = next(r for r in results if r["ruleId"] == "xss_reflected")
        assert "attachments" in xss_result
        assert xss_result["attachments"][0]["contents"]["text"] == "<script>alert(1)</script>"

    @pytest.mark.asyncio
    async def test_sarif_invocation_props(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        props = invocation["properties"]
        assert props["reportType"] == "technical"
        assert props["riskScore"] == 17
        assert props["target"] == "example.com"
        assert props["chainCount"] == 1

    @pytest.mark.asyncio
    async def test_sarif_help_uri(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        xss_rule = next(r for r in rules if r["id"] == "xss_reflected")
        assert xss_rule["helpUri"] == "https://owasp.org/xss"


class TestDeltaReportSARIF:
    @pytest.fixture
    async def two_scans(self, db, scan_repo, observation_repo):
        await scan_repo.create_scan(scan_id="ds-a", session_id="s1", target_domain="sarif.com")
        await observation_repo.bulk_create(
            "ds-a",
            [
                {
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "sarif.com",
                    "suite": "web",
                },
                {
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "sarif.com",
                    "suite": "web",
                },
            ],
        )
        await scan_repo.complete_scan("ds-a", status="complete", observations_count=2)

        await scan_repo.create_scan(scan_id="ds-b", session_id="s2", target_domain="sarif.com")
        await observation_repo.bulk_create(
            "ds-b",
            [
                {
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "sarif.com",
                    "suite": "web",
                },
                {
                    "title": "CSRF",
                    "severity": "medium",
                    "check_name": "csrf",
                    "host": "sarif.com",
                    "suite": "web",
                },
            ],
        )
        await scan_repo.complete_scan("ds-b", status="complete", observations_count=2)

    @pytest.mark.asyncio
    async def test_sarif_structure(self, two_scans):
        result = await generate_delta_report("ds-a", "ds-b", "sarif")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"

    @pytest.mark.asyncio
    async def test_sarif_contains_new_observations_only(self, two_scans):
        result = await generate_delta_report("ds-a", "ds-b", "sarif")
        sarif = json.loads(result["content"])
        results = sarif["runs"][0]["results"]
        # Only new observations (CSRF) should appear
        assert len(results) == 1
        assert "CSRF" in results[0]["message"]["text"]

    @pytest.mark.asyncio
    async def test_sarif_invocation_metadata(self, two_scans):
        result = await generate_delta_report("ds-a", "ds-b", "sarif")
        sarif = json.loads(result["content"])
        props = sarif["runs"][0]["invocations"][0]["properties"]
        assert props["reportType"] == "delta"
        assert props["scanA"] == "ds-a"
        assert props["scanB"] == "ds-b"


class TestExecutiveReportSARIF:
    @pytest.mark.asyncio
    async def test_sarif_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("sarif-scan", "sarif")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"
        # Executive shows top 5 observations
        assert len(sarif["runs"][0]["results"]) <= 5

    @pytest.mark.asyncio
    async def test_sarif_invocation_metadata(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_executive_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])
        props = sarif["runs"][0]["invocations"][0]["properties"]
        assert props["reportType"] == "executive"
        assert props["riskScore"] == 17
        assert props["activeObservations"] == 4


class TestComplianceReportSARIF:
    @pytest.mark.asyncio
    async def test_sarif_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
        result = await generate_compliance_report("sarif-scan", "sarif")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"

    @pytest.mark.asyncio
    async def test_sarif_with_overrides(
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

        await override_repo.set_override(fp, "accepted", reason="Known risk")

        result = await generate_compliance_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["suppressions"][0]["status"] == "accepted"
        assert results[0]["suppressions"][0]["justification"] == "Known risk"


class TestTrendReportSARIF:
    @pytest.fixture
    async def target_scans(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo,
            observation_repo,
            chain_repo,
            check_log_repo,
            scan_id="ts-1",
            target="sarif-trend.com",
        )

    @pytest.mark.asyncio
    async def test_sarif_structure(self, target_scans):
        result = await generate_trend_report("sarif", target="sarif-trend.com")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"

    @pytest.mark.asyncio
    async def test_sarif_data_points(self, target_scans):
        result = await generate_trend_report("sarif", target="sarif-trend.com")
        sarif = json.loads(result["content"])
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1
        # Each result represents a data point
        assert results[0]["ruleId"] == "trend_data_point"
        props = results[0]["properties"]
        assert "riskScore" in props
        assert "total" in props


# =============================================================================
# Targeted Export Tests
# =============================================================================


@pytest.fixture
async def targeted_setup(db, scan_repo, observation_repo, chain_repo, check_log_repo):
    """Set up a scan with observations and return (fingerprints, db)."""
    await _create_populated_scan(scan_repo, observation_repo, chain_repo, check_log_repo)
    from sqlalchemy import select

    async with db.session() as session:
        result = await session.execute(select(ObservationRecord.fingerprint))
        fps = [row[0] for row in result.all()]
    return fps, db


async def test_targeted_markdown_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps[:2], "md", db=db)

    assert result["format"] == "md"
    assert result["filename"].startswith("targeted-export-")
    assert result["filename"].endswith(".md")
    content = result["content"]
    assert "# Targeted Export" in content
    assert "**Observations:** 2" in content


async def test_targeted_json_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "json", db=db)

    assert result["format"] == "json"
    report = json.loads(result["content"])
    assert report["report_type"] == "targeted"
    assert report["summary"]["total_observations"] == 4


async def test_targeted_html_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "html", db=db)

    assert result["format"] == "html"
    assert "<!DOCTYPE html>" in result["content"]
    assert "Targeted Export" in result["content"]


async def test_targeted_sarif_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "sarif", db=db)

    assert result["format"] == "sarif"
    sarif = json.loads(result["content"])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 4
    props = sarif["runs"][0]["invocations"][0]["properties"]
    assert props["reportType"] == "targeted"


async def test_targeted_custom_title(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(
        fps[:1], "md", title="Critical Observations Only", db=db
    )
    assert "# Critical Observations Only" in result["content"]


async def test_targeted_no_observations_raises(db):
    with pytest.raises(ValueError, match="No observations found"):
        await generate_targeted_export(["nonexistent-fp"], "md", db=db)


async def test_targeted_risk_score_calculation(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "json", db=db)
    report = json.loads(result["content"])
    # 1 critical(10) + 1 high(5) + 1 medium(2) + 1 info(0) = 17
    assert report["summary"]["risk_score"] == 17


# =============================================================================
# UI Static Tests
# =============================================================================


class TestReportsUIPhase8B:
    def test_reports_html_has_sarif_button(self):
        import pathlib

        content = pathlib.Path("static/reports.html").read_text()
        assert 'data-format="sarif"' in content
        assert "SARIF" in content

    def test_reports_html_has_pdf_capability_check(self):
        import pathlib

        content = pathlib.Path("static/reports.html").read_text()
        assert "checkCapabilities" in content
        assert "pdf-unavailable" in content

    def test_reports_html_has_history_delete(self):
        import pathlib

        content = pathlib.Path("static/reports.html").read_text()
        assert "history-action-btn delete" in content
        assert "history-action-btn regen" in content

    def test_api_js_has_capabilities(self):
        import pathlib

        content = pathlib.Path("static/js/api.js").read_text()
        assert "getCapabilities" in content
        assert "/api/v1/capabilities" in content

    def test_api_js_has_targeted_export(self):
        import pathlib

        content = pathlib.Path("static/js/api.js").read_text()
        assert "generateTargetedExport" in content
        assert "/api/v1/reports/targeted" in content

    def test_api_js_has_scan_observations(self):
        import pathlib

        content = pathlib.Path("static/js/api.js").read_text()
        assert "getScanObservations" in content

    def test_trend_html_has_export_panel(self):
        import pathlib

        content = pathlib.Path("static/trend.html").read_text()
        assert "export-panel" in content
        assert "export-observations-list" in content
        assert "btn-export-selected" in content
        assert "openExportPanel" in content

    def test_trend_html_has_click_to_export(self):
        import pathlib

        # "Click to view observations" lives in the chart rendering JS, not trend.html
        content = pathlib.Path("static/js/viz/trend-charts.js").read_text()
        assert "Click to view observations" in content

    def test_scans_routes_has_capabilities(self):
        import pathlib

        content = pathlib.Path("app/routes/scan_history.py").read_text()
        assert "/api/v1/capabilities" in content
        assert "pdf" in content and "sarif" in content

    def test_scans_routes_has_targeted_export(self):
        import pathlib

        content = pathlib.Path("app/routes/scan_history.py").read_text()
        assert "/api/v1/reports/targeted" in content
        assert "TargetedExportInput" in content

    def test_valid_formats_includes_sarif(self):
        import pathlib

        content = pathlib.Path("app/routes/scan_history.py").read_text()
        assert '"sarif"' in content

    def test_cli_format_choices_include_sarif(self):
        import pathlib

        content = pathlib.Path("app/cli.py").read_text(encoding="utf-8")
        assert '"sarif"' in content
