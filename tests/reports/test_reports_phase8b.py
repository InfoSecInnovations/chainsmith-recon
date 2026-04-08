"""Tests for Phase 8B: SARIF export, capabilities, targeted export UI, and report helpers."""

import pathlib

import pytest

from app.reports import _check_coverage, _count_by_severity, _risk_score

pytestmark = pytest.mark.unit


# ═══════════════════════════════════════════════════════════════════════════════
# Static HTML/JS presence (smoke tests)
# ═══════════════════════════════════════════════════════════════════════════════


class TestReportsUIPhase8B:
    def test_reports_html_has_sarif_button(self):
        content = pathlib.Path("static/reports.html").read_text()
        assert 'data-format="sarif"' in content
        assert "SARIF" in content

    def test_reports_html_has_pdf_capability_check(self):
        content = pathlib.Path("static/reports.html").read_text()
        assert "checkCapabilities" in content
        assert "pdf-unavailable" in content

    def test_reports_html_has_history_delete(self):
        content = pathlib.Path("static/reports.html").read_text()
        assert "history-action-btn delete" in content
        assert "history-action-btn regen" in content

    def test_api_js_has_capabilities(self):
        content = pathlib.Path("static/js/api.js").read_text()
        assert "getCapabilities" in content
        assert "/api/v1/capabilities" in content

    def test_api_js_has_targeted_export(self):
        content = pathlib.Path("static/js/api.js").read_text()
        assert "generateTargetedExport" in content
        assert "/api/v1/reports/targeted" in content

    def test_api_js_has_scan_observations(self):
        content = pathlib.Path("static/js/api.js").read_text()
        assert "getScanObservations" in content

    def test_trend_html_has_export_panel(self):
        content = pathlib.Path("static/trend.html").read_text()
        assert "export-panel" in content
        assert "export-observations-list" in content
        assert "btn-export-selected" in content
        assert "openExportPanel" in content

    def test_trend_html_has_click_to_export(self):
        content = pathlib.Path("static/js/viz/trend-charts.js").read_text()
        assert "Click to view observations" in content

    def test_scans_routes_has_capabilities(self):
        content = pathlib.Path("app/routes/scan_history.py").read_text()
        assert "/api/v1/capabilities" in content
        assert "pdf" in content and "sarif" in content

    def test_scans_routes_has_targeted_export(self):
        content = pathlib.Path("app/routes/scan_history.py").read_text()
        assert "/api/v1/reports/targeted" in content
        assert "TargetedExportInput" in content

    def test_valid_formats_includes_sarif(self):
        content = pathlib.Path("app/routes/scan_history.py").read_text()
        assert '"sarif"' in content

    def test_cli_format_choices_include_sarif(self):
        content = pathlib.Path("app/cli.py").read_text(encoding="utf-8")
        assert '"sarif"' in content


# ═══════════════════════════════════════════════════════════════════════════════
# Behavioral tests for report helper logic
# ═══════════════════════════════════════════════════════════════════════════════


class TestCountBySeverity:
    """Test _count_by_severity aggregation logic."""

    def test_counts_all_severity_levels(self):
        observations = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
            {"severity": "info"},
            {"severity": "info"},
        ]
        counts = _count_by_severity(observations)
        assert counts == {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 3}

    def test_empty_observations(self):
        counts = _count_by_severity([])
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def test_unknown_severity_ignored(self):
        observations = [{"severity": "bogus"}, {"severity": "high"}]
        counts = _count_by_severity(observations)
        assert counts["high"] == 1
        assert sum(counts.values()) == 1

    def test_missing_severity_defaults_to_info(self):
        observations = [{}]
        counts = _count_by_severity(observations)
        assert counts["info"] == 1


class TestRiskScore:
    """Test _risk_score weighted computation."""

    def test_single_critical(self):
        counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
        assert _risk_score(counts) == 10

    def test_mixed_severities(self):
        counts = {"critical": 2, "high": 1, "medium": 3, "low": 0, "info": 5}
        # 2*10 + 1*5 + 3*2 + 0*1 + 5*0 = 20 + 5 + 6 + 0 + 0 = 31
        assert _risk_score(counts) == 31

    def test_zero_observations(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        assert _risk_score(counts) == 0


class TestCheckCoverage:
    """Test _check_coverage log entry analysis."""

    def test_all_event_types_counted(self):
        log_entries = [
            {"event": "started", "check": "a"},
            {"event": "completed", "check": "a"},
            {"event": "started", "check": "b"},
            {"event": "failed", "check": "b"},
            {"event": "started", "check": "c"},
            {"event": "skipped", "check": "c"},
        ]
        cov = _check_coverage(log_entries)
        assert cov["total"] == 3
        assert cov["completed"] == 1
        assert cov["failed"] == 1
        assert cov["skipped"] == 1

    def test_empty_log(self):
        cov = _check_coverage([])
        assert cov["total"] == 0
        assert cov["completed"] == 0
        assert cov["failed"] == 0
        assert cov["skipped"] == 0
