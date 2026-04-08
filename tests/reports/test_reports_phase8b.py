"""Tests for Phase 8B static HTML/JS UI elements (SARIF button, capabilities, targeted export UI)."""


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
