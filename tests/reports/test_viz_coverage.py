"""Tests for Phase 5c: Check Coverage Matrix visualization."""

import pytest

from .conftest import _all_viz_content


pytestmark = pytest.mark.unit


class TestCoverageTabPresence:
    """Verify coverage tab and panel exist in findings.html."""

    def test_coverage_tab_exists(self):
        content = _all_viz_content()
        assert 'data-viz="coverage"' in content, "Missing coverage viz tab"

    def test_coverage_tab_label(self):
        content = _all_viz_content()
        assert ">Coverage<" in content, "Coverage tab should be labeled 'Coverage'"

    def test_coverage_panel_exists(self):
        content = _all_viz_content()
        assert 'id="panel-coverage"' in content, "Missing coverage panel div"

    def test_coverage_empty_state(self):
        content = _all_viz_content()
        assert 'id="coverage-empty"' in content, "Missing coverage empty state"

    def test_coverage_content_div(self):
        content = _all_viz_content()
        assert 'id="coverage-content"' in content, "Missing coverage content div"

    def test_coverage_svg_element(self):
        content = _all_viz_content()
        assert 'id="coverage-graph"' in content, "Missing coverage SVG element"

    def test_coverage_tooltip_element(self):
        content = _all_viz_content()
        assert 'id="coverage-tooltip"' in content, "Missing coverage tooltip div"

    def test_coverage_legend(self):
        content = _all_viz_content()
        assert 'id="coverage-legend"' in content, "Missing coverage legend"

    def test_coverage_note_element(self):
        content = _all_viz_content()
        assert 'id="coverage-note"' in content, "Missing coverage note div"


class TestCoverageJavaScript:
    """Verify coverage JS functions and constants exist in findings.html."""

    def test_render_coverage_function(self):
        content = _all_viz_content()
        assert "renderCoverage" in content, "Missing renderCoverage function"

    def test_build_coverage_data_function(self):
        content = _all_viz_content()
        assert "function buildCoverageData(" in content, "Missing buildCoverageData function"

    def test_build_coverage_data_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.buildCoverageData" in content, (
            "buildCoverageData should be exposed on window"
        )

    def test_coverage_status_colors_defined(self):
        content = _all_viz_content()
        assert "COVERAGE_STATUS_COLORS" in content, "Missing COVERAGE_STATUS_COLORS constant"

    def test_coverage_status_color_values(self):
        """All status colors are present."""
        content = _all_viz_content()
        for color in ["#4ade80", "#f59e0b", "#6b7280", "#ef4444", "#1e293b"]:
            assert color in content, f"Missing coverage status color: {color}"

    def test_coverage_called_in_load_data(self):
        content = _all_viz_content()
        assert "renderCoverage(" in content, "renderCoverage should be called in loadData"

    def test_coverage_uses_d3_scale_band(self):
        content = _all_viz_content()
        # Already tested for heatmap, but coverage also uses it
        assert "d3.scaleBand()" in content

    def test_coverage_status_colors_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.COVERAGE_STATUS_COLORS" in content, (
            "COVERAGE_STATUS_COLORS should be exposed on window"
        )


class TestCoverageDataLogic:
    """Test the coverage matrix data assembly logic (pure Python mirror of buildCoverageData)."""

    SUITE_PATTERNS = {
        "network": ["dns", "service_probe", "port"],
        "web": ["header", "robots", "path", "openapi", "cors", "content"],
        "ai": [
            "llm",
            "embedding",
            "model",
            "fingerprint",
            "error",
            "tool",
            "prompt",
            "rate",
            "filter",
            "context",
        ],
        "mcp": ["mcp"],
        "agent": ["agent", "goal"],
        "rag": ["rag", "indirect"],
        "cag": ["cag", "cache"],
    }

    @staticmethod
    def normalize_host(name):
        import re
        from urllib.parse import urlparse

        if re.match(r"^https?://", name, re.IGNORECASE):
            try:
                return urlparse(name).hostname or name
            except Exception:
                pass
        return re.sub(r":\d+$", "", name)

    @classmethod
    def build_coverage_data(cls, findings_list, check_statuses):
        """Python mirror of the JS buildCoverageData."""
        checks = []
        check_status_map = {}

        for cs in check_statuses or []:
            name = cs.get("name") or cs.get("check_name")
            if not name:
                continue
            if name not in check_status_map:
                check_status_map[name] = cs.get("status", "completed")
                checks.append(name)

        for f in findings_list:
            name = f.get("check_name")
            if name and name not in check_status_map:
                check_status_map[name] = "completed"
                checks.append(name)

        if not checks:
            return {"matrix": {}, "hosts": [], "checks": [], "isGlobal": True}

        # Group findings by host
        findings_by_host = {}
        for f in findings_list:
            raw_host = f.get("host") or f.get("target_url") or "global"
            host = cls.normalize_host(raw_host)
            if host not in findings_by_host:
                findings_by_host[host] = []
            findings_by_host[host].append(f)

        hosts = sorted(findings_by_host.keys())
        is_global = len(hosts) <= 1

        if is_global:
            global_host = hosts[0] if hosts else "all"
            matrix = {global_host: {}}

            findings_by_check = {}
            for f in findings_list:
                cn = f.get("check_name")
                if not cn:
                    continue
                if cn not in findings_by_check:
                    findings_by_check[cn] = []
                findings_by_check[cn].append(f)

            for check in checks:
                check_findings = findings_by_check.get(check, [])
                status = check_status_map.get(check, "not-run")
                if check_findings and status == "completed":
                    status = "found"
                matrix[global_host][check] = {
                    "status": status,
                    "findingCount": len(check_findings),
                    "findings": check_findings,
                }
            return {"matrix": matrix, "hosts": [global_host], "checks": checks, "isGlobal": True}

        # Multi-host
        matrix = {}
        for host in hosts:
            matrix[host] = {}
            host_findings = findings_by_host.get(host, [])
            host_fbc = {}
            for f in host_findings:
                cn = f.get("check_name")
                if not cn:
                    continue
                if cn not in host_fbc:
                    host_fbc[cn] = []
                host_fbc[cn].append(f)

            for check in checks:
                check_findings = host_fbc.get(check, [])
                status = check_status_map.get(check, "not-run")
                if check_findings and status == "completed":
                    status = "found"
                matrix[host][check] = {
                    "status": status,
                    "findingCount": len(check_findings),
                    "findings": check_findings,
                }

        return {"matrix": matrix, "hosts": hosts, "checks": checks, "isGlobal": False}

    def test_empty_inputs(self):
        result = self.build_coverage_data([], [])
        assert result["hosts"] == []
        assert result["checks"] == []
        assert result["matrix"] == {}
        assert result["isGlobal"] is True

    def test_checks_only_no_findings(self):
        """Check statuses with no findings still produce a global view with checks listed."""
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {"name": "header_check", "status": "skipped"},
        ]
        result = self.build_coverage_data([], checks)
        assert result["isGlobal"] is True
        assert "dns_lookup" in result["checks"]
        assert "header_check" in result["checks"]
        # Single "all" host row in global view
        assert result["hosts"] == ["all"]
        assert result["matrix"]["all"]["dns_lookup"]["status"] == "completed"
        assert result["matrix"]["all"]["header_check"]["status"] == "skipped"

    def test_single_host_global_view(self):
        findings = [
            {"host": "example.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "example.com", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {"name": "header_check", "status": "completed"},
            {"name": "port_scan", "status": "completed"},
        ]
        result = self.build_coverage_data(findings, checks)
        assert result["isGlobal"] is True
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        # dns_lookup produced findings -> 'found'
        assert result["matrix"][host]["dns_lookup"]["status"] == "found"
        assert result["matrix"][host]["dns_lookup"]["findingCount"] == 1
        # header_check produced findings -> 'found'
        assert result["matrix"][host]["header_check"]["status"] == "found"
        # port_scan completed with no findings -> 'completed'
        assert result["matrix"][host]["port_scan"]["status"] == "completed"
        assert result["matrix"][host]["port_scan"]["findingCount"] == 0

    def test_multi_host_view(self):
        findings = [
            {"host": "a.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "b.com", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {"name": "header_check", "status": "completed"},
        ]
        result = self.build_coverage_data(findings, checks)
        assert result["isGlobal"] is False
        assert sorted(result["hosts"]) == ["a.com", "b.com"]
        # a.com has dns_lookup finding
        assert result["matrix"]["a.com"]["dns_lookup"]["status"] == "found"
        assert result["matrix"]["a.com"]["dns_lookup"]["findingCount"] == 1
        # a.com has no header_check finding
        assert result["matrix"]["a.com"]["header_check"]["status"] == "completed"
        assert result["matrix"]["a.com"]["header_check"]["findingCount"] == 0
        # b.com has header_check finding
        assert result["matrix"]["b.com"]["header_check"]["status"] == "found"

    def test_skipped_and_error_statuses(self):
        findings = [
            {"host": "a.com", "check_name": "ok_check", "severity": "info", "title": "X"},
            {"host": "b.com", "check_name": "ok_check", "severity": "info", "title": "Y"},
        ]
        checks = [
            {"name": "ok_check", "status": "completed"},
            {"name": "skip_check", "status": "skipped"},
            {"name": "err_check", "status": "error"},
        ]
        result = self.build_coverage_data(findings, checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["skip_check"]["status"] == "skipped"
        assert result["matrix"][host]["err_check"]["status"] == "error"

    def test_findings_without_check_statuses(self):
        """Findings with check_name but no checkStatuses still create coverage data."""
        findings = [
            {"host": "a.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "b.com", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        result = self.build_coverage_data(findings, [])
        assert result["isGlobal"] is False
        assert "dns_lookup" in result["checks"]
        assert "header_check" in result["checks"]
        # All statuses default to 'completed' then become 'found' because they have findings
        assert result["matrix"]["a.com"]["dns_lookup"]["status"] == "found"

    def test_check_name_deduplication(self):
        """Same check name from both checkStatuses and findings shouldn't be duplicated."""
        findings = [
            {"host": "h.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
        ]
        result = self.build_coverage_data(findings, checks)
        assert result["checks"].count("dns_lookup") == 1

    def test_host_normalization_in_coverage(self):
        findings = [
            {
                "host": "http://api.example.com/path",
                "check_name": "check_a",
                "severity": "info",
                "title": "A",
            },
            {
                "host": "api.example.com:8080",
                "check_name": "check_b",
                "severity": "low",
                "title": "B",
            },
        ]
        checks = [
            {"name": "check_a", "status": "completed"},
            {"name": "check_b", "status": "completed"},
        ]
        result = self.build_coverage_data(findings, checks)
        assert "api.example.com" in result["hosts"]
        assert result["isGlobal"] is True  # Both normalize to same host


class TestCoverageCSS:
    """Verify coverage CSS classes exist."""

    def test_coverage_container_class(self):
        content = _all_viz_content()
        assert ".coverage-container" in content

    def test_coverage_legend_class(self):
        content = _all_viz_content()
        assert ".coverage-legend" in content

    def test_coverage_tooltip_class(self):
        content = _all_viz_content()
        assert ".coverage-tooltip" in content

    def test_coverage_swatch_class(self):
        content = _all_viz_content()
        assert ".coverage-swatch" in content

    def test_coverage_note_class(self):
        content = _all_viz_content()
        assert ".coverage-note" in content
