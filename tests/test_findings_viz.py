"""
Tests for Phase 5 Findings Visualizations.

Phase 5a: Severity Heatmap visualization.

Covers:
- Heatmap tab and panel exist in findings.html
- Heatmap data grouping logic (buildHeatmapData exposed on window)
- Severity color constants
- Empty state handling
"""

from pathlib import Path

STATIC_DIR = Path(__file__).parent.parent / "static"
FINDINGS_HTML = STATIC_DIR / "findings.html"
VIZ_CSS = STATIC_DIR / "css" / "viz.css"
VIZ_JS_DIR = STATIC_DIR / "js" / "viz"


def _all_viz_content():
    """Return combined text of findings.html + all viz JS + viz CSS for assertion checks."""
    parts = [FINDINGS_HTML.read_text()]
    if VIZ_CSS.exists():
        parts.append(VIZ_CSS.read_text())
    if VIZ_JS_DIR.exists():
        for f in sorted(VIZ_JS_DIR.glob("*.js")):
            parts.append(f.read_text())
    return "\n".join(parts)


# --- Static HTML tests --------------------------------------------------------


class TestHeatmapTabPresence:
    """Verify heatmap tab and panel exist in findings.html."""

    def test_findings_html_exists(self):
        assert FINDINGS_HTML.exists(), "static/findings.html must exist"

    def test_heatmap_tab_exists(self):
        content = _all_viz_content()
        assert 'data-viz="heatmap"' in content, "Missing heatmap viz tab"

    def test_heatmap_tab_label(self):
        content = _all_viz_content()
        assert ">Heatmap<" in content, "Heatmap tab should be labeled 'Heatmap'"

    def test_heatmap_panel_exists(self):
        content = _all_viz_content()
        assert 'id="panel-heatmap"' in content, "Missing heatmap panel div"

    def test_heatmap_empty_state(self):
        content = _all_viz_content()
        assert 'id="heatmap-empty"' in content, "Missing heatmap empty state"

    def test_heatmap_content_div(self):
        content = _all_viz_content()
        assert 'id="heatmap-content"' in content, "Missing heatmap content div"

    def test_heatmap_svg_element(self):
        content = _all_viz_content()
        assert 'id="heatmap-graph"' in content, "Missing heatmap SVG element"

    def test_heatmap_tooltip_element(self):
        content = _all_viz_content()
        assert 'id="heatmap-tooltip"' in content, "Missing heatmap tooltip div"

    def test_heatmap_legend(self):
        content = _all_viz_content()
        assert 'id="heatmap-legend"' in content, "Missing heatmap legend"


# --- JavaScript function tests ------------------------------------------------


class TestHeatmapJavaScript:
    """Verify heatmap JS functions and constants exist in findings.html."""

    def test_render_heatmap_function(self):
        content = _all_viz_content()
        assert "renderHeatmap" in content, "Missing renderHeatmap function"

    def test_build_heatmap_data_function(self):
        content = _all_viz_content()
        assert "function buildHeatmapData(" in content, "Missing buildHeatmapData function"

    def test_build_heatmap_data_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.buildHeatmapData" in content, (
            "buildHeatmapData should be exposed on window for testing"
        )

    def test_heatmap_sev_colors_defined(self):
        content = _all_viz_content()
        assert "SEV_COLORS" in content, "Missing severity colors constant"

    def test_heatmap_severity_color_values(self):
        """All severity colors from the spec are present."""
        content = _all_viz_content()
        for color in ["#991b1b", "#dc2626", "#f59e0b", "#4a9eff", "#6b7280", "#1e293b"]:
            assert color in content, f"Missing heatmap severity color: {color}"

    def test_known_suites_defined(self):
        content = _all_viz_content()
        assert "KNOWN_SUITES" in content, "Missing KNOWN_SUITES constant"
        for suite in ["web", "network", "ai", "mcp", "agent", "rag", "cag"]:
            assert f"'{suite}'" in content, f"Missing known suite: {suite}"

    def test_heatmap_called_in_load_data(self):
        content = _all_viz_content()
        assert "renderHeatmap(" in content, "renderHeatmap should be called in loadData"

    def test_heatmap_uses_d3_scale_band(self):
        content = _all_viz_content()
        assert "d3.scaleBand()" in content, "Heatmap should use d3.scaleBand for axes"

    def test_infer_suite_function(self):
        content = _all_viz_content()
        assert "inferSuite" in content, "Missing inferSuite function"

    def test_infer_suite_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.inferSuite" in content, "inferSuite should be exposed on window"

    def test_suite_patterns_defined(self):
        content = _all_viz_content()
        assert "SUITE_PATTERNS" in content, "Missing SUITE_PATTERNS constant"


# --- Heatmap data grouping logic tests ----------------------------------------


class TestHeatmapDataLogic:
    """Test the heatmap data grouping logic (pure Python mirror of buildHeatmapData)."""

    KNOWN_SUITES = ["web", "network", "ai", "mcp", "agent", "rag", "cag"]
    SEV_ORDER = ["critical", "high", "medium", "low", "info"]

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
    def infer_suite(cls, check_name):
        if not check_name:
            return "other"
        lower = check_name.lower()
        for suite, patterns in cls.SUITE_PATTERNS.items():
            if any(p in lower for p in patterns):
                return suite
        return "other"

    @classmethod
    def build_heatmap_data(cls, findings_list):
        """Python mirror of the JS buildHeatmapData for testing grouping logic."""
        sev_order = ["critical", "high", "medium", "low", "info"]
        known_suites = ["web", "network", "ai", "mcp", "agent", "rag", "cag"]
        matrix = {}
        hosts = set()
        suites = set()

        for f in findings_list:
            raw_host = f.get("host") or f.get("target_url") or "unknown"
            host = cls.normalize_host(raw_host)
            suite = f.get("suite") or cls.infer_suite(f.get("check_name"))
            hosts.add(host)
            suites.add(suite)

            if host not in matrix:
                matrix[host] = {}
            if suite not in matrix[host]:
                matrix[host][suite] = {"worst": None, "count": 0, "findings": []}

            cell = matrix[host][suite]
            cell["count"] += 1
            cell["findings"].append(f)

            sev_idx = (
                sev_order.index(f["severity"]) if f["severity"] in sev_order else len(sev_order)
            )
            worst_idx = (
                sev_order.index(cell["worst"]) if cell["worst"] in sev_order else len(sev_order)
            )
            if sev_idx < worst_idx:
                cell["worst"] = f["severity"]

        all_suites = [s for s in known_suites if s in suites]
        for s in sorted(suites):
            if s not in all_suites:
                all_suites.append(s)

        return {"matrix": matrix, "hosts": sorted(hosts), "suites": all_suites}

    def test_empty_findings(self):
        result = self.build_heatmap_data([])
        assert result["hosts"] == []
        assert result["suites"] == []
        assert result["matrix"] == {}

    def test_single_finding(self):
        findings = [{"host": "example.com", "suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_heatmap_data(findings)
        assert result["hosts"] == ["example.com"]
        assert "web" in result["suites"]
        assert result["matrix"]["example.com"]["web"]["worst"] == "high"
        assert result["matrix"]["example.com"]["web"]["count"] == 1

    def test_multiple_findings_same_cell(self):
        findings = [
            {"host": "example.com", "suite": "web", "severity": "low", "title": "A"},
            {"host": "example.com", "suite": "web", "severity": "critical", "title": "B"},
            {"host": "example.com", "suite": "web", "severity": "medium", "title": "C"},
        ]
        result = self.build_heatmap_data(findings)
        cell = result["matrix"]["example.com"]["web"]
        assert cell["worst"] == "critical"
        assert cell["count"] == 3

    def test_multiple_hosts_and_suites(self):
        findings = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "X"},
            {"host": "a.com", "suite": "network", "severity": "info", "title": "Y"},
            {"host": "b.com", "suite": "ai", "severity": "medium", "title": "Z"},
        ]
        result = self.build_heatmap_data(findings)
        assert sorted(result["hosts"]) == ["a.com", "b.com"]
        assert "web" in result["suites"]
        assert "network" in result["suites"]
        assert "ai" in result["suites"]
        assert result["matrix"]["a.com"]["web"]["worst"] == "high"
        assert result["matrix"]["b.com"]["ai"]["worst"] == "medium"
        # Cell not present for b.com/web
        assert "web" not in result["matrix"].get("b.com", {})

    def test_suite_order_follows_known_suites(self):
        findings = [
            {"host": "h", "suite": "cag", "severity": "low", "title": "A"},
            {"host": "h", "suite": "web", "severity": "low", "title": "B"},
            {"host": "h", "suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_heatmap_data(findings)
        # Known order: web comes before ai comes before cag
        assert result["suites"].index("web") < result["suites"].index("ai")
        assert result["suites"].index("ai") < result["suites"].index("cag")

    def test_unknown_suite_appended(self):
        findings = [
            {"host": "h", "suite": "web", "severity": "low", "title": "A"},
            {"host": "h", "suite": "custom", "severity": "info", "title": "B"},
        ]
        result = self.build_heatmap_data(findings)
        assert "custom" in result["suites"]
        # custom comes after known suites
        assert result["suites"].index("web") < result["suites"].index("custom")

    def test_fallback_host_from_target_url(self):
        findings = [
            {"target_url": "http://test.io/path", "suite": "web", "severity": "info", "title": "T"}
        ]
        result = self.build_heatmap_data(findings)
        assert "test.io" in result["hosts"]

    def test_worst_severity_picks_most_severe(self):
        """Verify worst severity is determined by index position, not alphabetically."""
        findings = [
            {"host": "h", "suite": "web", "severity": "info", "title": "A"},
            {"host": "h", "suite": "web", "severity": "high", "title": "B"},
            {"host": "h", "suite": "web", "severity": "low", "title": "C"},
        ]
        result = self.build_heatmap_data(findings)
        assert result["matrix"]["h"]["web"]["worst"] == "high"

    def test_hosts_with_ports_are_merged(self):
        """Findings for example.com:443 and example.com:8080 collapse into one row."""
        findings = [
            {"host": "example.com:443", "suite": "web", "severity": "high", "title": "A"},
            {"host": "example.com:8080", "suite": "web", "severity": "low", "title": "B"},
            {"host": "example.com", "suite": "network", "severity": "info", "title": "C"},
        ]
        result = self.build_heatmap_data(findings)
        assert result["hosts"] == ["example.com"], (
            "All port variants should merge into one host row"
        )
        assert result["matrix"]["example.com"]["web"]["count"] == 2
        assert result["matrix"]["example.com"]["web"]["worst"] == "high"
        assert result["matrix"]["example.com"]["network"]["count"] == 1

    def test_url_hosts_are_normalized_to_hostname(self):
        """Full URLs like http://api.example.com/foo collapse to api.example.com."""
        findings = [
            {
                "host": "http://api.example.com/login",
                "suite": "web",
                "severity": "high",
                "title": "A",
            },
            {
                "host": "http://api.example.com/admin",
                "suite": "web",
                "severity": "low",
                "title": "B",
            },
            {
                "host": "http://api.example.com:8080/other",
                "suite": "ai",
                "severity": "info",
                "title": "C",
            },
        ]
        result = self.build_heatmap_data(findings)
        assert result["hosts"] == ["api.example.com"], "URL paths should collapse to hostname"
        assert result["matrix"]["api.example.com"]["web"]["count"] == 2

    def test_infer_suite_from_check_name(self):
        """When suite field is absent, check_name is used to infer suite."""
        findings = [
            {"host": "h", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "h", "check_name": "header_check", "severity": "low", "title": "B"},
            {"host": "h", "check_name": "llm_injection", "severity": "high", "title": "C"},
        ]
        result = self.build_heatmap_data(findings)
        assert "network" in result["matrix"]["h"], "dns_lookup should infer to network"
        assert "web" in result["matrix"]["h"], "header_check should infer to web"
        assert "ai" in result["matrix"]["h"], "llm_injection should infer to ai"

    def test_infer_suite_unknown_check(self):
        """Unknown check names get 'other' suite."""
        findings = [
            {"host": "h", "check_name": "custom_something", "severity": "info", "title": "A"},
        ]
        result = self.build_heatmap_data(findings)
        assert "other" in result["matrix"]["h"]


# --- CSS tests ----------------------------------------------------------------


class TestHeatmapCSS:
    """Verify heatmap CSS classes exist."""

    def test_heatmap_container_class(self):
        content = _all_viz_content()
        assert ".heatmap-container" in content

    def test_heatmap_legend_class(self):
        content = _all_viz_content()
        assert ".heatmap-legend" in content

    def test_heatmap_tooltip_class(self):
        content = _all_viz_content()
        assert ".heatmap-tooltip" in content

    def test_heatmap_swatch_class(self):
        content = _all_viz_content()
        assert ".heatmap-swatch" in content


# =============================================================================
# Phase 5b: Attack Surface Radar
# =============================================================================


class TestRadarTabPresence:
    """Verify radar tab and panel exist in findings.html."""

    def test_radar_tab_exists(self):
        content = _all_viz_content()
        assert 'data-viz="radar"' in content, "Missing radar viz tab"

    def test_radar_tab_label(self):
        content = _all_viz_content()
        assert ">Radar<" in content, "Radar tab should be labeled 'Radar'"

    def test_radar_panel_exists(self):
        content = _all_viz_content()
        assert 'id="panel-radar"' in content, "Missing radar panel div"

    def test_radar_empty_state(self):
        content = _all_viz_content()
        assert 'id="radar-empty"' in content, "Missing radar empty state"

    def test_radar_content_div(self):
        content = _all_viz_content()
        assert 'id="radar-content"' in content, "Missing radar content div"

    def test_radar_svg_element(self):
        content = _all_viz_content()
        assert 'id="radar-graph"' in content, "Missing radar SVG element"

    def test_radar_tooltip_element(self):
        content = _all_viz_content()
        assert 'id="radar-tooltip"' in content, "Missing radar tooltip div"

    def test_radar_legend(self):
        content = _all_viz_content()
        assert 'id="radar-legend"' in content, "Missing radar legend"


class TestRadarJavaScript:
    """Verify radar JS functions and constants exist in findings.html."""

    def test_render_radar_function(self):
        content = _all_viz_content()
        assert "renderRadar" in content, "Missing renderRadar function"

    def test_build_radar_data_function(self):
        content = _all_viz_content()
        assert "function buildRadarData(" in content, "Missing buildRadarData function"

    def test_build_radar_data_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.buildRadarData" in content, (
            "buildRadarData should be exposed on window for testing"
        )

    def test_radar_risk_weights_defined(self):
        content = _all_viz_content()
        assert "RADAR_RISK_WEIGHTS" in content, "Missing RADAR_RISK_WEIGHTS constant"

    def test_radar_risk_weight_values(self):
        """All risk weights from the spec are present."""
        content = _all_viz_content()
        for sev, weight in [("critical", 16), ("high", 8), ("medium", 4), ("low", 2), ("info", 1)]:
            assert f"{sev}" in content and str(weight) in content, f"Missing risk weight for {sev}"

    def test_radar_called_in_load_data(self):
        content = _all_viz_content()
        assert "renderRadar(" in content, "renderRadar should be called in loadData"

    def test_radar_uses_d3_line_radial(self):
        content = _all_viz_content()
        assert "d3.lineRadial()" in content, "Radar should use d3.lineRadial for polygon"

    def test_radar_uses_curve_linear_closed(self):
        content = _all_viz_content()
        assert "curveLinearClosed" in content, "Radar polygon should use curveLinearClosed"

    def test_radar_risk_weights_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.RADAR_RISK_WEIGHTS" in content, (
            "RADAR_RISK_WEIGHTS should be exposed on window"
        )


class TestRadarDataLogic:
    """Test the radar data grouping logic (pure Python mirror of buildRadarData)."""

    RISK_WEIGHTS = {"critical": 16, "high": 8, "medium": 4, "low": 2, "info": 1}
    KNOWN_SUITES = ["web", "network", "ai", "mcp", "agent", "rag", "cag"]

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

    @classmethod
    def infer_suite(cls, check_name):
        if not check_name:
            return "other"
        lower = check_name.lower()
        for suite, patterns in cls.SUITE_PATTERNS.items():
            if any(p in lower for p in patterns):
                return suite
        return "other"

    @classmethod
    def build_radar_data(cls, findings_list):
        """Python mirror of the JS buildRadarData."""
        scores = {}
        for f in findings_list:
            suite = f.get("suite") or cls.infer_suite(f.get("check_name"))
            if suite not in scores:
                scores[suite] = {"score": 0, "breakdown": {}, "findings": []}
            entry = scores[suite]
            weight = cls.RISK_WEIGHTS.get(f["severity"], 0)
            entry["score"] += weight
            entry["breakdown"][f["severity"]] = entry["breakdown"].get(f["severity"], 0) + 1
            entry["findings"].append(f)

        suites = [s for s in cls.KNOWN_SUITES if s in scores]
        for s in sorted(scores.keys()):
            if s not in suites:
                suites.append(s)

        return {"suites": suites, "scores": scores}

    def test_empty_findings(self):
        result = self.build_radar_data([])
        assert result["suites"] == []
        assert result["scores"] == {}

    def test_single_finding_score(self):
        findings = [{"suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_radar_data(findings)
        assert result["scores"]["web"]["score"] == 8
        assert result["scores"]["web"]["breakdown"] == {"high": 1}

    def test_multiple_findings_same_suite(self):
        findings = [
            {"suite": "web", "severity": "critical", "title": "A"},
            {"suite": "web", "severity": "high", "title": "B"},
            {"suite": "web", "severity": "info", "title": "C"},
        ]
        result = self.build_radar_data(findings)
        # 16 + 8 + 1 = 25
        assert result["scores"]["web"]["score"] == 25

    def test_multiple_suites(self):
        findings = [
            {"suite": "web", "severity": "high", "title": "A"},
            {"suite": "network", "severity": "medium", "title": "B"},
            {"suite": "ai", "severity": "critical", "title": "C"},
        ]
        result = self.build_radar_data(findings)
        assert result["scores"]["web"]["score"] == 8
        assert result["scores"]["network"]["score"] == 4
        assert result["scores"]["ai"]["score"] == 16

    def test_suite_order_follows_known_suites(self):
        findings = [
            {"suite": "cag", "severity": "low", "title": "A"},
            {"suite": "web", "severity": "low", "title": "B"},
            {"suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_radar_data(findings)
        assert result["suites"].index("web") < result["suites"].index("ai")
        assert result["suites"].index("ai") < result["suites"].index("cag")

    def test_unknown_suite_appended(self):
        findings = [
            {"suite": "web", "severity": "low", "title": "A"},
            {"suite": "custom", "severity": "info", "title": "B"},
        ]
        result = self.build_radar_data(findings)
        assert "custom" in result["suites"]
        assert result["suites"].index("web") < result["suites"].index("custom")

    def test_infer_suite_from_check_name(self):
        findings = [
            {"check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"check_name": "header_check", "severity": "low", "title": "B"},
        ]
        result = self.build_radar_data(findings)
        assert "network" in result["scores"]
        assert "web" in result["scores"]
        assert result["scores"]["network"]["score"] == 1
        assert result["scores"]["web"]["score"] == 2

    def test_risk_weight_computation_all_severities(self):
        """Verify each severity maps to the correct weight."""
        for sev, expected_weight in self.RISK_WEIGHTS.items():
            findings = [{"suite": "web", "severity": sev, "title": "T"}]
            result = self.build_radar_data(findings)
            assert result["scores"]["web"]["score"] == expected_weight, (
                f"{sev} should have weight {expected_weight}"
            )

    def test_breakdown_counts_per_severity(self):
        findings = [
            {"suite": "ai", "severity": "critical", "title": "A"},
            {"suite": "ai", "severity": "critical", "title": "B"},
            {"suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_radar_data(findings)
        assert result["scores"]["ai"]["breakdown"]["critical"] == 2
        assert result["scores"]["ai"]["breakdown"]["low"] == 1

    def test_findings_stored_in_scores(self):
        findings = [
            {"suite": "mcp", "severity": "medium", "title": "A"},
            {"suite": "mcp", "severity": "info", "title": "B"},
        ]
        result = self.build_radar_data(findings)
        assert len(result["scores"]["mcp"]["findings"]) == 2


class TestRadarCSS:
    """Verify radar CSS classes exist."""

    def test_radar_container_class(self):
        content = _all_viz_content()
        assert ".radar-container" in content

    def test_radar_legend_class(self):
        content = _all_viz_content()
        assert ".radar-legend" in content

    def test_radar_tooltip_class(self):
        content = _all_viz_content()
        assert ".radar-tooltip" in content

    def test_radar_swatch_class(self):
        content = _all_viz_content()
        assert ".radar-swatch" in content


# =============================================================================
# Phase 5c: Check Coverage Matrix
# =============================================================================


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


# =============================================================================
# Phase 5d: Timeline View
# =============================================================================


class TestTimelineTabPresence:
    """Verify timeline tab and panel exist in findings.html."""

    def test_timeline_tab_exists(self):
        content = _all_viz_content()
        assert 'data-viz="timeline"' in content, "Missing timeline viz tab"

    def test_timeline_tab_label(self):
        content = _all_viz_content()
        assert ">Timeline<" in content, "Timeline tab should be labeled 'Timeline'"

    def test_timeline_panel_exists(self):
        content = _all_viz_content()
        assert 'id="panel-timeline"' in content, "Missing timeline panel div"

    def test_timeline_empty_state(self):
        content = _all_viz_content()
        assert 'id="timeline-empty"' in content, "Missing timeline empty state"

    def test_timeline_content_div(self):
        content = _all_viz_content()
        assert 'id="timeline-content"' in content, "Missing timeline content div"

    def test_timeline_svg_element(self):
        content = _all_viz_content()
        assert 'id="timeline-graph"' in content, "Missing timeline SVG element"

    def test_timeline_tooltip_element(self):
        content = _all_viz_content()
        assert 'id="timeline-tooltip"' in content, "Missing timeline tooltip div"

    def test_timeline_legend(self):
        content = _all_viz_content()
        assert 'id="timeline-legend"' in content, "Missing timeline legend"

    def test_timeline_group_toggle(self):
        content = _all_viz_content()
        assert 'id="timeline-group-toggle"' in content, "Missing timeline group toggle"

    def test_timeline_group_toggle_host_button(self):
        content = _all_viz_content()
        assert 'data-group="host"' in content, "Missing host group toggle button"

    def test_timeline_group_toggle_suite_button(self):
        content = _all_viz_content()
        assert 'data-group="suite"' in content, "Missing suite group toggle button"


class TestTimelineJavaScript:
    """Verify timeline JS functions and constants exist in findings.html."""

    def test_render_timeline_function(self):
        content = _all_viz_content()
        assert "renderTimeline" in content, "Missing renderTimeline function"

    def test_build_timeline_data_function(self):
        content = _all_viz_content()
        assert "function buildTimelineData(" in content, "Missing buildTimelineData function"

    def test_build_timeline_data_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.buildTimelineData" in content, (
            "buildTimelineData should be exposed on window"
        )

    def test_timeline_sev_colors_defined(self):
        content = _all_viz_content()
        assert "TIMELINE_SEV_COLORS" in content, "Missing TIMELINE_SEV_COLORS constant"

    def test_timeline_sev_colors_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.TIMELINE_SEV_COLORS" in content, (
            "TIMELINE_SEV_COLORS should be exposed on window"
        )

    def test_timeline_sev_radii_defined(self):
        content = _all_viz_content()
        assert "TIMELINE_SEV_RADII" in content, "Missing TIMELINE_SEV_RADII constant"

    def test_timeline_sev_radii_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.TIMELINE_SEV_RADII" in content, (
            "TIMELINE_SEV_RADII should be exposed on window"
        )

    def test_timeline_severity_color_values(self):
        """All severity colors from the spec are present in timeline constants."""
        content = _all_viz_content()
        for color in ["#991b1b", "#dc2626", "#f59e0b", "#4a9eff", "#6b7280"]:
            assert color in content, f"Missing timeline severity color: {color}"

    def test_timeline_called_in_load_data(self):
        content = _all_viz_content()
        assert "renderTimeline(" in content, "renderTimeline should be called in loadData"

    def test_timeline_uses_d3_scale_linear(self):
        content = _all_viz_content()
        assert "d3.scaleLinear()" in content, "Timeline should use d3.scaleLinear for X axis"

    def test_timeline_uses_d3_scale_band(self):
        content = _all_viz_content()
        assert "d3.scaleBand()" in content, "Timeline should use d3.scaleBand for Y axis"


class TestTimelineDataLogic:
    """Test the timeline data grouping logic (pure Python mirror of buildTimelineData)."""

    KNOWN_SUITES = ["web", "network", "ai", "mcp", "agent", "rag", "cag"]

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
    def infer_suite(cls, check_name):
        if not check_name:
            return "other"
        lower = check_name.lower()
        for suite, patterns in cls.SUITE_PATTERNS.items():
            if any(p in lower for p in patterns):
                return suite
        return "other"

    @classmethod
    def build_timeline_data(cls, findings_list, group_by="host"):
        """Python mirror of the JS buildTimelineData."""
        lanes = {}
        points = []

        for index, f in enumerate(findings_list):
            raw_host = f.get("host") or f.get("target_url") or "unknown"
            host = cls.normalize_host(raw_host)
            suite = f.get("suite") or cls.infer_suite(f.get("check_name"))
            lane = host if group_by == "host" else suite

            if lane not in lanes:
                lanes[lane] = []

            point = {
                "index": index,
                "finding": f,
                "lane": lane,
                "host": host,
                "suite": suite,
                "severity": f.get("severity", "info"),
                "title": f.get("title", "Untitled"),
                "checkName": f.get("check_name", ""),
            }
            points.append(point)
            lanes[lane].append(point)

        if group_by == "suite":
            known = [s for s in cls.KNOWN_SUITES if s in lanes]
            extra = sorted(k for k in lanes if k not in known)
            lane_keys = known + extra
        else:
            lane_keys = sorted(lanes.keys())

        return {"points": points, "lanes": lanes, "laneKeys": lane_keys}

    def test_empty_findings(self):
        result = self.build_timeline_data([])
        assert result["points"] == []
        assert result["lanes"] == {}
        assert result["laneKeys"] == []

    def test_single_finding_by_host(self):
        findings = [{"host": "example.com", "suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_timeline_data(findings, "host")
        assert len(result["points"]) == 1
        assert result["points"][0]["index"] == 0
        assert result["points"][0]["lane"] == "example.com"
        assert result["points"][0]["severity"] == "high"
        assert result["laneKeys"] == ["example.com"]

    def test_single_finding_by_suite(self):
        findings = [{"host": "example.com", "suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_timeline_data(findings, "suite")
        assert result["points"][0]["lane"] == "web"
        assert result["laneKeys"] == ["web"]

    def test_multiple_findings_preserve_order(self):
        findings = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "First"},
            {"host": "a.com", "suite": "web", "severity": "low", "title": "Second"},
            {"host": "a.com", "suite": "web", "severity": "info", "title": "Third"},
        ]
        result = self.build_timeline_data(findings, "host")
        assert result["points"][0]["title"] == "First"
        assert result["points"][1]["title"] == "Second"
        assert result["points"][2]["title"] == "Third"
        assert result["points"][0]["index"] == 0
        assert result["points"][1]["index"] == 1
        assert result["points"][2]["index"] == 2

    def test_multiple_hosts_creates_lanes(self):
        findings = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "A"},
            {"host": "b.com", "suite": "network", "severity": "low", "title": "B"},
            {"host": "c.com", "suite": "ai", "severity": "info", "title": "C"},
        ]
        result = self.build_timeline_data(findings, "host")
        assert sorted(result["laneKeys"]) == ["a.com", "b.com", "c.com"]
        assert len(result["lanes"]["a.com"]) == 1
        assert len(result["lanes"]["b.com"]) == 1

    def test_suite_grouping_uses_known_order(self):
        findings = [
            {"host": "h", "suite": "cag", "severity": "low", "title": "A"},
            {"host": "h", "suite": "web", "severity": "low", "title": "B"},
            {"host": "h", "suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_timeline_data(findings, "suite")
        assert result["laneKeys"].index("web") < result["laneKeys"].index("ai")
        assert result["laneKeys"].index("ai") < result["laneKeys"].index("cag")

    def test_host_normalization(self):
        findings = [
            {
                "host": "http://api.example.com/path",
                "suite": "web",
                "severity": "high",
                "title": "A",
            },
            {"host": "api.example.com:8080", "suite": "web", "severity": "low", "title": "B"},
        ]
        result = self.build_timeline_data(findings, "host")
        assert result["laneKeys"] == ["api.example.com"]
        assert len(result["lanes"]["api.example.com"]) == 2

    def test_infer_suite_when_no_suite_field(self):
        findings = [
            {"host": "h", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "h", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        result = self.build_timeline_data(findings, "suite")
        assert "network" in result["laneKeys"]
        assert "web" in result["laneKeys"]

    def test_unknown_suite_appended_after_known(self):
        findings = [
            {"host": "h", "suite": "web", "severity": "low", "title": "A"},
            {"host": "h", "suite": "custom", "severity": "info", "title": "B"},
        ]
        result = self.build_timeline_data(findings, "suite")
        assert result["laneKeys"].index("web") < result["laneKeys"].index("custom")

    def test_default_group_by_is_host(self):
        findings = [{"host": "h.com", "suite": "web", "severity": "info", "title": "T"}]
        result = self.build_timeline_data(findings)
        assert result["points"][0]["lane"] == "h.com"

    def test_missing_host_falls_back_to_unknown(self):
        findings = [{"suite": "web", "severity": "info", "title": "T"}]
        result = self.build_timeline_data(findings, "host")
        assert "unknown" in result["laneKeys"]

    def test_missing_severity_defaults_to_info(self):
        findings = [{"host": "h", "suite": "web", "title": "T"}]
        result = self.build_timeline_data(findings, "host")
        assert result["points"][0]["severity"] == "info"

    def test_lanes_contain_correct_points(self):
        findings = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "A"},
            {"host": "b.com", "suite": "network", "severity": "low", "title": "B"},
            {"host": "a.com", "suite": "ai", "severity": "info", "title": "C"},
        ]
        result = self.build_timeline_data(findings, "host")
        assert len(result["lanes"]["a.com"]) == 2
        assert len(result["lanes"]["b.com"]) == 1
        assert result["lanes"]["a.com"][0]["title"] == "A"
        assert result["lanes"]["a.com"][1]["title"] == "C"


class TestTimelineCSS:
    """Verify timeline CSS classes exist."""

    def test_timeline_container_class(self):
        content = _all_viz_content()
        assert ".timeline-container" in content

    def test_timeline_legend_class(self):
        content = _all_viz_content()
        assert ".timeline-legend" in content

    def test_timeline_tooltip_class(self):
        content = _all_viz_content()
        assert ".timeline-tooltip" in content

    def test_timeline_swatch_class(self):
        content = _all_viz_content()
        assert ".timeline-swatch" in content

    def test_timeline_toggle_class(self):
        content = _all_viz_content()
        assert ".timeline-toggle" in content
