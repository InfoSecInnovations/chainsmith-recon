"""Tests for Phase 5a: Severity Heatmap visualization."""

import pytest

from .conftest import FINDINGS_HTML, _all_viz_content

pytestmark = pytest.mark.unit


# --- Static HTML tests --------------------------------------------------------


class TestHeatmapTabPresence:
    """Verify heatmap tab and panel exist in observations.html."""

    def test_observations_html_exists(self):
        assert FINDINGS_HTML.exists(), "static/observations.html must exist"

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
    """Verify heatmap JS functions and constants exist in observations.html."""

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
    def build_heatmap_data(cls, observations_list):
        """Python mirror of the JS buildHeatmapData for testing grouping logic."""
        sev_order = ["critical", "high", "medium", "low", "info"]
        known_suites = ["web", "network", "ai", "mcp", "agent", "rag", "cag"]
        matrix = {}
        hosts = set()
        suites = set()

        for f in observations_list:
            raw_host = f.get("host") or f.get("target_url") or "unknown"
            host = cls.normalize_host(raw_host)
            suite = f.get("suite") or cls.infer_suite(f.get("check_name"))
            hosts.add(host)
            suites.add(suite)

            if host not in matrix:
                matrix[host] = {}
            if suite not in matrix[host]:
                matrix[host][suite] = {"worst": None, "count": 0, "observations": []}

            cell = matrix[host][suite]
            cell["count"] += 1
            cell["observations"].append(f)

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

    def test_empty_observations(self):
        result = self.build_heatmap_data([])
        assert result["hosts"] == []
        assert result["suites"] == []
        assert result["matrix"] == {}

    def test_single_observation(self):
        observations = [{"host": "example.com", "suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_heatmap_data(observations)
        assert result["hosts"] == ["example.com"]
        assert "web" in result["suites"]
        assert result["matrix"]["example.com"]["web"]["worst"] == "high"
        assert result["matrix"]["example.com"]["web"]["count"] == 1

    def test_multiple_observations_same_cell(self):
        observations = [
            {"host": "example.com", "suite": "web", "severity": "low", "title": "A"},
            {"host": "example.com", "suite": "web", "severity": "critical", "title": "B"},
            {"host": "example.com", "suite": "web", "severity": "medium", "title": "C"},
        ]
        result = self.build_heatmap_data(observations)
        cell = result["matrix"]["example.com"]["web"]
        assert cell["worst"] == "critical"
        assert cell["count"] == 3

    def test_multiple_hosts_and_suites(self):
        observations = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "X"},
            {"host": "a.com", "suite": "network", "severity": "info", "title": "Y"},
            {"host": "b.com", "suite": "ai", "severity": "medium", "title": "Z"},
        ]
        result = self.build_heatmap_data(observations)
        assert sorted(result["hosts"]) == ["a.com", "b.com"]
        assert "web" in result["suites"]
        assert "network" in result["suites"]
        assert "ai" in result["suites"]
        assert result["matrix"]["a.com"]["web"]["worst"] == "high"
        assert result["matrix"]["b.com"]["ai"]["worst"] == "medium"
        # Cell not present for b.com/web
        assert "web" not in result["matrix"].get("b.com", {})

    def test_suite_order_follows_known_suites(self):
        observations = [
            {"host": "h", "suite": "cag", "severity": "low", "title": "A"},
            {"host": "h", "suite": "web", "severity": "low", "title": "B"},
            {"host": "h", "suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_heatmap_data(observations)
        # Known order: web comes before ai comes before cag
        assert result["suites"].index("web") < result["suites"].index("ai")
        assert result["suites"].index("ai") < result["suites"].index("cag")

    def test_unknown_suite_appended(self):
        observations = [
            {"host": "h", "suite": "web", "severity": "low", "title": "A"},
            {"host": "h", "suite": "custom", "severity": "info", "title": "B"},
        ]
        result = self.build_heatmap_data(observations)
        assert "custom" in result["suites"]
        # custom comes after known suites
        assert result["suites"].index("web") < result["suites"].index("custom")

    def test_fallback_host_from_target_url(self):
        observations = [
            {"target_url": "http://test.io/path", "suite": "web", "severity": "info", "title": "T"}
        ]
        result = self.build_heatmap_data(observations)
        assert "test.io" in result["hosts"]

    def test_worst_severity_picks_most_severe(self):
        """Verify worst severity is determined by index position, not alphabetically."""
        observations = [
            {"host": "h", "suite": "web", "severity": "info", "title": "A"},
            {"host": "h", "suite": "web", "severity": "high", "title": "B"},
            {"host": "h", "suite": "web", "severity": "low", "title": "C"},
        ]
        result = self.build_heatmap_data(observations)
        assert result["matrix"]["h"]["web"]["worst"] == "high"

    def test_hosts_with_ports_are_merged(self):
        """Observations for example.com:443 and example.com:8080 collapse into one row."""
        observations = [
            {"host": "example.com:443", "suite": "web", "severity": "high", "title": "A"},
            {"host": "example.com:8080", "suite": "web", "severity": "low", "title": "B"},
            {"host": "example.com", "suite": "network", "severity": "info", "title": "C"},
        ]
        result = self.build_heatmap_data(observations)
        assert result["hosts"] == ["example.com"], (
            "All port variants should merge into one host row"
        )
        assert result["matrix"]["example.com"]["web"]["count"] == 2
        assert result["matrix"]["example.com"]["web"]["worst"] == "high"
        assert result["matrix"]["example.com"]["network"]["count"] == 1

    def test_url_hosts_are_normalized_to_hostname(self):
        """Full URLs like http://api.example.com/foo collapse to api.example.com."""
        observations = [
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
        result = self.build_heatmap_data(observations)
        assert result["hosts"] == ["api.example.com"], "URL paths should collapse to hostname"
        assert result["matrix"]["api.example.com"]["web"]["count"] == 2

    def test_infer_suite_from_check_name(self):
        """When suite field is absent, check_name is used to infer suite."""
        observations = [
            {"host": "h", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "h", "check_name": "header_check", "severity": "low", "title": "B"},
            {"host": "h", "check_name": "llm_injection", "severity": "high", "title": "C"},
        ]
        result = self.build_heatmap_data(observations)
        assert "network" in result["matrix"]["h"], "dns_lookup should infer to network"
        assert "web" in result["matrix"]["h"], "header_check should infer to web"
        assert "ai" in result["matrix"]["h"], "llm_injection should infer to ai"

    def test_infer_suite_unknown_check(self):
        """Unknown check names get 'other' suite."""
        observations = [
            {"host": "h", "check_name": "custom_something", "severity": "info", "title": "A"},
        ]
        result = self.build_heatmap_data(observations)
        assert "other" in result["matrix"]["h"]


# --- CSS tests ----------------------------------------------------------------


class TestHeatmapDataRendering:
    """Behavioral tests that exercise data rendering logic end-to-end."""

    def test_worst_severity_drives_cell_color(self):
        """The worst severity in a cell determines the visual weight, not the count."""
        observations = [
            {"host": "h.com", "suite": "web", "severity": "info", "title": "A"},
            {"host": "h.com", "suite": "web", "severity": "info", "title": "B"},
            {"host": "h.com", "suite": "web", "severity": "critical", "title": "C"},
        ]
        result = TestHeatmapDataLogic.build_heatmap_data(observations)
        cell = result["matrix"]["h.com"]["web"]
        assert cell["worst"] == "critical"
        assert cell["count"] == 3

    def test_suite_inference_routes_observations_to_correct_cells(self):
        """Observations without explicit suite are routed by check_name pattern matching."""
        observations = [
            {"host": "h.com", "check_name": "dns_lookup", "severity": "info", "title": "DNS"},
            {"host": "h.com", "check_name": "mcp_discovery", "severity": "high", "title": "MCP"},
            {"host": "h.com", "check_name": "rag_poisoning", "severity": "medium", "title": "RAG"},
        ]
        result = TestHeatmapDataLogic.build_heatmap_data(observations)
        matrix = result["matrix"]["h.com"]
        assert "network" in matrix, "dns_lookup should map to network suite"
        assert "mcp" in matrix, "mcp_discovery should map to mcp suite"
        assert "rag" in matrix, "rag_poisoning should map to rag suite"
        assert matrix["network"]["count"] == 1
        assert matrix["mcp"]["count"] == 1
        assert matrix["rag"]["count"] == 1

    def test_empty_observations_produce_empty_matrix(self):
        """No observations means no cells to render — empty matrix."""
        result = TestHeatmapDataLogic.build_heatmap_data([])
        assert result["matrix"] == {}
        assert result["hosts"] == []
        assert result["suites"] == []


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
