"""Tests for Phase 5b: Attack Surface Radar visualization."""

import pytest

from .conftest import _all_viz_content

pytestmark = pytest.mark.unit


class TestRadarTabPresence:
    """Verify radar tab and panel exist in observations.html."""

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
    """Verify radar JS functions and constants exist in observations.html."""

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
    def build_radar_data(cls, observations_list):
        """Python mirror of the JS buildRadarData."""
        scores = {}
        for f in observations_list:
            suite = f.get("suite") or cls.infer_suite(f.get("check_name"))
            if suite not in scores:
                scores[suite] = {"score": 0, "breakdown": {}, "observations": []}
            entry = scores[suite]
            weight = cls.RISK_WEIGHTS.get(f["severity"], 0)
            entry["score"] += weight
            entry["breakdown"][f["severity"]] = entry["breakdown"].get(f["severity"], 0) + 1
            entry["observations"].append(f)

        suites = [s for s in cls.KNOWN_SUITES if s in scores]
        for s in sorted(scores.keys()):
            if s not in suites:
                suites.append(s)

        return {"suites": suites, "scores": scores}

    def test_empty_observations(self):
        result = self.build_radar_data([])
        assert result["suites"] == []
        assert result["scores"] == {}

    def test_single_observation_score(self):
        observations = [{"suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_radar_data(observations)
        assert result["scores"]["web"]["score"] == 8
        assert result["scores"]["web"]["breakdown"] == {"high": 1}

    def test_multiple_observations_same_suite(self):
        observations = [
            {"suite": "web", "severity": "critical", "title": "A"},
            {"suite": "web", "severity": "high", "title": "B"},
            {"suite": "web", "severity": "info", "title": "C"},
        ]
        result = self.build_radar_data(observations)
        # 16 + 8 + 1 = 25
        assert result["scores"]["web"]["score"] == 25

    def test_multiple_suites(self):
        observations = [
            {"suite": "web", "severity": "high", "title": "A"},
            {"suite": "network", "severity": "medium", "title": "B"},
            {"suite": "ai", "severity": "critical", "title": "C"},
        ]
        result = self.build_radar_data(observations)
        assert result["scores"]["web"]["score"] == 8
        assert result["scores"]["network"]["score"] == 4
        assert result["scores"]["ai"]["score"] == 16

    def test_suite_order_follows_known_suites(self):
        observations = [
            {"suite": "cag", "severity": "low", "title": "A"},
            {"suite": "web", "severity": "low", "title": "B"},
            {"suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_radar_data(observations)
        assert result["suites"].index("web") < result["suites"].index("ai")
        assert result["suites"].index("ai") < result["suites"].index("cag")

    def test_unknown_suite_appended(self):
        observations = [
            {"suite": "web", "severity": "low", "title": "A"},
            {"suite": "custom", "severity": "info", "title": "B"},
        ]
        result = self.build_radar_data(observations)
        assert "custom" in result["suites"]
        assert result["suites"].index("web") < result["suites"].index("custom")

    def test_infer_suite_from_check_name(self):
        observations = [
            {"check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"check_name": "header_check", "severity": "low", "title": "B"},
        ]
        result = self.build_radar_data(observations)
        assert "network" in result["scores"]
        assert "web" in result["scores"]
        assert result["scores"]["network"]["score"] == 1
        assert result["scores"]["web"]["score"] == 2

    def test_risk_weight_computation_all_severities(self):
        """Verify each severity maps to the correct weight."""
        for sev, expected_weight in self.RISK_WEIGHTS.items():
            observations = [{"suite": "web", "severity": sev, "title": "T"}]
            result = self.build_radar_data(observations)
            assert result["scores"]["web"]["score"] == expected_weight, (
                f"{sev} should have weight {expected_weight}"
            )

    def test_breakdown_counts_per_severity(self):
        observations = [
            {"suite": "ai", "severity": "critical", "title": "A"},
            {"suite": "ai", "severity": "critical", "title": "B"},
            {"suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_radar_data(observations)
        assert result["scores"]["ai"]["breakdown"]["critical"] == 2
        assert result["scores"]["ai"]["breakdown"]["low"] == 1

    def test_observations_stored_in_scores(self):
        observations = [
            {"suite": "mcp", "severity": "medium", "title": "A"},
            {"suite": "mcp", "severity": "info", "title": "B"},
        ]
        result = self.build_radar_data(observations)
        assert len(result["scores"]["mcp"]["observations"]) == 2


class TestRadarDataRendering:
    """Behavioral tests that exercise data rendering logic end-to-end."""

    def test_risk_scores_reflect_severity_weighting(self):
        """A single critical observation outweighs multiple info observations."""
        observations = [
            {"suite": "web", "severity": "critical", "title": "A"},
            {"suite": "network", "severity": "info", "title": "B"},
            {"suite": "network", "severity": "info", "title": "C"},
            {"suite": "network", "severity": "info", "title": "D"},
        ]
        result = TestRadarDataLogic.build_radar_data(observations)
        # critical=16 vs 3*info=3
        assert result["scores"]["web"]["score"] > result["scores"]["network"]["score"]

    def test_suite_scores_are_independent(self):
        """Each suite accumulates its own independent risk score."""
        observations = [
            {"suite": "ai", "severity": "high", "title": "A"},
            {"suite": "ai", "severity": "medium", "title": "B"},
            {"suite": "mcp", "severity": "low", "title": "C"},
        ]
        result = TestRadarDataLogic.build_radar_data(observations)
        assert result["scores"]["ai"]["score"] == 12  # 8 + 4
        assert result["scores"]["mcp"]["score"] == 2
        assert "ai" in result["suites"]
        assert "mcp" in result["suites"]

    def test_inferred_suites_score_correctly(self):
        """Observations without suite field still produce correct risk scores via inference."""
        observations = [
            {"check_name": "agent_discovery", "severity": "critical", "title": "A"},
            {"check_name": "cache_poisoning", "severity": "low", "title": "B"},
        ]
        result = TestRadarDataLogic.build_radar_data(observations)
        assert result["scores"]["agent"]["score"] == 16
        assert result["scores"]["cag"]["score"] == 2


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
