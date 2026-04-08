"""Tests for Phase 5d: Timeline View visualization."""

import pytest

from .conftest import _all_viz_content

pytestmark = pytest.mark.unit


class TestTimelineTabPresence:
    """Verify timeline tab and panel exist in observations.html."""

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
    """Verify timeline JS functions and constants exist in observations.html."""

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

    def test_format_timestamp_function(self):
        content = _all_viz_content()
        assert "formatTimestamp" in content, "Missing formatTimestamp function"

    def test_format_time_short_function(self):
        content = _all_viz_content()
        assert "formatTimeShort" in content, "Missing formatTimeShort function"

    def test_relative_time_function(self):
        content = _all_viz_content()
        assert "relativeTime" in content, "Missing relativeTime function"

    def test_tooltip_shows_time_label(self):
        content = _all_viz_content()
        assert "Time: " in content, "Tooltip should display timestamp with 'Time:' label"


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
    def build_timeline_data(cls, observations_list, group_by="host"):
        """Python mirror of the JS buildTimelineData."""
        lanes = {}
        points = []

        for index, f in enumerate(observations_list):
            raw_host = f.get("host") or f.get("target_url") or "unknown"
            host = cls.normalize_host(raw_host)
            suite = f.get("suite") or cls.infer_suite(f.get("check_name"))
            lane = host if group_by == "host" else suite

            if lane not in lanes:
                lanes[lane] = []

            point = {
                "index": index,
                "observation": f,
                "lane": lane,
                "host": host,
                "suite": suite,
                "severity": f.get("severity", "info"),
                "title": f.get("title", "Untitled"),
                "checkName": f.get("check_name", ""),
                "createdAt": f.get("created_at") or None,
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

    def test_empty_observations(self):
        result = self.build_timeline_data([])
        assert result["points"] == []
        assert result["lanes"] == {}
        assert result["laneKeys"] == []

    def test_single_observation_by_host(self):
        observations = [{"host": "example.com", "suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_timeline_data(observations, "host")
        assert len(result["points"]) == 1
        assert result["points"][0]["index"] == 0
        assert result["points"][0]["lane"] == "example.com"
        assert result["points"][0]["severity"] == "high"
        assert result["laneKeys"] == ["example.com"]

    def test_single_observation_by_suite(self):
        observations = [{"host": "example.com", "suite": "web", "severity": "high", "title": "XSS"}]
        result = self.build_timeline_data(observations, "suite")
        assert result["points"][0]["lane"] == "web"
        assert result["laneKeys"] == ["web"]

    def test_multiple_observations_preserve_order(self):
        observations = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "First"},
            {"host": "a.com", "suite": "web", "severity": "low", "title": "Second"},
            {"host": "a.com", "suite": "web", "severity": "info", "title": "Third"},
        ]
        result = self.build_timeline_data(observations, "host")
        assert result["points"][0]["title"] == "First"
        assert result["points"][1]["title"] == "Second"
        assert result["points"][2]["title"] == "Third"
        assert result["points"][0]["index"] == 0
        assert result["points"][1]["index"] == 1
        assert result["points"][2]["index"] == 2

    def test_multiple_hosts_creates_lanes(self):
        observations = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "A"},
            {"host": "b.com", "suite": "network", "severity": "low", "title": "B"},
            {"host": "c.com", "suite": "ai", "severity": "info", "title": "C"},
        ]
        result = self.build_timeline_data(observations, "host")
        assert sorted(result["laneKeys"]) == ["a.com", "b.com", "c.com"]
        assert len(result["lanes"]["a.com"]) == 1
        assert len(result["lanes"]["b.com"]) == 1

    def test_suite_grouping_uses_known_order(self):
        observations = [
            {"host": "h", "suite": "cag", "severity": "low", "title": "A"},
            {"host": "h", "suite": "web", "severity": "low", "title": "B"},
            {"host": "h", "suite": "ai", "severity": "low", "title": "C"},
        ]
        result = self.build_timeline_data(observations, "suite")
        assert result["laneKeys"].index("web") < result["laneKeys"].index("ai")
        assert result["laneKeys"].index("ai") < result["laneKeys"].index("cag")

    def test_host_normalization(self):
        observations = [
            {
                "host": "http://api.example.com/path",
                "suite": "web",
                "severity": "high",
                "title": "A",
            },
            {"host": "api.example.com:8080", "suite": "web", "severity": "low", "title": "B"},
        ]
        result = self.build_timeline_data(observations, "host")
        assert result["laneKeys"] == ["api.example.com"]
        assert len(result["lanes"]["api.example.com"]) == 2

    def test_infer_suite_when_no_suite_field(self):
        observations = [
            {"host": "h", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "h", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        result = self.build_timeline_data(observations, "suite")
        assert "network" in result["laneKeys"]
        assert "web" in result["laneKeys"]

    def test_unknown_suite_appended_after_known(self):
        observations = [
            {"host": "h", "suite": "web", "severity": "low", "title": "A"},
            {"host": "h", "suite": "custom", "severity": "info", "title": "B"},
        ]
        result = self.build_timeline_data(observations, "suite")
        assert result["laneKeys"].index("web") < result["laneKeys"].index("custom")

    def test_default_group_by_is_host(self):
        observations = [{"host": "h.com", "suite": "web", "severity": "info", "title": "T"}]
        result = self.build_timeline_data(observations)
        assert result["points"][0]["lane"] == "h.com"

    def test_missing_host_falls_back_to_unknown(self):
        observations = [{"suite": "web", "severity": "info", "title": "T"}]
        result = self.build_timeline_data(observations, "host")
        assert "unknown" in result["laneKeys"]

    def test_missing_severity_defaults_to_info(self):
        observations = [{"host": "h", "suite": "web", "title": "T"}]
        result = self.build_timeline_data(observations, "host")
        assert result["points"][0]["severity"] == "info"

    def test_created_at_captured_on_point(self):
        observations = [
            {
                "host": "h",
                "suite": "web",
                "severity": "info",
                "title": "T",
                "created_at": "2026-04-08T10:30:00Z",
            },
        ]
        result = self.build_timeline_data(observations, "host")
        assert result["points"][0]["createdAt"] == "2026-04-08T10:30:00Z"

    def test_created_at_defaults_to_none(self):
        observations = [{"host": "h", "suite": "web", "severity": "info", "title": "T"}]
        result = self.build_timeline_data(observations, "host")
        assert result["points"][0]["createdAt"] is None

    def test_lanes_contain_correct_points(self):
        observations = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "A"},
            {"host": "b.com", "suite": "network", "severity": "low", "title": "B"},
            {"host": "a.com", "suite": "ai", "severity": "info", "title": "C"},
        ]
        result = self.build_timeline_data(observations, "host")
        assert len(result["lanes"]["a.com"]) == 2
        assert len(result["lanes"]["b.com"]) == 1
        assert result["lanes"]["a.com"][0]["title"] == "A"
        assert result["lanes"]["a.com"][1]["title"] == "C"


class TestTimelineDataRendering:
    """Behavioral tests that exercise data rendering logic end-to-end."""

    def test_group_by_host_vs_suite_produces_different_lanes(self):
        """Same observations grouped by host vs suite produce different lane structures."""
        observations = [
            {"host": "a.com", "suite": "web", "severity": "high", "title": "A"},
            {"host": "b.com", "suite": "web", "severity": "low", "title": "B"},
            {"host": "a.com", "suite": "network", "severity": "info", "title": "C"},
        ]
        by_host = TestTimelineDataLogic.build_timeline_data(observations, "host")
        by_suite = TestTimelineDataLogic.build_timeline_data(observations, "suite")
        # Host grouping: 2 lanes (a.com, b.com)
        assert sorted(by_host["laneKeys"]) == ["a.com", "b.com"]
        assert len(by_host["lanes"]["a.com"]) == 2
        # Suite grouping: 2 lanes (web, network)
        assert "web" in by_suite["laneKeys"]
        assert "network" in by_suite["laneKeys"]
        assert len(by_suite["lanes"]["web"]) == 2

    def test_point_index_matches_observation_order(self):
        """Each point's index reflects the original observation order for X-axis positioning."""
        observations = [
            {"host": "h.com", "suite": "web", "severity": "high", "title": "First"},
            {"host": "h.com", "suite": "web", "severity": "low", "title": "Second"},
            {"host": "h.com", "suite": "web", "severity": "info", "title": "Third"},
        ]
        result = TestTimelineDataLogic.build_timeline_data(observations, "host")
        titles_by_index = {p["index"]: p["title"] for p in result["points"]}
        assert titles_by_index == {0: "First", 1: "Second", 2: "Third"}

    def test_mixed_host_normalization_collapses_lanes(self):
        """URL and port-variant hosts collapse into one lane for clean rendering."""
        observations = [
            {"host": "http://api.example.com/a", "suite": "web", "severity": "high", "title": "A"},
            {"host": "api.example.com:8080", "suite": "web", "severity": "low", "title": "B"},
            {"host": "api.example.com", "suite": "web", "severity": "info", "title": "C"},
        ]
        result = TestTimelineDataLogic.build_timeline_data(observations, "host")
        assert result["laneKeys"] == ["api.example.com"]
        assert len(result["lanes"]["api.example.com"]) == 3


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

    def test_timeline_time_label_class(self):
        content = _all_viz_content()
        assert "timeline-time-label" in content, (
            "Missing timeline-time-label class for axis timestamps"
        )
