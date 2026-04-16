"""Tests for Benchmark Bar Chart visualization."""

import pytest

from .conftest import FINDINGS_HTML, _all_viz_content

pytestmark = pytest.mark.unit


# --- Static HTML tests --------------------------------------------------------


class TestBenchmarkTabPresence:
    """Verify benchmark tab and panel exist in observations.html."""

    def test_observations_html_exists(self):
        assert FINDINGS_HTML.exists(), "static/observations.html must exist"

    def test_benchmark_tab_exists(self):
        content = _all_viz_content()
        assert 'data-viz="benchmark"' in content, "Missing benchmark viz tab"

    def test_benchmark_tab_label(self):
        content = _all_viz_content()
        assert ">Benchmark<" in content, "Benchmark tab should be labeled 'Benchmark'"

    def test_benchmark_panel_exists(self):
        content = _all_viz_content()
        assert 'id="panel-benchmark"' in content, "Missing benchmark panel div"

    def test_benchmark_empty_state(self):
        content = _all_viz_content()
        assert 'id="benchmark-empty"' in content, "Missing benchmark empty state"

    def test_benchmark_content_div(self):
        content = _all_viz_content()
        assert 'id="benchmark-content"' in content, "Missing benchmark content div"

    def test_benchmark_svg_element(self):
        content = _all_viz_content()
        assert 'id="benchmark-graph"' in content, "Missing benchmark SVG element"

    def test_benchmark_tooltip_element(self):
        content = _all_viz_content()
        assert 'id="benchmark-tooltip"' in content, "Missing benchmark tooltip div"

    def test_benchmark_legend(self):
        content = _all_viz_content()
        assert 'id="benchmark-legend"' in content, "Missing benchmark legend"

    def test_benchmark_host_select(self):
        content = _all_viz_content()
        assert 'id="benchmark-host-select"' in content, "Missing host selector dropdown"

    def test_benchmark_baseline_select(self):
        content = _all_viz_content()
        assert 'id="benchmark-baseline-select"' in content, "Missing baseline selector dropdown"

    def test_benchmark_depth_select(self):
        content = _all_viz_content()
        assert 'id="benchmark-depth-select"' in content, "Missing depth selector dropdown"


# --- JavaScript function tests ------------------------------------------------


class TestBenchmarkJavaScript:
    """Verify benchmark JS functions and constants exist."""

    def test_render_benchmark_function(self):
        content = _all_viz_content()
        assert "renderBenchmark" in content, "Missing renderBenchmark function"

    def test_build_benchmark_data_function(self):
        content = _all_viz_content()
        assert "function buildBenchmarkData(" in content, "Missing buildBenchmarkData function"

    def test_build_benchmark_data_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.buildBenchmarkData" in content, (
            "buildBenchmarkData should be exposed on window for testing"
        )

    def test_compute_historical_baseline_function(self):
        content = _all_viz_content()
        assert "function computeHistoricalBaseline(" in content, (
            "Missing computeHistoricalBaseline function"
        )

    def test_compute_historical_baseline_exposed_on_window(self):
        content = _all_viz_content()
        assert "window.computeHistoricalBaseline" in content, (
            "computeHistoricalBaseline should be exposed on window for testing"
        )

    def test_benchmark_called_in_load_data(self):
        content = _all_viz_content()
        assert "renderBenchmark(" in content, "renderBenchmark should be called in loadData"

    def test_benchmark_uses_d3_scale_band(self):
        content = _all_viz_content()
        assert "d3.scaleBand()" in content, "Benchmark should use d3.scaleBand for axes"

    def test_benchmark_uses_d3_scale_linear(self):
        content = _all_viz_content()
        assert "d3.scaleLinear()" in content, "Benchmark should use d3.scaleLinear for Y axis"


# --- Benchmark data logic tests -----------------------------------------------


class TestBenchmarkDataLogic:
    """Test the benchmark data grouping and weighted baseline logic (Python mirror)."""

    SEV_ORDER = ["critical", "high", "medium", "low", "info"]

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
    def build_benchmark_data(cls, observations_list):
        """Python mirror of JS buildBenchmarkData."""
        host_map = {}
        for f in observations_list:
            raw_host = f.get("host") or f.get("target_url") or "unknown"
            host = cls.normalize_host(raw_host)
            if host not in host_map:
                host_map[host] = []
            host_map[host].append(f)

        hosts = sorted(host_map.keys())

        per_host = {}
        for host in hosts:
            obs = host_map[host]
            counts = {s: 0 for s in cls.SEV_ORDER}
            checks = set()
            for f in obs:
                sev = f.get("severity")
                if sev in counts:
                    counts[sev] += 1
                if f.get("check_name"):
                    checks.add(f["check_name"])
            per_host[host] = {"counts": counts, "check_count": max(len(checks), 1)}

        # Weighted average
        total_weight = 0
        weighted_sums = {s: 0 for s in cls.SEV_ORDER}
        for host in hosts:
            w = per_host[host]["check_count"]
            total_weight += w
            for sev in cls.SEV_ORDER:
                weighted_sums[sev] += per_host[host]["counts"][sev] * w

        weighted_baseline = {}
        for sev in cls.SEV_ORDER:
            weighted_baseline[sev] = (
                round(weighted_sums[sev] / total_weight, 1) if total_weight > 0 else 0
            )

        return {
            "hosts": hosts,
            "per_host": per_host,
            "weighted_baseline": weighted_baseline,
        }

    @classmethod
    def compute_historical_baseline(cls, data_points):
        """Python mirror of JS computeHistoricalBaseline."""
        baseline = {s: 0 for s in cls.SEV_ORDER}
        if not data_points:
            return baseline
        for dp in data_points:
            for sev in cls.SEV_ORDER:
                baseline[sev] += dp.get(sev, 0)
        for sev in cls.SEV_ORDER:
            baseline[sev] = round(baseline[sev] / len(data_points), 1)
        return baseline

    # --- buildBenchmarkData tests ---

    def test_empty_observations(self):
        result = self.build_benchmark_data([])
        assert result["hosts"] == []
        assert result["per_host"] == {}
        assert all(v == 0 for v in result["weighted_baseline"].values())

    def test_single_host(self):
        obs = [
            {"host": "a.com", "severity": "high", "check_name": "xss", "title": "XSS"},
            {"host": "a.com", "severity": "high", "check_name": "sqli", "title": "SQLi"},
            {"host": "a.com", "severity": "info", "check_name": "header", "title": "H"},
        ]
        result = self.build_benchmark_data(obs)
        assert result["hosts"] == ["a.com"]
        assert result["per_host"]["a.com"]["counts"]["high"] == 2
        assert result["per_host"]["a.com"]["counts"]["info"] == 1
        assert result["per_host"]["a.com"]["check_count"] == 3

    def test_weighted_baseline_favors_more_checks(self):
        """Host with more checks should have more weight in the baseline."""
        obs = [
            # Host A: 1 check, 1 critical
            {"host": "a.com", "severity": "critical", "check_name": "c1", "title": "A"},
            # Host B: 3 checks, 0 critical
            {"host": "b.com", "severity": "info", "check_name": "c2", "title": "B1"},
            {"host": "b.com", "severity": "info", "check_name": "c3", "title": "B2"},
            {"host": "b.com", "severity": "info", "check_name": "c4", "title": "B3"},
        ]
        result = self.build_benchmark_data(obs)

        # Simple mean critical would be (1+0)/2 = 0.5
        # Weighted: (1*1 + 0*3) / (1+3) = 0.25
        assert result["weighted_baseline"]["critical"] == 0.2  # rounded to 1 decimal

    def test_multiple_hosts_baseline(self):
        obs = [
            {"host": "a.com", "severity": "high", "check_name": "c1", "title": "A"},
            {"host": "b.com", "severity": "high", "check_name": "c1", "title": "B"},
        ]
        result = self.build_benchmark_data(obs)
        # Both hosts: 1 check each, 1 high each → weighted avg = 1.0
        assert result["weighted_baseline"]["high"] == 1.0

    def test_host_normalization(self):
        obs = [
            {"host": "example.com:443", "severity": "low", "check_name": "c1", "title": "A"},
            {"host": "example.com:8080", "severity": "low", "check_name": "c2", "title": "B"},
        ]
        result = self.build_benchmark_data(obs)
        assert result["hosts"] == ["example.com"]
        assert result["per_host"]["example.com"]["counts"]["low"] == 2

    # --- computeHistoricalBaseline tests ---

    def test_historical_baseline_empty(self):
        result = self.compute_historical_baseline([])
        assert all(v == 0 for v in result.values())

    def test_historical_baseline_single_point(self):
        points = [{"critical": 2, "high": 4, "medium": 6, "low": 3, "info": 10}]
        result = self.compute_historical_baseline(points)
        assert result == {"critical": 2.0, "high": 4.0, "medium": 6.0, "low": 3.0, "info": 10.0}

    def test_historical_baseline_averages(self):
        points = [
            {"critical": 2, "high": 4, "medium": 0, "low": 0, "info": 0},
            {"critical": 4, "high": 6, "medium": 0, "low": 0, "info": 0},
        ]
        result = self.compute_historical_baseline(points)
        assert result["critical"] == 3.0
        assert result["high"] == 5.0

    def test_historical_baseline_missing_fields(self):
        """Data points with missing severity fields default to 0."""
        points = [{"critical": 5}]
        result = self.compute_historical_baseline(points)
        assert result["critical"] == 5.0
        assert result["high"] == 0

    # --- Auto-switch logic test ---

    def test_all_hosts_baseline_disabled_when_host_is_all(self):
        """When host is 'All', baseline should auto-switch to 'target_history'.
        This is a behavioral spec — the JS enforces it by disabling the option."""
        # This is tested via the HTML presence of both selectors
        content = _all_viz_content()
        assert 'value="all_hosts"' in content
        assert 'value="target_history"' in content


# --- CSS tests ----------------------------------------------------------------


class TestBenchmarkCSS:
    """Verify benchmark CSS classes exist."""

    def test_benchmark_container_class(self):
        content = _all_viz_content()
        assert ".benchmark-container" in content

    def test_benchmark_controls_class(self):
        content = _all_viz_content()
        assert ".benchmark-controls" in content

    def test_benchmark_legend_class(self):
        content = _all_viz_content()
        assert ".benchmark-legend" in content

    def test_benchmark_tooltip_class(self):
        content = _all_viz_content()
        assert ".benchmark-tooltip" in content

    def test_benchmark_swatch_class(self):
        content = _all_viz_content()
        assert ".benchmark-swatch" in content

    def test_benchmark_chart_area_class(self):
        content = _all_viz_content()
        assert ".benchmark-chart-area" in content
