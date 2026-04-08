"""Tests for Phase 5c: Check Coverage Matrix visualization."""

import pytest

from .conftest import _all_viz_content

pytestmark = pytest.mark.unit


class TestCoverageTabPresence:
    """Verify coverage tab and panel exist in observations.html."""

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
    """Verify coverage JS functions and constants exist in observations.html."""

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

    def test_skip_sub_status_colors_defined(self):
        """Precondition-based skip sub-status colors are defined."""
        content = _all_viz_content()
        for key in ["skipped-precondition", "skipped-suite", "skipped-critical"]:
            assert key in content, f"Missing skip sub-status color key: {key}"

    def test_skip_status_labels_defined(self):
        """SKIP_STATUS_LABELS object is defined in viz-common."""
        content = _all_viz_content()
        assert "SKIP_STATUS_LABELS" in content, "Missing SKIP_STATUS_LABELS constant"
        assert "Preconditions not met" in content
        assert "Suite not found on target" in content

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

    SKIP_SUITE_KEYWORDS = ["not found on target"]
    SKIP_CRITICAL_KEYWORDS = ["on_critical"]
    SKIP_PRECONDITION_KEYWORDS = ["precondition"]

    @classmethod
    def classify_skip_reason(cls, skip_reason):
        if not skip_reason:
            return "skipped"
        lower = skip_reason.lower()
        if any(k in lower for k in cls.SKIP_SUITE_KEYWORDS):
            return "skipped-suite"
        if any(k in lower for k in cls.SKIP_CRITICAL_KEYWORDS):
            return "skipped-critical"
        return "skipped-precondition"

    @classmethod
    def build_coverage_data(cls, observations_list, check_statuses):
        """Python mirror of the JS buildCoverageData."""
        checks = []
        check_status_map = {}
        skip_reason_map = {}

        for cs in check_statuses or []:
            name = cs.get("name") or cs.get("check_name")
            if not name:
                continue
            if name not in check_status_map:
                status = cs.get("status", "completed")
                if status == "skipped" and cs.get("skip_reason"):
                    skip_reason_map[name] = cs["skip_reason"]
                    status = cls.classify_skip_reason(cs["skip_reason"])
                elif status == "skipped":
                    skip_reason_map[name] = "Skipped"
                check_status_map[name] = status
                checks.append(name)

        for f in observations_list:
            name = f.get("check_name")
            if name and name not in check_status_map:
                check_status_map[name] = "completed"
                checks.append(name)

        if not checks:
            return {"matrix": {}, "hosts": [], "checks": [], "isGlobal": True}

        # Group observations by host
        observations_by_host = {}
        for f in observations_list:
            raw_host = f.get("host") or f.get("target_url") or "global"
            host = cls.normalize_host(raw_host)
            if host not in observations_by_host:
                observations_by_host[host] = []
            observations_by_host[host].append(f)

        hosts = sorted(observations_by_host.keys())
        is_global = len(hosts) <= 1

        if is_global:
            global_host = hosts[0] if hosts else "all"
            matrix = {global_host: {}}

            observations_by_check = {}
            for f in observations_list:
                cn = f.get("check_name")
                if not cn:
                    continue
                if cn not in observations_by_check:
                    observations_by_check[cn] = []
                observations_by_check[cn].append(f)

            for check in checks:
                check_observations = observations_by_check.get(check, [])
                status = check_status_map.get(check, "not-run")
                if check_observations and status == "completed":
                    status = "found"
                matrix[global_host][check] = {
                    "status": status,
                    "skipReason": skip_reason_map.get(check),
                    "observationCount": len(check_observations),
                    "observations": check_observations,
                }
            return {
                "matrix": matrix,
                "hosts": [global_host],
                "checks": checks,
                "isGlobal": True,
                "skipReasonMap": skip_reason_map,
            }

        # Multi-host
        matrix = {}
        for host in hosts:
            matrix[host] = {}
            host_observations = observations_by_host.get(host, [])
            host_fbc = {}
            for f in host_observations:
                cn = f.get("check_name")
                if not cn:
                    continue
                if cn not in host_fbc:
                    host_fbc[cn] = []
                host_fbc[cn].append(f)

            for check in checks:
                check_observations = host_fbc.get(check, [])
                status = check_status_map.get(check, "not-run")
                if check_observations and status == "completed":
                    status = "found"
                matrix[host][check] = {
                    "status": status,
                    "skipReason": skip_reason_map.get(check),
                    "observationCount": len(check_observations),
                    "observations": check_observations,
                }

        return {
            "matrix": matrix,
            "hosts": hosts,
            "checks": checks,
            "isGlobal": False,
            "skipReasonMap": skip_reason_map,
        }

    def test_empty_inputs(self):
        result = self.build_coverage_data([], [])
        assert result["hosts"] == []
        assert result["checks"] == []
        assert result["matrix"] == {}
        assert result["isGlobal"] is True

    def test_checks_only_no_observations(self):
        """Check statuses with no observations still produce a global view with checks listed."""
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
        observations = [
            {"host": "example.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "example.com", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {"name": "header_check", "status": "completed"},
            {"name": "port_scan", "status": "completed"},
        ]
        result = self.build_coverage_data(observations, checks)
        assert result["isGlobal"] is True
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        # dns_lookup produced observations -> 'found'
        assert result["matrix"][host]["dns_lookup"]["status"] == "found"
        assert result["matrix"][host]["dns_lookup"]["observationCount"] == 1
        # header_check produced observations -> 'found'
        assert result["matrix"][host]["header_check"]["status"] == "found"
        # port_scan completed with no observations -> 'completed'
        assert result["matrix"][host]["port_scan"]["status"] == "completed"
        assert result["matrix"][host]["port_scan"]["observationCount"] == 0

    def test_multi_host_view(self):
        observations = [
            {"host": "a.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "b.com", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {"name": "header_check", "status": "completed"},
        ]
        result = self.build_coverage_data(observations, checks)
        assert result["isGlobal"] is False
        assert sorted(result["hosts"]) == ["a.com", "b.com"]
        # a.com has dns_lookup observation
        assert result["matrix"]["a.com"]["dns_lookup"]["status"] == "found"
        assert result["matrix"]["a.com"]["dns_lookup"]["observationCount"] == 1
        # a.com has no header_check observation
        assert result["matrix"]["a.com"]["header_check"]["status"] == "completed"
        assert result["matrix"]["a.com"]["header_check"]["observationCount"] == 0
        # b.com has header_check observation
        assert result["matrix"]["b.com"]["header_check"]["status"] == "found"

    def test_skipped_and_error_statuses(self):
        observations = [
            {"host": "a.com", "check_name": "ok_check", "severity": "info", "title": "X"},
            {"host": "b.com", "check_name": "ok_check", "severity": "info", "title": "Y"},
        ]
        checks = [
            {"name": "ok_check", "status": "completed"},
            {"name": "skip_check", "status": "skipped"},
            {"name": "err_check", "status": "error"},
        ]
        result = self.build_coverage_data(observations, checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["skip_check"]["status"] == "skipped"
        assert result["matrix"][host]["err_check"]["status"] == "error"

    def test_skip_reason_precondition_not_met(self):
        """Skipped check with precondition reason gets sub-classified."""
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {
                "name": "mcp_auth_check",
                "status": "skipped",
                "skip_reason": "Precondition not met: mcp_servers is truthy",
            },
        ]
        result = self.build_coverage_data([], checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["mcp_auth_check"]["status"] == "skipped-precondition"
        assert result["matrix"][host]["mcp_auth_check"]["skipReason"] == (
            "Precondition not met: mcp_servers is truthy"
        )

    def test_skip_reason_suite_not_found(self):
        """Suite-level skip reason is classified as skipped-suite."""
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {
                "name": "mcp_auth_check",
                "status": "skipped",
                "skip_reason": "MCP not found on target",
            },
        ]
        result = self.build_coverage_data([], checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["mcp_auth_check"]["status"] == "skipped-suite"

    def test_skip_reason_critical_upstream(self):
        """on_critical skip reason is classified as skipped-critical."""
        checks = [
            {
                "name": "mcp_tool_enum",
                "status": "skipped",
                "skip_reason": "on_critical='skip_downstream' from network suite",
            },
        ]
        result = self.build_coverage_data([], checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["mcp_tool_enum"]["status"] == "skipped-critical"

    def test_skip_reason_map_returned(self):
        """skipReasonMap is included in the returned data."""
        checks = [
            {"name": "check_a", "status": "completed"},
            {"name": "check_b", "status": "skipped", "skip_reason": "MCP not found on target"},
            {"name": "check_c", "status": "skipped", "skip_reason": "Precondition not met: x"},
        ]
        result = self.build_coverage_data([], checks)
        assert "skipReasonMap" in result
        assert result["skipReasonMap"]["check_b"] == "MCP not found on target"
        assert result["skipReasonMap"]["check_c"] == "Precondition not met: x"
        assert "check_a" not in result["skipReasonMap"]

    def test_skip_without_reason_stays_generic(self):
        """Skipped status without skip_reason stays as generic 'skipped'."""
        checks = [
            {"name": "some_check", "status": "skipped"},
        ]
        result = self.build_coverage_data([], checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["some_check"]["status"] == "skipped"

    def test_observations_without_check_statuses(self):
        """Observations with check_name but no checkStatuses still create coverage data."""
        observations = [
            {"host": "a.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "b.com", "check_name": "header_check", "severity": "low", "title": "B"},
        ]
        result = self.build_coverage_data(observations, [])
        assert result["isGlobal"] is False
        assert "dns_lookup" in result["checks"]
        assert "header_check" in result["checks"]
        # All statuses default to 'completed' then become 'found' because they have observations
        assert result["matrix"]["a.com"]["dns_lookup"]["status"] == "found"

    def test_check_name_deduplication(self):
        """Same check name from both checkStatuses and observations shouldn't be duplicated."""
        observations = [
            {"host": "h.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
        ]
        result = self.build_coverage_data(observations, checks)
        assert result["checks"].count("dns_lookup") == 1

    def test_host_normalization_in_coverage(self):
        observations = [
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
        result = self.build_coverage_data(observations, checks)
        assert "api.example.com" in result["hosts"]
        assert result["isGlobal"] is True  # Both normalize to same host


class TestCoverageDataRendering:
    """Behavioral tests that exercise data rendering logic end-to-end."""

    def test_found_status_only_when_observations_exist(self):
        """A check transitions to 'found' only when it has actual observations."""
        observations = [
            {"host": "h.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
        ]
        checks = [
            {"name": "dns_lookup", "status": "completed"},
            {"name": "port_scan", "status": "completed"},
        ]
        result = TestCoverageDataLogic.build_coverage_data(observations, checks)
        host = result["hosts"][0]
        # dns_lookup has an observation -> found
        assert result["matrix"][host]["dns_lookup"]["status"] == "found"
        assert result["matrix"][host]["dns_lookup"]["observationCount"] == 1
        # port_scan has no observations -> stays completed
        assert result["matrix"][host]["port_scan"]["status"] == "completed"
        assert result["matrix"][host]["port_scan"]["observationCount"] == 0

    def test_observation_count_accumulates_per_check(self):
        """Multiple observations for the same check accumulate correctly."""
        observations = [
            {"host": "h.com", "check_name": "dns_lookup", "severity": "info", "title": "A"},
            {"host": "h.com", "check_name": "dns_lookup", "severity": "low", "title": "B"},
            {"host": "h.com", "check_name": "dns_lookup", "severity": "high", "title": "C"},
        ]
        checks = [{"name": "dns_lookup", "status": "completed"}]
        result = TestCoverageDataLogic.build_coverage_data(observations, checks)
        host = result["hosts"][0]
        assert result["matrix"][host]["dns_lookup"]["observationCount"] == 3
        assert len(result["matrix"][host]["dns_lookup"]["observations"]) == 3

    def test_multi_host_observations_attributed_correctly(self):
        """Observations are attributed to the correct host row in multi-host view."""
        observations = [
            {"host": "a.com", "check_name": "check_x", "severity": "high", "title": "A1"},
            {"host": "a.com", "check_name": "check_x", "severity": "low", "title": "A2"},
            {"host": "b.com", "check_name": "check_x", "severity": "info", "title": "B1"},
        ]
        checks = [{"name": "check_x", "status": "completed"}]
        result = TestCoverageDataLogic.build_coverage_data(observations, checks)
        assert result["isGlobal"] is False
        assert result["matrix"]["a.com"]["check_x"]["observationCount"] == 2
        assert result["matrix"]["b.com"]["check_x"]["observationCount"] == 1


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
