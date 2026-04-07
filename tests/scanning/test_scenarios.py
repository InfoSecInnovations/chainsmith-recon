"""Tests for scenario model, parsing, and file loading."""

import json
from pathlib import Path

import pytest

from app.scenarios import (
    Scenario,
    ScenarioLoadError,
    ScenarioTarget,
    _parse_scenario,
    find_scenario_file,
    load_scenario_file,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# ScenarioTarget Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioTarget:
    """Tests for ScenarioTarget dataclass."""

    def test_default_values(self):
        """Defaults are empty."""
        target = ScenarioTarget()

        assert target.pattern == ""
        assert target.known_hosts == []
        assert target.ports == []
        assert target.notes == ""

    def test_custom_values(self):
        """Custom values are stored."""
        target = ScenarioTarget(
            pattern="*.example.local",
            known_hosts=["api.example.local", "www.example.local"],
            ports=[8080, 8443],
            notes="Test notes",
        )

        assert target.pattern == "*.example.local"
        assert len(target.known_hosts) == 2
        assert 8080 in target.ports


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenario:
    """Tests for Scenario dataclass."""

    def test_minimal_scenario(self):
        """Minimal scenario with just name."""
        scenario = Scenario(name="test-scenario")

        assert scenario.name == "test-scenario"
        assert scenario.description == ""
        assert scenario.version == "1.0.0"
        assert scenario.simulations == []

    def test_directory_property(self, tmp_path: Path):
        """directory property returns parent of source_path."""
        source = tmp_path / "scenarios" / "test" / "scenario.json"
        scenario = Scenario(name="test", source_path=source)

        assert scenario.directory == tmp_path / "scenarios" / "test"

    def test_directory_none_without_source(self):
        """directory is None without source_path."""
        scenario = Scenario(name="test")

        assert scenario.directory is None

    def test_to_dict(self, tmp_path: Path):
        """to_dict includes all fields."""
        source = tmp_path / "scenario.json"
        scenario = Scenario(
            name="test-scenario",
            description="A test",
            version="2.0.0",
            target=ScenarioTarget(pattern="*.test.local"),
            simulations=["network/dns.yaml"],
            expected_observations=["observation-1"],
            expected_chains=["chain-1"],
            source_path=source,
        )

        d = scenario.to_dict()

        assert d["name"] == "test-scenario"
        assert d["description"] == "A test"
        assert d["version"] == "2.0.0"
        assert d["target"]["pattern"] == "*.test.local"
        assert "network/dns.yaml" in d["simulations"]
        assert "observation-1" in d["expected_observations"]
        assert str(source) in d["source_path"]


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario Parsing Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseScenario:
    """Tests for _parse_scenario function."""

    def test_parse_minimal(self, tmp_path: Path):
        """Minimal valid JSON is parsed."""
        data = {"name": "minimal"}
        source = tmp_path / "scenario.json"

        scenario = _parse_scenario(data, source)

        assert scenario.name == "minimal"
        assert scenario.source_path == source

    def test_parse_full(self, tmp_path: Path):
        """Full JSON with all fields is parsed."""
        data = {
            "name": "full-scenario",
            "description": "Full test scenario",
            "version": "1.2.3",
            "target": {
                "pattern": "*.example.local",
                "known_hosts": ["api.example.local"],
                "ports": [8080, 8443],
                "notes": "Test target",
            },
            "simulations": ["network/dns.yaml", "web/headers.yaml"],
            "expected_observations": ["observation-1", "observation-2"],
            "expected_chains": ["chain-1"],
        }
        source = tmp_path / "scenario.json"

        scenario = _parse_scenario(data, source)

        assert scenario.name == "full-scenario"
        assert scenario.description == "Full test scenario"
        assert scenario.version == "1.2.3"
        assert scenario.target.pattern == "*.example.local"
        assert len(scenario.target.known_hosts) == 1
        assert len(scenario.simulations) == 2

    def test_parse_missing_name_raises(self, tmp_path: Path):
        """Missing name raises ScenarioLoadError."""
        data = {"description": "No name"}
        source = tmp_path / "scenario.json"

        with pytest.raises(ScenarioLoadError, match="non-empty 'name'"):
            _parse_scenario(data, source)

    def test_parse_empty_name_raises(self, tmp_path: Path):
        """Empty name raises ScenarioLoadError."""
        data = {"name": ""}
        source = tmp_path / "scenario.json"

        with pytest.raises(ScenarioLoadError, match="non-empty 'name'"):
            _parse_scenario(data, source)

    def test_parse_non_dict_raises(self, tmp_path: Path):
        """Non-dict data raises ScenarioLoadError."""
        source = tmp_path / "scenario.json"

        with pytest.raises(ScenarioLoadError, match="must be an object"):
            _parse_scenario(["not", "a", "dict"], source)

    def test_parse_invalid_simulations_raises(self, tmp_path: Path):
        """Non-list simulations raises ScenarioLoadError."""
        data = {"name": "test", "simulations": "not-a-list"}
        source = tmp_path / "scenario.json"

        with pytest.raises(ScenarioLoadError, match="must be a list"):
            _parse_scenario(data, source)


# ═══════════════════════════════════════════════════════════════════════════════
# load_scenario_file Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLoadScenarioFile:
    """Tests for load_scenario_file function."""

    def test_load_from_json_file(self, tmp_path: Path):
        """Load scenario from JSON file path."""
        scenario_file = tmp_path / "scenario.json"
        scenario_file.write_text(json.dumps({"name": "from-file"}))

        scenario = load_scenario_file(scenario_file)

        assert scenario.name == "from-file"
        assert scenario.source_path == scenario_file

    def test_load_from_directory(self, tmp_path: Path):
        """Load scenario from directory containing scenario.json."""
        scenario_dir = tmp_path / "my-scenario"
        scenario_dir.mkdir()
        (scenario_dir / "scenario.json").write_text(json.dumps({"name": "from-dir"}))

        scenario = load_scenario_file(scenario_dir)

        assert scenario.name == "from-dir"

    def test_load_missing_file_raises(self, tmp_path: Path):
        """Missing file raises ScenarioLoadError."""
        with pytest.raises(ScenarioLoadError, match="not found"):
            load_scenario_file(tmp_path / "missing.json")

    def test_load_invalid_json_raises(self, tmp_path: Path):
        """Invalid JSON raises ScenarioLoadError."""
        scenario_file = tmp_path / "bad.json"
        scenario_file.write_text("not valid json {")

        with pytest.raises(ScenarioLoadError, match="Invalid JSON"):
            load_scenario_file(scenario_file)


# ═══════════════════════════════════════════════════════════════════════════════
# find_scenario_file Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindScenarioFile:
    """Tests for find_scenario_file function."""

    def test_find_by_name_in_search_dirs(self, tmp_path: Path):
        """Find scenario by name in search directories."""
        scenarios_dir = tmp_path / "scenarios"
        scenario_bundle = scenarios_dir / "test-scenario"
        scenario_bundle.mkdir(parents=True)
        (scenario_bundle / "scenario.json").write_text(json.dumps({"name": "test-scenario"}))

        result = find_scenario_file("test-scenario", search_dirs=[scenarios_dir])

        assert result == scenario_bundle

    def test_find_explicit_path(self, tmp_path: Path):
        """Find scenario by explicit directory path."""
        scenario_bundle = tmp_path / "explicit-scenario"
        scenario_bundle.mkdir()
        (scenario_bundle / "scenario.json").write_text(json.dumps({"name": "explicit"}))

        result = find_scenario_file(str(scenario_bundle))

        assert result == scenario_bundle

    def test_find_not_found_raises(self, tmp_path: Path):
        """Missing scenario raises ScenarioLoadError."""
        with pytest.raises(ScenarioLoadError, match="not found"):
            find_scenario_file("nonexistent", search_dirs=[tmp_path])

    def test_find_searches_multiple_dirs(self, tmp_path: Path):
        """Searches multiple directories in order."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir2.mkdir()

        # Scenario only in dir2
        scenario_bundle = dir2 / "my-scenario"
        scenario_bundle.mkdir()
        (scenario_bundle / "scenario.json").write_text(json.dumps({"name": "my-scenario"}))

        result = find_scenario_file("my-scenario", search_dirs=[dir1, dir2])

        assert result == scenario_bundle
