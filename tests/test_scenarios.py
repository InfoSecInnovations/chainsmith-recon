"""
Tests for app/scenarios.py

Covers:
- ScenarioTarget and Scenario dataclasses
- Scenario parsing from JSON
- load_scenario_file (from directory or file)
- find_scenario_file (search paths)
- ScenarioManager (load, clear, get_simulations, list_available)
- get_scenario_manager singleton
- Error handling (ScenarioLoadError)
"""

import json
from pathlib import Path

import pytest

from app.scenarios import (
    Scenario,
    ScenarioLoadError,
    ScenarioManager,
    ScenarioTarget,
    _parse_scenario,
    find_scenario_file,
    get_scenario_manager,
    load_scenario_file,
)

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
            expected_findings=["finding-1"],
            expected_chains=["chain-1"],
            source_path=source,
        )

        d = scenario.to_dict()

        assert d["name"] == "test-scenario"
        assert d["description"] == "A test"
        assert d["version"] == "2.0.0"
        assert d["target"]["pattern"] == "*.test.local"
        assert "network/dns.yaml" in d["simulations"]
        assert "finding-1" in d["expected_findings"]
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
            "expected_findings": ["finding-1", "finding-2"],
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


# ═══════════════════════════════════════════════════════════════════════════════
# ScenarioManager Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioManager:
    """Tests for ScenarioManager class."""

    def test_init_no_active(self, tmp_path: Path):
        """Manager starts with no active scenario."""
        mgr = ScenarioManager(scenarios_dirs=[tmp_path])

        assert mgr.active is None
        assert mgr.is_active is False

    def test_load_scenario(self, tmp_path: Path):
        """load() activates a scenario."""
        # Create scenario bundle
        scenario_bundle = tmp_path / "test-scenario"
        scenario_bundle.mkdir()
        (scenario_bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test-scenario",
                    "description": "Test",
                    "simulations": [],
                }
            )
        )

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        scenario = mgr.load("test-scenario")

        assert mgr.active is scenario
        assert mgr.is_active is True
        assert scenario.name == "test-scenario"

    def test_load_replaces_previous(self, tmp_path: Path):
        """load() replaces any previous active scenario."""
        # Create two scenario bundles
        for name in ["scenario-1", "scenario-2"]:
            bundle = tmp_path / name
            bundle.mkdir()
            (bundle / "scenario.json").write_text(json.dumps({"name": name}))

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        mgr.load("scenario-1")
        assert mgr.active.name == "scenario-1"

        mgr.load("scenario-2")
        assert mgr.active.name == "scenario-2"

    def test_clear_deactivates(self, tmp_path: Path):
        """clear() deactivates the scenario."""
        bundle = tmp_path / "test"
        bundle.mkdir()
        (bundle / "scenario.json").write_text(json.dumps({"name": "test"}))

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        mgr.load("test")
        assert mgr.is_active is True

        mgr.clear()
        assert mgr.active is None
        assert mgr.is_active is False
        assert mgr.get_simulations() == []

    def test_get_simulations_empty_when_no_simulations(self, tmp_path: Path):
        """get_simulations returns empty list for scenario with no simulations."""
        bundle = tmp_path / "test"
        bundle.mkdir()
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test",
                    "simulations": [],
                }
            )
        )

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        mgr.load("test")

        assert mgr.get_simulations() == []

    def test_list_available_finds_scenarios(self, tmp_path: Path):
        """list_available returns all discoverable scenarios."""
        for name in ["scenario-a", "scenario-b"]:
            bundle = tmp_path / name
            bundle.mkdir()
            (bundle / "scenario.json").write_text(
                json.dumps(
                    {
                        "name": name,
                        "description": f"Description for {name}",
                        "version": "1.0.0",
                        "simulations": ["a.yaml", "b.yaml"],
                    }
                )
            )

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        available = mgr.list_available()

        assert len(available) == 2
        names = {s["name"] for s in available}
        assert "scenario-a" in names
        assert "scenario-b" in names

        # Check structure
        for item in available:
            assert "name" in item
            assert "description" in item
            assert "version" in item
            assert "simulation_count" in item
            assert item["simulation_count"] == 2

    def test_list_available_skips_invalid(self, tmp_path: Path):
        """list_available skips invalid scenario bundles."""
        # Valid scenario
        valid = tmp_path / "valid"
        valid.mkdir()
        (valid / "scenario.json").write_text(json.dumps({"name": "valid"}))

        # Invalid scenario (missing name)
        invalid = tmp_path / "invalid"
        invalid.mkdir()
        (invalid / "scenario.json").write_text(json.dumps({"description": "no name"}))

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        available = mgr.list_available()

        assert len(available) == 1
        assert available[0]["name"] == "valid"

    def test_list_available_empty_dir(self, tmp_path: Path):
        """list_available returns empty list for empty directory."""
        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        available = mgr.list_available()

        assert available == []

    def test_list_available_missing_dir(self, tmp_path: Path):
        """list_available handles missing directories."""
        mgr = ScenarioManager(scenarios_dirs=[tmp_path / "nonexistent"])
        available = mgr.list_available()

        assert available == []


# ═══════════════════════════════════════════════════════════════════════════════
# ScenarioManager Simulation Loading Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioManagerSimulations:
    """Tests for ScenarioManager simulation loading."""

    def test_load_with_missing_simulations_adds_warning(self, tmp_path: Path):
        """Missing simulation files add warning to description."""
        bundle = tmp_path / "test"
        bundle.mkdir()
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test",
                    "description": "Original description",
                    "simulations": ["nonexistent/missing.yaml"],
                }
            )
        )

        mgr = ScenarioManager(scenarios_dirs=[tmp_path])
        scenario = mgr.load("test")

        assert "[WARNINGS:" in scenario.description
        assert "not found" in scenario.description


# ═══════════════════════════════════════════════════════════════════════════════
# Simulation Precedence Tests (Phase 5)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulationPrecedence:
    """Tests for simulation resolution precedence: scenario-specific > global."""

    def _create_simulation_yaml(self, path: Path, marker: str):
        """Create a minimal simulation YAML with a marker in the disposition."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"""
suite: network
emulates: test_check
target: "test.local"
disposition: {marker}
output:
  hosts: []
""")

    def test_scenario_specific_wins_over_global(self, tmp_path: Path):
        """Scenario-specific simulation takes precedence over global."""
        # Setup directories
        scenarios_dir = tmp_path / "scenarios"
        global_sims_dir = tmp_path / "global_sims"

        # Create scenario bundle
        bundle = scenarios_dir / "test-scenario"
        bundle.mkdir(parents=True)
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test-scenario",
                    "simulations": ["network/dns.yaml"],
                }
            )
        )

        # Create both scenario-specific and global simulations
        self._create_simulation_yaml(
            bundle / "simulations" / "network" / "dns.yaml", marker="scenario_specific"
        )
        self._create_simulation_yaml(global_sims_dir / "network" / "dns.yaml", marker="global")

        # Load scenario
        mgr = ScenarioManager(
            scenarios_dirs=[scenarios_dir],
            global_simulations_dir=global_sims_dir,
        )
        mgr.load("test-scenario")

        # Verify scenario-specific was loaded
        sims = mgr.get_simulations()
        assert len(sims) == 1
        assert sims[0]._config.disposition == "scenario_specific"

    def test_falls_back_to_global_when_scenario_specific_missing(self, tmp_path: Path):
        """Falls back to global simulation when scenario-specific doesn't exist."""
        # Setup directories
        scenarios_dir = tmp_path / "scenarios"
        global_sims_dir = tmp_path / "global_sims"

        # Create scenario bundle WITHOUT scenario-specific simulation
        bundle = scenarios_dir / "test-scenario"
        bundle.mkdir(parents=True)
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test-scenario",
                    "simulations": ["network/dns.yaml"],
                }
            )
        )

        # Create only global simulation
        self._create_simulation_yaml(
            global_sims_dir / "network" / "dns.yaml", marker="global_fallback"
        )

        # Load scenario
        mgr = ScenarioManager(
            scenarios_dirs=[scenarios_dir],
            global_simulations_dir=global_sims_dir,
        )
        mgr.load("test-scenario")

        # Verify global was loaded
        sims = mgr.get_simulations()
        assert len(sims) == 1
        assert sims[0]._config.disposition == "global_fallback"

    def test_mixed_sources(self, tmp_path: Path):
        """Some simulations from scenario-specific, some from global."""
        # Setup directories
        scenarios_dir = tmp_path / "scenarios"
        global_sims_dir = tmp_path / "global_sims"

        # Create scenario bundle
        bundle = scenarios_dir / "test-scenario"
        bundle.mkdir(parents=True)
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test-scenario",
                    "simulations": [
                        "network/dns.yaml",  # scenario-specific
                        "web/headers.yaml",  # global fallback
                    ],
                }
            )
        )

        # Scenario-specific simulation
        self._create_simulation_yaml(
            bundle / "simulations" / "network" / "dns.yaml", marker="scenario_dns"
        )

        # Global simulation (no scenario-specific for this one)
        self._create_simulation_yaml(
            global_sims_dir / "web" / "headers.yaml", marker="global_headers"
        )

        # Load scenario
        mgr = ScenarioManager(
            scenarios_dirs=[scenarios_dir],
            global_simulations_dir=global_sims_dir,
        )
        mgr.load("test-scenario")

        # Verify both loaded from correct sources
        sims = mgr.get_simulations()
        assert len(sims) == 2

        dispositions = {s._config.disposition for s in sims}
        assert "scenario_dns" in dispositions
        assert "global_headers" in dispositions

    def test_error_when_neither_exists(self, tmp_path: Path):
        """Warning added when simulation exists in neither location."""
        # Setup directories
        scenarios_dir = tmp_path / "scenarios"
        global_sims_dir = tmp_path / "global_sims"
        global_sims_dir.mkdir(parents=True)

        # Create scenario bundle referencing non-existent simulation
        bundle = scenarios_dir / "test-scenario"
        bundle.mkdir(parents=True)
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test-scenario",
                    "description": "Original",
                    "simulations": ["nowhere/missing.yaml"],
                }
            )
        )

        # Load scenario
        mgr = ScenarioManager(
            scenarios_dirs=[scenarios_dir],
            global_simulations_dir=global_sims_dir,
        )
        scenario = mgr.load("test-scenario")

        # Verify warning was added
        assert "[WARNINGS:" in scenario.description
        assert "not found" in scenario.description
        assert mgr.get_simulations() == []

    def test_scenario_specific_replaces_not_merges(self, tmp_path: Path):
        """Scenario-specific completely replaces global, doesn't merge fields."""
        # Setup directories
        scenarios_dir = tmp_path / "scenarios"
        global_sims_dir = tmp_path / "global_sims"

        # Create scenario bundle
        bundle = scenarios_dir / "test-scenario"
        bundle.mkdir(parents=True)
        (bundle / "scenario.json").write_text(
            json.dumps(
                {
                    "name": "test-scenario",
                    "simulations": ["network/dns.yaml"],
                }
            )
        )

        # Scenario-specific with different target
        scenario_sim = bundle / "simulations" / "network" / "dns.yaml"
        scenario_sim.parent.mkdir(parents=True, exist_ok=True)
        scenario_sim.write_text("""
suite: network
emulates: dns_enumeration
target: "scenario-target.local"
disposition: scenario_version
output:
  hosts:
    - name: "scenario-host.local"
      port: 8080
""")

        # Global with different target
        global_sim = global_sims_dir / "network" / "dns.yaml"
        global_sim.parent.mkdir(parents=True, exist_ok=True)
        global_sim.write_text("""
suite: network
emulates: dns_enumeration
target: "global-target.local"
disposition: global_version
output:
  hosts:
    - name: "global-host.local"
      port: 9090
""")

        # Load scenario
        mgr = ScenarioManager(
            scenarios_dirs=[scenarios_dir],
            global_simulations_dir=global_sims_dir,
        )
        mgr.load("test-scenario")

        # Verify scenario-specific was loaded (not merged)
        sims = mgr.get_simulations()
        assert len(sims) == 1
        config = sims[0]._config
        assert config.target == "scenario-target.local"
        assert config.disposition == "scenario_version"
        # Should NOT contain global-host
        assert len(config.output.get("hosts", [])) == 1
        assert config.output["hosts"][0]["name"] == "scenario-host.local"


# ═══════════════════════════════════════════════════════════════════════════════
# get_scenario_manager Singleton Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetScenarioManager:
    """Tests for get_scenario_manager singleton."""

    def test_returns_manager(self, clean_env, monkeypatch):
        """get_scenario_manager returns a ScenarioManager."""
        # Reset the singleton
        import app.scenarios

        app.scenarios._manager = None

        mgr = get_scenario_manager()

        assert isinstance(mgr, ScenarioManager)

    def test_returns_same_instance(self, clean_env, monkeypatch):
        """get_scenario_manager returns cached instance."""
        import app.scenarios

        app.scenarios._manager = None

        mgr1 = get_scenario_manager()
        mgr2 = get_scenario_manager()

        assert mgr1 is mgr2

    def test_auto_loads_from_env(self, clean_env, tmp_path: Path, monkeypatch):
        """CHAINSMITH_SCENARIO env var auto-loads scenario."""
        # Create a scenario
        bundle = tmp_path / "auto-scenario"
        bundle.mkdir()
        (bundle / "scenario.json").write_text(json.dumps({"name": "auto-scenario"}))

        # Set env and reset singleton
        monkeypatch.setenv("CHAINSMITH_SCENARIO", "auto-scenario")
        monkeypatch.setenv("CHAINSMITH_SCENARIOS_DIR", str(tmp_path))

        import app.scenarios

        app.scenarios._manager = None

        mgr = get_scenario_manager()

        # Should have auto-loaded
        assert mgr.is_active is True
        assert mgr.active.name == "auto-scenario"


# ═══════════════════════════════════════════════════════════════════════════════
# Integration with Real Scenarios
# ═══════════════════════════════════════════════════════════════════════════════


class TestRealScenarios:
    """Tests using actual scenario files from the project."""

    def test_load_demo_domain(self, scenarios_dir: Path):
        """Load actual demo-domain scenario."""
        demo = scenarios_dir / "demo-domain"

        if not demo.exists():
            pytest.skip("demo-domain scenario not found")

        scenario = load_scenario_file(demo)

        assert scenario.name == "demo-domain"

    def test_load_fakobanko(self, scenarios_dir: Path):
        """Load actual fakobanko scenario."""
        fakobanko = scenarios_dir / "fakobanko"

        if not fakobanko.exists():
            pytest.skip("fakobanko scenario not found")

        scenario = load_scenario_file(fakobanko)

        assert scenario.name == "fakobanko"

    def test_manager_lists_real_scenarios(self, scenarios_dir: Path):
        """ScenarioManager finds real scenarios."""
        if not scenarios_dir.exists():
            pytest.skip("scenarios directory not found")

        mgr = ScenarioManager(scenarios_dirs=[scenarios_dir])
        available = mgr.list_available()

        # Should find at least demo-domain and fakobanko
        {s["name"] for s in available}

        # At least one should exist
        assert len(available) > 0
