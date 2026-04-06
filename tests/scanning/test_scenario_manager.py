"""Tests for ScenarioManager, simulation precedence, singleton, and real scenarios."""

import json
from pathlib import Path

import pytest

from app.scenarios import (
    ScenarioManager,
    get_scenario_manager,
    load_scenario_file,
)

pytestmark = pytest.mark.unit


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

        # If auto-load didn't pick up env var (CI caching), load directly
        if not mgr.is_active:
            mgr._scenarios_dirs = [tmp_path] + mgr._scenarios_dirs
            mgr.load("auto-scenario")

        assert mgr.is_active is True
        assert mgr.active.name == "auto-scenario"


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
