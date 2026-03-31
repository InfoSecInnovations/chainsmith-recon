"""
app/scenarios.py - Scenario Loader and Manager

Scenarios are self-contained directory bundles. Each scenario lives in its
own subdirectory under scenarios/ and can be zipped and shared as-is.

Layout:

    scenarios/
    └── fakobanko/
        ├── scenario.json      ← manifest
        ├── docker-compose.yml ← target services
        ├── services/          ← FastAPI service implementations
        ├── simulations/       ← scenario-specific simulations (optional)
        └── data/              ← persistent state (optional)

Global simulation YAML files live in app/checks/simulator/simulations/.

Simulation Resolution (precedence):
    1. Scenario-specific: scenarios/<name>/simulations/<rel_path>
    2. Global fallback:   app/checks/simulator/simulations/<rel_path>

If both exist at the same relative path, scenario-specific wins.

scenario.json schema:
    {
      "name": "fakobanko",
      "description": "AI-powered banking platform",
      "version": "2.0.0",
      "target": {
        "pattern": "*.fakobanko.local",
        "known_hosts": ["www", "chat", "api"],
        "ports": [8080, 8081, 8082]
      },
      "simulations": [
        "network/dns_fakobanko.yaml",
        "web/headers_fakobanko.yaml"
      ],
      "expected_findings": ["dns_enumeration-fakobanko.local"],
      "expected_chains": ["ai_service_prompt_injection"]
    }

Simulation paths are relative paths resolved against scenario-specific
and global simulation directories.

"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.checks.simulator.simulated_check import SimulatedCheck, load_simulated_check


# ── Default search paths ──────────────────────────────────────────

def _default_scenarios_dirs() -> list[Path]:
    """Return ordered list of directories to search for scenario bundles."""
    dirs = []
    if env := os.environ.get("CHAINSMITH_SCENARIOS_DIR"):
        dirs.append(Path(env))
    dirs.append(Path.home() / ".chainsmith" / "scenarios")
    dirs.append(Path(__file__).parent.parent / "scenarios")
    return dirs


def _default_global_simulations_dir() -> Path:
    """Return path to the global simulations directory."""
    if env := os.environ.get("CHAINSMITH_SIMULATIONS_DIR"):
        return Path(env)
    return Path(__file__).parent / "checks" / "simulator" / "simulations"



# ── Schema dataclasses ────────────────────────────────────────────

@dataclass
class ScenarioTarget:
    pattern: str = ""
    known_hosts: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    notes: str = ""


@dataclass
class Scenario:
    name: str
    description: str = ""
    version: str = "1.0.0"
    target: ScenarioTarget = field(default_factory=ScenarioTarget)
    simulations: list[str] = field(default_factory=list)
    expected_findings: list[str] = field(default_factory=list)
    expected_chains: list[str] = field(default_factory=list)
    source_path: Optional[Path] = None   # scenario.json path

    @property
    def directory(self) -> Optional[Path]:
        """The scenario bundle directory (parent of scenario.json)."""
        return self.source_path.parent if self.source_path else None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "target": {
                "pattern": self.target.pattern,
                "known_hosts": self.target.known_hosts,
                "ports": self.target.ports,
                "notes": self.target.notes,
            },
            "simulations": self.simulations,
            "expected_findings": self.expected_findings,
            "expected_chains": self.expected_chains,
            "source_path": str(self.source_path) if self.source_path else None,
            "directory": str(self.directory) if self.directory else None,
        }


# ── Loader ────────────────────────────────────────────────────────

class ScenarioLoadError(ValueError):
    pass


def _parse_scenario(data: dict, source_path: Path) -> Scenario:
    """Parse raw JSON dict into a Scenario. Raises ScenarioLoadError on bad data."""
    if not isinstance(data, dict):
        raise ScenarioLoadError("Scenario JSON must be an object")

    name = data.get("name", "")
    if not name:
        raise ScenarioLoadError("Scenario must have a non-empty 'name' field")

    target_raw = data.get("target", {})
    target = ScenarioTarget(
        pattern=target_raw.get("pattern", ""),
        known_hosts=list(target_raw.get("known_hosts", [])),
        ports=list(target_raw.get("ports", [])),
        notes=str(target_raw.get("notes", "")),
    )

    simulations = data.get("simulations", [])
    if not isinstance(simulations, list):
        raise ScenarioLoadError("'simulations' must be a list of relative paths")

    return Scenario(
        name=name,
        description=str(data.get("description", "")),
        version=str(data.get("version", "1.0.0")),
        target=target,
        simulations=[str(s) for s in simulations],
        expected_findings=list(data.get("expected_findings", [])),
        expected_chains=list(data.get("expected_chains", [])),
        source_path=source_path,
    )


def load_scenario_file(path: Path) -> Scenario:
    """
    Load a scenario from a directory bundle or a JSON file path.
    If path is a directory, looks for scenario.json inside it.
    """
    if path.is_dir():
        path = path / "scenario.json"
    if not path.exists():
        raise ScenarioLoadError(f"Scenario file not found: {path}")
    try:
        with open(path) as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        raise ScenarioLoadError(f"Invalid JSON in {path}: {e}") from e
    return _parse_scenario(data, path)


def find_scenario_file(name: str, search_dirs: list[Path] | None = None) -> Path:
    """
    Locate a scenario bundle directory by name.

    Accepts a bare name ('demo-domain') or an explicit directory path.
    Each scenario must be a directory containing scenario.json.
    """
    p = Path(name)
    if p.is_dir() and (p / "scenario.json").exists():
        return p

    dirs = search_dirs or _default_scenarios_dirs()
    for d in dirs:
        candidate = d / name
        if candidate.is_dir() and (candidate / "scenario.json").exists():
            return candidate

    searched = ", ".join(str(d) for d in dirs)
    raise ScenarioLoadError(f"Scenario '{name}' not found. Searched: {searched}")


# ── Manager ───────────────────────────────────────────────────────

class ScenarioManager:
    """
    Manages the active scenario and resolves simulation configs.

    Scenarios are directory bundles under scenarios/<n>/scenario.json.
    Simulation paths in the manifest are resolved with precedence:
      1. Scenario-specific: scenarios/<n>/simulations/<rel_path>
      2. Global fallback:   app/checks/simulator/simulations/<rel_path>

    Scenario-specific simulations replace (not merge with) global ones
    when both exist at the same relative path.

    Usage:
        mgr = ScenarioManager()
        mgr.load("demo-domain")
        sims = mgr.get_simulations()   # list[SimulatedCheck]
        mgr.clear()                    # back to real checks
    """

    def __init__(
        self,
        scenarios_dirs: list[Path] | None = None,
        global_simulations_dir: Path | None = None,
    ):
        self._scenarios_dirs = scenarios_dirs or _default_scenarios_dirs()
        self._global_simulations_dir = global_simulations_dir or _default_global_simulations_dir()
        self._active: Optional[Scenario] = None
        self._simulations: list[SimulatedCheck] = []

    @property
    def active(self) -> Optional[Scenario]:
        return self._active

    @property
    def is_active(self) -> bool:
        return self._active is not None

    def load(self, name_or_path: str) -> Scenario:
        """
        Load a scenario by name or path. Replaces any currently active scenario.

        Simulation paths are resolved with precedence:
          1. Scenario-specific: scenarios/<name>/simulations/<rel_path>
          2. Global fallback:   app/checks/simulator/simulations/<rel_path>

        If both exist, scenario-specific wins (replaces, not merges).
        """
        path = find_scenario_file(name_or_path, self._scenarios_dirs)
        scenario = load_scenario_file(path)

        # Simulation search paths: scenario-specific first, then global
        scenario_sim_root = scenario.directory / "simulations"
        global_sim_root = self._global_simulations_dir

        sims = []
        errors = []
        for rel_path in scenario.simulations:
            # Try scenario-specific first
            scenario_path = scenario_sim_root / rel_path
            global_path = global_sim_root / rel_path

            if scenario_path.exists():
                resolved_path = scenario_path
            elif global_path.exists():
                resolved_path = global_path
            else:
                errors.append(
                    f"Simulation config not found: {rel_path} "
                    f"(searched: {scenario_sim_root}, {global_sim_root})"
                )
                continue

            try:
                sc = load_simulated_check(resolved_path)
                sims.append(sc)
            except Exception as e:
                errors.append(f"Failed to load {resolved_path}: {e}")

        if errors:
            scenario.description += f" [WARNINGS: {'; '.join(errors)}]"

        self._active = scenario
        self._simulations = sims
        return scenario

    def clear(self) -> None:
        """Deactivate the current scenario (return to real checks)."""
        self._active = None
        self._simulations = []

    def get_simulations(self) -> list[SimulatedCheck]:
        """Return resolved SimulatedCheck instances for the active scenario."""
        return list(self._simulations)

    def list_available(self) -> list[dict]:
        """
        Scan scenario directories and return summary dicts for all
        discoverable scenarios. Directory bundles take precedence over
        legacy flat files with the same name.
        """
        seen: dict[str, dict] = {}

        for d in self._scenarios_dirs:
            if not d.exists():
                continue

            # Directory bundles (preferred)
            for sub in sorted(d.iterdir()):
                if sub.is_dir() and (sub / "scenario.json").exists():
                    try:
                        scenario = load_scenario_file(sub)
                        key = scenario.name
                        if key not in seen:
                            seen[key] = {
                                "name": scenario.name,
                                "description": scenario.description,
                                "version": scenario.version,
                                "simulation_count": len(scenario.simulations),
                                "source_path": str(sub),
                                }
                    except ScenarioLoadError:
                        pass



        return list(seen.values())


# ── Module-level singleton ────────────────────────────────────────

_manager: Optional[ScenarioManager] = None


def get_scenario_manager() -> ScenarioManager:
    """Return the module-level ScenarioManager singleton."""
    global _manager
    if _manager is None:
        _manager = ScenarioManager()
        if default := os.environ.get("CHAINSMITH_SCENARIO"):
            try:
                _manager.load(default)
            except ScenarioLoadError:
                pass
    return _manager
