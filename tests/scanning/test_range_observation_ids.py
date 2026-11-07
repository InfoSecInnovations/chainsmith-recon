"""
The range's planted-observation ids and its scenario lists share one vocabulary.

A range service plants a vulnerability behind `is_observation_active("<id>")`,
and `resolve_active_observations` activates ids from the scenario's `certain`
list, a sample of its `random_pool`, and each selected chain's
`required_findings` (randomize.json). An id that a list names but no service
gates plants nothing; a gate that no list names can never switch on. These
tests hold the two sides together for every scenario whose compose file runs
`app.scenario_services`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
SERVICES = REPO / "app" / "scenario_services"
SCENARIOS = REPO / "scenarios"

_GATE = re.compile(r"""is_observation_active\(\s*["']([^"']+)["']""")


def _gate_ids() -> set[str]:
    """Every literal id a range service gates on.

    `common/config.py` defines the function and only names ids in docstring
    examples, so it is left out.
    """
    gates: set[str] = set()
    for path in SERVICES.rglob("*.py"):
        if "__pycache__" in path.parts or path == SERVICES / "common" / "config.py":
            continue
        gates.update(_GATE.findall(path.read_text(encoding="utf-8")))
    return gates


def _range_scenarios() -> list[str]:
    """Scenarios whose compose file runs the shared `app.scenario_services`."""
    names = []
    for compose in sorted(SCENARIOS.glob("*/docker-compose.yml")):
        if "app.scenario_services." in compose.read_text(encoding="utf-8"):
            names.append(compose.parent.name)
    return names


RANGE_SCENARIOS = _range_scenarios()
GATES = _gate_ids()


def _observations(scenario: str) -> dict:
    data = json.loads((SCENARIOS / scenario / "scenario.json").read_text(encoding="utf-8"))
    return data["observations"]


def _chain_findings(scenario: str) -> set[str]:
    path = SCENARIOS / scenario / "randomize.json"
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        finding
        for chain in data.get("chain_packages", [])
        for finding in chain.get("required_findings", []) or []
    }


def test_gate_scan_finds_gates():
    assert len(GATES) > 20
    assert "fakobanko" in RANGE_SCENARIOS


@pytest.mark.parametrize("scenario", RANGE_SCENARIOS)
def test_listed_ids_gate_something(scenario):
    obs = _observations(scenario)
    listed = list(obs.get("certain", [])) + list(obs.get("random_pool", []))
    dead = sorted(set(listed) - GATES)
    assert not dead, f"{scenario}: certain/random_pool ids no service gates on: {dead}"


@pytest.mark.parametrize("scenario", RANGE_SCENARIOS)
def test_every_gate_is_reachable(scenario):
    obs = _observations(scenario)
    reachable = set(obs.get("certain", [])) | set(obs.get("random_pool", []))
    reachable |= _chain_findings(scenario)
    unreachable = sorted(GATES - reachable)
    assert not unreachable, f"{scenario}: gates no list can activate: {unreachable}"


@pytest.mark.parametrize("scenario", RANGE_SCENARIOS)
def test_lists_have_no_duplicates(scenario):
    obs = _observations(scenario)
    certain, pool = list(obs.get("certain", [])), list(obs.get("random_pool", []))
    assert len(certain) == len(set(certain))
    assert len(pool) == len(set(pool))
    assert not set(certain) & set(pool), "an id is both certain and pooled"


@pytest.mark.parametrize("scenario", RANGE_SCENARIOS)
def test_random_count_bounds_fit_pool(scenario):
    obs = _observations(scenario)
    pool = obs.get("random_pool", [])
    count = obs.get("random_count", {})
    low, high = count.get("min", 2), count.get("max", 5)
    assert isinstance(low, int) and isinstance(high, int)
    assert 0 <= low <= high <= len(pool), (
        f"{scenario}: random_count {low}..{high}, pool {len(pool)}"
    )
    if pool:
        assert high > 0, f"{scenario}: a non-empty random_pool never samples"
