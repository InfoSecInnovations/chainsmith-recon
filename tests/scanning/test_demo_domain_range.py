"""
demo-domain range: observation ids, and a session every container shares.

demo-domain has its own gating module (`scenarios/demo-domain/demo_domain/
config.py`), separate from `app.scenario_services`. It had three problems:

- it read `DEMO_DOMAIN_SESSION_STATE`, but compose sets `SESSION_STATE_PATH`,
  so each container rolled its own unshared session;
- the file range/start-range.sh writes (no observation lists) failed
  validation, and the fallback overwrote it, chains included;
- its lists had drifted from the gates its services check.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "scenarios" / "demo-domain"
CONFIG = DEMO / "demo_domain" / "config.py"


def _load(monkeypatch, **env):
    for key in ("DEMO_DOMAIN_SESSION_STATE", "SESSION_STATE_PATH"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    spec = importlib.util.spec_from_file_location("demo_domain_config_under_test", CONFIG)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gates() -> set[str]:
    gates: set[str] = set()
    for path in [*(DEMO / "services").glob("*.py"), *(DEMO / "demo_domain").glob("*.py")]:
        if path.name == "config.py":
            continue
        gates |= set(
            re.findall(r'is_observation_active\(\s*"([a-z0-9_]+)"', path.read_text("utf-8"))
        )
    return gates


def test_every_listed_id_is_a_gate_and_every_gate_is_reachable(monkeypatch):
    cfg = _load(monkeypatch)
    gates = _gates()
    assert len(gates) > 15
    listed = set(cfg.CERTAIN_OBSERVATIONS) | set(cfg.RANDOM_OBSERVATIONS_POOL)
    chains = json.loads((DEMO / "randomize.json").read_text("utf-8"))["chain_packages"]
    required = {f for c in chains for f in c.get("required_findings", [])}

    assert listed - gates == set(), "listed ids that gate nothing"
    assert gates - listed - required == set(), "gates nothing can activate"
    assert not set(cfg.CERTAIN_OBSERVATIONS) & set(cfg.RANDOM_OBSERVATIONS_POOL)


def test_scenario_json_mirrors_the_module_lists(monkeypatch):
    cfg = _load(monkeypatch)
    obs = json.loads((DEMO / "scenario.json").read_text("utf-8"))["observations"]
    assert obs["certain"] == cfg.CERTAIN_OBSERVATIONS
    assert obs["random_pool"] == cfg.RANDOM_OBSERVATIONS_POOL


def test_the_compose_session_path_is_honoured(monkeypatch, tmp_path):
    cfg = _load(monkeypatch, SESSION_STATE_PATH=str(tmp_path / "session.json"))
    assert tmp_path / "session.json" == cfg.SESSION_STATE_PATH
    # The explicit demo-specific variable still wins.
    cfg = _load(monkeypatch, DEMO_DOMAIN_SESSION_STATE="/x/demo.json", SESSION_STATE_PATH="/y")
    assert Path("/x/demo.json") == cfg.SESSION_STATE_PATH


def test_derivation_is_seeded_by_session_id(monkeypatch):
    cfg = _load(monkeypatch)
    assert cfg.resolve_active_observations("abc") == cfg.resolve_active_observations("abc")
    first = cfg.resolve_active_observations("abc")
    assert first[: len(cfg.CERTAIN_OBSERVATIONS)] == cfg.CERTAIN_OBSERVATIONS
    sample = len(first) - len(cfg.CERTAIN_OBSERVATIONS)
    assert cfg.RANDOM_COUNT_MIN <= sample <= cfg.RANDOM_COUNT_MAX


def _start_range_session(tmp_path) -> Path:
    script = (REPO / "range" / "start-range.sh").read_text(encoding="utf-8")
    code = re.search(r"python3 << 'EOF'\n(.*?)\nEOF\n", script, re.S).group(1)
    session_file = tmp_path / "session.json"
    env = {
        **os.environ,
        "RANGE_RANDOMIZE": "true",
        "RANGE_RANDOMIZE_FILE": str(DEMO / "randomize.json"),
        "RANGE_SESSION_FILE": str(session_file),
        "RANGE_SCENARIO": "demo-domain",
    }
    subprocess.run([sys.executable, "-c", code], env=env, check=True, capture_output=True)
    return session_file


def test_the_start_range_file_is_read_not_overwritten(monkeypatch, tmp_path):
    session_file = _start_range_session(tmp_path)
    before = session_file.read_text("utf-8")
    cfg = _load(monkeypatch, SESSION_STATE_PATH=str(session_file))

    session = cfg.get_or_create_session()

    assert session_file.read_text("utf-8") == before  # chains survive
    data = json.loads(before)
    assert session.session_id == data["session_id"]
    assert session.selected_chains == data["selected_chains"]
    for certain in cfg.CERTAIN_OBSERVATIONS:
        assert cfg.is_observation_active(certain)
    for chain in data["selected_chains"]:
        for required in chain.get("required_findings", []):
            assert required in session.active_observations


def test_two_containers_agree(monkeypatch, tmp_path):
    session_file = _start_range_session(tmp_path)
    a = _load(monkeypatch, SESSION_STATE_PATH=str(session_file)).get_or_create_session()
    b = _load(monkeypatch, SESSION_STATE_PATH=str(session_file)).get_or_create_session()
    assert a.active_observations == b.active_observations
    assert a.active_hallucinations == b.active_hallucinations
