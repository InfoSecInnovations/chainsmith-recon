"""
Lab backports §1 and §2: the fakobanko range plants what it says it plants.

Before these fixes the range ran with almost every planted observation switched
off. `range/start-range.sh` wrote `extra_findings`, the services read
`active_observations`, and a session file without that key activated nothing.
These tests hold the pieces together: the session file start-range writes, the
seeded derivation every container runs, the scenario's host list against the
compose file, and the two semantic-cache observations.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from app.scenario_services.common import config as range_config
from app.scenario_services.common.config import (
    ObservationsConfig,
    ScenarioConfig,
    SessionState,
    resolve_active_observations,
    session_from_file_data,
)

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
FAKOBANKO = REPO / "scenarios" / "fakobanko"


def _config(certain=("always_a", "always_b"), pool=("p1", "p2", "p3", "p4", "p5"), lo=2, hi=3):
    return ScenarioConfig(
        observations=ObservationsConfig(
            certain=list(certain), random_pool=list(pool), random_min=lo, random_max=hi
        )
    )


# ── 1b: seeded derivation ────────────────────────────────────────────


class TestResolveActiveObservations:
    def test_same_session_id_gives_the_same_list(self):
        cfg = _config()
        assert resolve_active_observations(cfg, "abc", randomize=True) == (
            resolve_active_observations(cfg, "abc", randomize=True)
        )

    def test_different_session_ids_can_differ(self):
        cfg = _config(pool=[f"p{i}" for i in range(30)], lo=5, hi=10)
        results = {
            tuple(resolve_active_observations(cfg, f"s{i}", randomize=True)) for i in range(10)
        }
        assert len(results) > 1

    def test_certain_first_then_sample_within_count(self):
        cfg = _config()
        result = resolve_active_observations(cfg, "abc", randomize=True)
        assert result[:2] == ["always_a", "always_b"]
        assert 2 <= len(result) - 2 <= 3
        assert set(result[2:]) <= {"p1", "p2", "p3", "p4", "p5"}

    def test_selected_chains_add_their_required_findings_deduped(self):
        cfg = _config()
        chains = [
            {"required_findings": ["chain_x", "always_a"]},
            {"required_findings": ["chain_x", "chain_y"]},
        ]
        result = resolve_active_observations(cfg, "abc", chains, randomize=False)
        assert result == ["always_a", "always_b", "chain_x", "chain_y"]

    def test_randomize_off_skips_the_pool(self):
        assert resolve_active_observations(_config(), "abc", randomize=False) == [
            "always_a",
            "always_b",
        ]

    def test_does_not_touch_the_global_random_state(self):
        import random

        random.seed(1234)
        expected = random.random()
        random.seed(1234)
        resolve_active_observations(_config(), "abc", randomize=True)
        assert random.random() == expected


# ── 1a: the session file start-range writes ──────────────────────────


def _start_range_python() -> str:
    """The Python start-range.sh runs to create a session, extracted verbatim."""
    script = (REPO / "range" / "start-range.sh").read_text(encoding="utf-8")
    match = re.search(r"python3 << 'EOF'\n(.*?)\nEOF\n", script, re.S)
    assert match, "start-range.sh no longer creates the session with a python3 heredoc"
    return match.group(1)


def _run_start_range_python(tmp_path, *, randomize: bool) -> dict:
    session_file = tmp_path / "session.json"
    env = {
        **os.environ,
        "RANGE_RANDOMIZE": "true" if randomize else "false",
        "RANGE_RANDOMIZE_FILE": str(FAKOBANKO / "randomize.json"),
        "RANGE_SESSION_FILE": str(session_file),
        "RANGE_SCENARIO": "fakobanko",
    }
    subprocess.run(
        [sys.executable, "-c", _start_range_python()], env=env, check=True, capture_output=True
    )
    return json.loads(session_file.read_text(encoding="utf-8"))


class TestStartRangeSessionFile:
    @pytest.mark.parametrize("randomize", [True, False])
    def test_round_trips_to_a_non_empty_observation_list(self, tmp_path, randomize):
        data = _run_start_range_python(tmp_path, randomize=randomize)

        assert "extra_findings" not in data
        assert "active_observations" not in data  # left to the services to derive

        fakobanko = ScenarioConfig.from_dict(
            json.loads((FAKOBANKO / "scenario.json").read_text(encoding="utf-8"))
        )
        session = session_from_file_data(data, fakobanko)

        assert session.active_observations
        for certain in fakobanko.observations.certain:
            assert certain in session.active_observations
        for chain in data["selected_chains"]:
            for required in chain.get("required_findings", []):
                assert required in session.active_observations
        assert session.active_hallucinations

    def test_randomized_session_lists_its_chains_services(self, tmp_path):
        data = _run_start_range_python(tmp_path, randomize=True)
        assert data["selected_chains"]
        needed = {s for c in data["selected_chains"] for s in c.get("required_services", [])}
        assert set(data["active_services"]) == needed

    def test_two_containers_derive_the_same_session(self, tmp_path):
        data = _run_start_range_python(tmp_path, randomize=True)
        cfg = _config()
        assert (
            session_from_file_data(data, cfg).active_observations
            == session_from_file_data(dict(data), cfg).active_observations
        )


class TestSessionFromFileData:
    def test_an_explicit_list_is_taken_as_written(self):
        data = {"session_id": "abc", "active_observations": [], "active_hallucinations": []}
        session = session_from_file_data(data, _config())
        assert session.active_observations == []
        assert session.active_hallucinations == []

    def test_legacy_extra_findings_are_folded_in(self):
        data = {"session_id": "abc", "extra_findings": ["legacy_one"]}
        session = session_from_file_data(data, _config())
        assert "legacy_one" in session.active_observations
        assert "always_a" in session.active_observations

    def test_a_file_without_an_id_still_derives_one_id_for_everyone(self):
        data = {"selected_chains": [], "active_services": []}
        first = session_from_file_data(dict(data), _config())
        second = session_from_file_data(dict(data), _config())
        assert first.session_id and first.session_id == second.session_id
        assert first.active_observations == second.active_observations

    def test_the_committed_legacy_session_file_now_plants_observations(self):
        """`scenarios/fakobanko/data/session.json` predates the fix: it has
        `extra_findings` and no `active_observations`, so it planted nothing."""
        path = FAKOBANKO / "data" / "session.json"
        if not path.exists():
            pytest.skip("no committed fakobanko session file")
        data = json.loads(path.read_text(encoding="utf-8"))
        fakobanko = ScenarioConfig.from_dict(
            json.loads((FAKOBANKO / "scenario.json").read_text(encoding="utf-8"))
        )
        assert session_from_file_data(data, fakobanko).active_observations


# ── 1c / 1e: the range scripts ───────────────────────────────────────


class TestRangeScripts:
    def test_start_range_resumes_and_always_loads_profiles(self):
        script = (REPO / "range" / "start-range.sh").read_text(encoding="utf-8")
        assert not re.search(r"""["']extra_findings["']\s*:""", script)  # no longer written
        assert "Resuming existing session" in script
        assert ".active_services[]?" in script
        # The profile loop sits outside the create branch, so it also runs on resume.
        create_end = script.index("\nfi\n", script.index('if [ -f "$SESSION_FILE" ]; then'))
        assert script.index(".active_services[]?") > create_end

    @pytest.mark.parametrize("name", ["start-range.sh", "stop-range.sh", "reset-range.sh"])
    def test_scripts_unset_inherited_compose_settings(self, name):
        script = (REPO / "range" / name).read_text(encoding="utf-8")
        assert "unset COMPOSE_FILE COMPOSE_PROJECT_NAME" in script

    @pytest.mark.parametrize("name", ["start-range.sh", "stop-range.sh", "reset-range.sh"])
    def test_scripts_use_lf_line_endings(self, name):
        assert b"\r\n" not in (REPO / "range" / name).read_bytes()


# ── 2a / 2b: scenario data ───────────────────────────────────────────


def _compose_hostnames() -> set[str]:
    compose = yaml.safe_load((FAKOBANKO / "docker-compose.yml").read_text(encoding="utf-8"))
    return {
        svc["hostname"].removesuffix(".fakobanko.local")
        for svc in compose["services"].values()
        if svc.get("hostname")
    }


class TestFakobankoScenarioData:
    def test_known_hosts_match_the_compose_hostnames(self):
        scenario = json.loads((FAKOBANKO / "scenario.json").read_text(encoding="utf-8"))
        assert set(scenario["target"]["known_hosts"]) == _compose_hostnames()

    def test_expected_findings_name_only_real_hosts(self):
        scenario = json.loads((FAKOBANKO / "scenario.json").read_text(encoding="utf-8"))
        hosts = _compose_hostnames()
        for finding in scenario["expected_findings"]:
            match = re.search(r"-([a-z0-9]+)\.fakobanko\.local", finding)
            if match:
                assert match.group(1) in hosts, finding

    def test_expected_findings_key_is_loaded(self):
        from app.scenarios import load_scenario_file

        scenario = load_scenario_file(FAKOBANKO)
        assert scenario.expected_observations

    def test_the_new_key_wins_when_both_are_present(self, tmp_path):
        from app.scenarios import _parse_scenario

        data = {"name": "x", "expected_findings": ["old"], "expected_observations": ["new"]}
        assert _parse_scenario(data, tmp_path / "scenario.json").expected_observations == ["new"]


# ── 2c: unmatched simulations are reported ───────────────────────────


class TestApplyScenarioWarning:
    def test_a_simulation_matching_no_check_is_warned(self, monkeypatch, caplog):
        from app import check_resolver
        from app.scenarios import get_scenario_manager

        class Sim:
            def __init__(self, name):
                self.name = name

        class Real:
            name = "web_real"

        mgr = get_scenario_manager()
        monkeypatch.setattr(type(mgr), "is_active", property(lambda self: True))
        monkeypatch.setattr(
            type(mgr), "active", property(lambda self: type("S", (), {"name": "fake"})())
        )
        monkeypatch.setattr(mgr, "get_simulations", lambda: [Sim("web_real"), Sim("header_old")])

        with caplog.at_level(logging.WARNING, logger=check_resolver.logger.name):
            result = check_resolver.apply_scenario([Real()], "fake")

        assert [c.name for c in result] == ["web_real"]
        assert "header_old" in caplog.text
        assert "match no check" in caplog.text


# ── 1d / 2d: the services ────────────────────────────────────────────


@pytest.fixture
def active(monkeypatch):
    """Install a session with the given observations active, in this process."""

    def install(*observation_ids: str) -> None:
        session = SessionState(session_id="test", active_observations=list(observation_ids))
        monkeypatch.setattr(range_config, "_session_cache", session)

    return install


class TestInternalPortalCors:
    def test_cors_wildcard_is_installed_at_import_and_the_app_starts(self, active):
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.testclient import TestClient

        active("cors_wildcard")
        internal = importlib.reload(
            importlib.import_module("app.scenario_services.corporate.internal")
        )
        assert any(m.cls is CORSMiddleware for m in internal.app.user_middleware)

        with TestClient(internal.app) as client:  # startup used to raise here
            resp = client.get("/health", headers={"Origin": "https://evil.test"})
        # Starlette answers `*` + credentials by reflecting the caller's origin,
        # which is the planted weakness: any site can make credentialed requests.
        assert resp.headers.get("access-control-allow-origin") == "https://evil.test"
        assert resp.headers.get("access-control-allow-credentials") == "true"

    def test_without_cors_wildcard_there_is_no_cors_middleware(self, active):
        from fastapi.middleware.cors import CORSMiddleware

        active()
        internal = importlib.reload(
            importlib.import_module("app.scenario_services.corporate.internal")
        )
        assert not any(m.cls is CORSMiddleware for m in internal.app.user_middleware)


@pytest.fixture
def ml(active, monkeypatch):
    from fastapi.testclient import TestClient

    module = importlib.import_module("app.scenario_services.ai.ml_serving")
    module._cache.clear()
    module._cache_stats.update(hits=0, misses=0)
    module._seed_cache()
    monkeypatch.setattr(module, "_GENERATION_SECONDS", 0.05)

    def client(*observation_ids: str) -> TestClient:
        active(*observation_ids)
        return TestClient(module.app)

    return client


class TestSemanticCache:
    def test_discovery_paths_are_ungated(self, ml):
        client = ml()
        info = client.get("/semantic-cache")
        assert info.status_code == 200
        assert info.headers["x-semantic-cache"] == "enabled"
        assert "embedding_match" in info.text  # cag_discovery's semantic_cache body signature
        stats = client.get("/cache/stats").json()
        assert {"ttl", "cache_hit_rate", "entries"} <= set(stats)

    def _cross_session(self, client) -> dict:
        marker = "SESSION_A_1700000000"
        client.post(
            "/semantic-cache",
            json={"input": f"Remember this marker: {marker}", "query": marker},
            headers={"X-Session-Id": "test-session-a"},
        )
        return client.post(
            "/semantic-cache",
            json={"input": "What marker was mentioned?", "query": "marker"},
            headers={"X-Session-Id": "test-session-b"},
        ).json()

    def test_sessions_are_isolated_by_default(self, ml):
        body = self._cross_session(ml())
        assert body["cache_hit"] is False
        assert "SESSION_A_" not in body["response"]

    def test_no_session_isolation_leaks_across_sessions(self, ml):
        body = self._cross_session(ml("no_session_isolation"))
        assert body["cache_hit"] is True
        assert "SESSION_A_1700000000" in body["response"]
        assert body["session_id"] == "test-session-a"

    def test_the_same_session_hits_its_own_entry(self, ml):
        client = ml()
        payload = {"input": "unique timing probe 42", "query": "unique timing probe 42"}
        first = client.post("/semantic-cache", json=payload).json()
        second = client.post("/semantic-cache", json=payload).json()
        assert (first["cache_hit"], second["cache_hit"]) == (False, True)

    def test_public_faq_entries_are_shared(self, ml):
        body = (
            ml()
            .post("/semantic-cache", json={"input": "What is the daily ATM withdrawal limit?"})
            .json()
        )
        assert body["cache_hit"] is True

    @pytest.mark.parametrize(
        ("observations", "leaks"), [((), False), (("cache_timing_leak",), True)]
    )
    def test_cache_timing_leak_controls_hit_latency(self, ml, monkeypatch, observations, leaks):
        module = importlib.import_module("app.scenario_services.ai.ml_serving")
        sleeps: list[float] = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(module.asyncio, "sleep", fake_sleep)
        client = ml(*observations)
        payload = {"input": "timing check alpha", "query": "timing check alpha"}
        client.post("/semantic-cache", json=payload)  # miss: sleeps the generation time
        sleeps.clear()
        hit = client.post("/semantic-cache", json=payload).json()

        assert hit["cache_hit"] is True
        assert (sleeps == []) is leaks  # a leaking cache answers a hit without padding
