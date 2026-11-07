"""
Tests for tunable-config + strict-env validation folded into verify_contracts
(Phase 56.16).

verify_contracts now also validates each component's config.yaml/suite.yaml against
their Pydantic schemas, and — for the check root only — the per-component
env-override namespace (a typo'd / uncoercible CHAINSMITH__ var is a hard
violation). Plus the /api/v1/checks surface carries the resolved knobs + provenance.
"""

import uuid

import pytest
import yaml

from app.component_loader import verify_contracts
from app.components.config_resolver import env_key

pytestmark = pytest.mark.unit


def _write_check(root, suite, name, *, config=None):
    d = root / suite / name
    d.mkdir(parents=True)
    (d / "contract.yaml").write_text(
        yaml.safe_dump(
            {
                "id": str(uuid.uuid4()),
                "name": name,
                "type": "check",
                "description": f"{name} description",
                "entry": "check.py:Foo",
                "suite": suite,
                # Every built-in check declares one since the 57.4 exit
                # condition; without it the tree is not "clean" any more.
                "severity": {"model": "fixed", "default": "info"},
            }
        ),
        encoding="utf-8",
    )
    # Stub entry file so the entry-constructible pass is satisfied (no-arg class).
    (d / "check.py").write_text("class Foo:\n    pass\n", encoding="utf-8")
    if config is not None:
        (d / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")


def _codes(violations):
    return {v.code for v in violations}


# ── config.yaml schema ───────────────────────────────────────────────


def test_clean_synthetic_tree_has_no_violations(tmp_path):
    _write_check(tmp_path, "web", "web_ok", config={"enabled": True})
    assert verify_contracts(tmp_path, "check", env={}) == []


def test_bad_config_yaml_extra_key_is_violation(tmp_path):
    _write_check(tmp_path, "web", "web_bad", config={"enabled": True, "bogus_key": 1})
    assert "config-schema" in _codes(verify_contracts(tmp_path, "check", env={}))


def test_bad_config_on_critical_enum_is_violation(tmp_path):
    _write_check(tmp_path, "web", "web_oc", config={"on_critical": "explode"})
    assert "config-schema" in _codes(verify_contracts(tmp_path, "check", env={}))


def test_unparseable_config_yaml_is_violation(tmp_path):
    _write_check(tmp_path, "web", "web_ok")
    d = tmp_path / "web" / "web_ok"
    (d / "config.yaml").write_text("enabled: true\n  : broken\n", encoding="utf-8")
    assert "config-yaml-parse" in _codes(verify_contracts(tmp_path, "check", env={}))


# ── suite.yaml schema ────────────────────────────────────────────────


def test_bad_suite_yaml_is_violation(tmp_path):
    _write_check(tmp_path, "web", "web_ok")
    (tmp_path / "web" / "suite.yaml").write_text(
        yaml.safe_dump({"name": "web", "on_critical": "nope"}), encoding="utf-8"
    )
    assert "suite-schema" in _codes(verify_contracts(tmp_path, "check", env={}))


def test_valid_suite_yaml_clean(tmp_path):
    _write_check(tmp_path, "web", "web_ok")
    (tmp_path / "web" / "suite.yaml").write_text(
        yaml.safe_dump({"name": "web", "enabled": True, "on_critical": "stop"}), encoding="utf-8"
    )
    assert verify_contracts(tmp_path, "check", env={}) == []


# ── strict env (check root only) ─────────────────────────────────────


def test_unknown_env_override_is_violation(tmp_path):
    _write_check(tmp_path, "web", "web_ok")
    env = {"CHAINSMITH__WEB_OK__TIMOUT_SECONDS": "5"}  # typo
    assert "env-unknown" in _codes(verify_contracts(tmp_path, "check", env=env))


def test_uncoercible_env_override_is_violation(tmp_path):
    _write_check(tmp_path, "web", "web_ok")
    env = {env_key("web_ok", "retry_count"): "abc"}
    assert "env-uncoercible" in _codes(verify_contracts(tmp_path, "check", env=env))


def test_valid_env_override_is_clean(tmp_path):
    _write_check(tmp_path, "web", "web_ok")
    env = {env_key("web_ok", "timeout_seconds"): "12"}
    assert verify_contracts(tmp_path, "check", env=env) == []


def test_env_validation_skipped_for_non_check_roots(tmp_path):
    # An agent-style tree: a stray CHAINSMITH__ var must NOT trip env validation
    # (only checks consume these knobs). We give it a valid agent contract so the
    # env pass is the only thing that could fire — and it shouldn't.
    d = tmp_path / "myagent"
    d.mkdir(parents=True)
    (d / "contract.yaml").write_text(
        yaml.safe_dump(
            {
                "id": str(uuid.uuid4()),
                "name": "myagent",
                "type": "agent",
                "description": "x",
                "entry": "agent.py:Foo",
                "role": "coach",
            }
        ),
        encoding="utf-8",
    )
    env = {"CHAINSMITH__MYAGENT__TIMEOUT_SECONDS": "5"}
    codes = _codes(verify_contracts(tmp_path, "agent", env=env))
    assert "env-unknown" not in codes and "env-uncoercible" not in codes


# ── real tree stays clean (no CHAINSMITH__ vars in CI) ───────────────


def test_real_checks_tree_config_and_env_clean():
    from pathlib import Path

    # Default env (os.environ); CI carries no CHAINSMITH__ override vars.
    violations = verify_contracts(Path("app/checks"), "check")
    bad = [v for v in violations if v.code.startswith(("config-", "suite-", "env-"))]
    assert bad == [], f"unexpected config/env violations: {bad}"


# ── /api/v1/checks surface carries resolved config + provenance ──────


async def test_checks_route_entries_carry_config_block():
    from app.routes.checks import get_available_checks

    result = await get_available_checks(include_disabled=False)
    sample = result["checks"][0]
    assert "config" in sample
    cfg = sample["config"]
    assert {
        "timeout_seconds",
        "requests_per_second",
        "retry_count",
        "delay_between_targets",
        "on_critical",
        "provenance",
    } <= cfg.keys()
    # provenance attributes each knob to a known layer
    assert all(
        layer in {"class_default", "suite", "config", "env", "default"}
        for layer in cfg["provenance"].values()
    )
