"""
Tests for the `contract.yaml` `severity:` block (Phase 57.4, §7).

Three surfaces, in the order a severity declaration travels:

1. **Schema** — `SeverityBlock` on `CheckContract`. Shape errors (unknown model,
   unknown level, stray key) are pydantic's, and surface as `contract-schema`.
2. **Cross-field rules** — `verify_contracts`. The load-bearing one is
   *contextual-without-default*: `on_critical` reads severity the moment a check
   finishes, long before a grader has placed one (§6.1), so a contextual check
   with no default takes that input away.
3. **Wiring** — `BaseCheck.from_config` fills `severity` and
   `provisional_severity` from the contract, and `provisional_for()` resolves a
   fixed check's per-discriminator value out of the `observations:` map.
"""

import uuid

import pytest
import yaml

from app.checks.base import BaseCheck
from app.component_loader import verify_contracts
from app.components.config_models import ComponentConfig
from app.components.config_resolver import ConfigResolver
from app.components.contracts import CheckContract

pytestmark = pytest.mark.unit


def _write_check(root, suite, name, *, severity=None):
    d = root / suite / name
    d.mkdir(parents=True)
    contract = {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": "check",
        "description": f"{name} description",
        "entry": "check.py:Foo",
        "suite": suite,
    }
    if severity is not None:
        contract["severity"] = severity
    (d / "contract.yaml").write_text(yaml.safe_dump(contract), encoding="utf-8")
    (d / "check.py").write_text("class Foo:\n    pass\n", encoding="utf-8")
    return d


def _codes(violations):
    return {v.code for v in violations}


def _verify(tmp_path):
    return verify_contracts(tmp_path, "check", env={})


# ── the block is required (§8 exit condition) ────────────────────────


def test_a_builtin_check_with_no_severity_block_is_a_violation(tmp_path):
    """57.4 is complete, so an undeclared built-in check has no provisional
    severity for `on_critical` and no model for a grader to honour."""
    _write_check(tmp_path, "web", "web_undeclared")
    assert _codes(_verify(tmp_path)) == {"severity-undeclared"}


def test_a_custom_check_with_no_severity_block_is_exempt(tmp_path):
    """The Chainsmith agent scaffolds `custom`-suite checks without a severity
    block (O-5, parked). A violation here would fail discovery for every check."""
    d = tmp_path / "custom" / "custom_scaffolded"
    d.mkdir(parents=True)
    contract = {
        "id": str(uuid.uuid4()),
        "name": "custom_scaffolded",
        "type": "check",
        "description": "scaffolded",
        "entry": "check.py:Foo",
        "suite": "custom",
    }
    (d / "contract.yaml").write_text(yaml.safe_dump(contract), encoding="utf-8")
    (d / "check.py").write_text("class Foo:\n    pass\n", encoding="utf-8")
    assert _verify(tmp_path) == []


def test_a_custom_check_that_declares_severity_is_still_validated(tmp_path):
    """Exempt from declaring, not from the cross-field rules once it does."""
    _write_check(tmp_path, "custom", "custom_bad", severity={"model": "contextual"})
    assert "severity-contextual-without-default" in _codes(_verify(tmp_path))


def test_the_severity_requirement_applies_only_to_checks(tmp_path):
    """Agents, advisors and gates have no severity model at all."""
    d = tmp_path / "some_agent"
    d.mkdir()
    contract = {
        "id": str(uuid.uuid4()),
        "name": "some_agent",
        "type": "agent",
        "description": "an agent",
        "entry": "agent.py:Foo",
    }
    (d / "contract.yaml").write_text(yaml.safe_dump(contract), encoding="utf-8")
    (d / "agent.py").write_text("class Foo:\n    pass\n", encoding="utf-8")
    assert "severity-undeclared" not in _codes(verify_contracts(tmp_path, "agent", env={}))


def test_well_formed_fixed_block_is_clean(tmp_path):
    _write_check(
        tmp_path,
        "web",
        "web_fixed",
        severity={"model": "fixed", "observations": {"missing-hsts": "medium"}},
    )
    assert _verify(tmp_path) == []


def test_well_formed_contextual_block_is_clean(tmp_path):
    _write_check(
        tmp_path,
        "ai",
        "ai_contextual",
        severity={
            "model": "contextual",
            "default": "medium",
            "range": ["info", "critical"],
            "rubric": "Did the target comply with the payload's intent?",
            "signals": ["reproduction_rate"],
        },
    )
    assert _verify(tmp_path) == []


# ── schema (pydantic, reported as contract-schema) ───────────────────


def test_unknown_severity_model_is_a_schema_violation(tmp_path):
    _write_check(tmp_path, "web", "web_bad_model", severity={"model": "vibes"})
    assert "contract-schema" in _codes(_verify(tmp_path))


def test_unknown_severity_level_is_a_schema_violation(tmp_path):
    _write_check(
        tmp_path,
        "web",
        "web_bad_level",
        severity={"model": "fixed", "observations": {"x": "catastrophic"}},
    )
    assert "contract-schema" in _codes(_verify(tmp_path))


def test_stray_key_in_severity_block_is_a_schema_violation(tmp_path):
    _write_check(
        tmp_path, "web", "web_stray", severity={"model": "fixed", "default": "low", "weight": 3}
    )
    assert "contract-schema" in _codes(_verify(tmp_path))


# ── cross-field rules (verify_contracts) ─────────────────────────────


def test_contextual_without_default_is_a_violation(tmp_path):
    """The one that matters: on_critical has no input without it (§6.1)."""
    _write_check(
        tmp_path, "ai", "ai_no_default", severity={"model": "contextual", "range": ["info", "high"]}
    )
    assert "severity-contextual-without-default" in _codes(_verify(tmp_path))


def test_fixed_with_neither_observations_nor_default_is_a_violation(tmp_path):
    _write_check(tmp_path, "web", "web_empty_fixed", severity={"model": "fixed"})
    assert "severity-fixed-without-severities" in _codes(_verify(tmp_path))


def test_fixed_with_only_a_default_is_accepted(tmp_path):
    """A fixed check that emits one kind of observation needs no map."""
    _write_check(tmp_path, "web", "web_one_shot", severity={"model": "fixed", "default": "high"})
    assert _verify(tmp_path) == []


def test_rubric_on_a_fixed_check_is_a_violation(tmp_path):
    """Inert forever, not inert-until-58 — a fixed check never calls a grader
    that would read it, so the author picked the wrong model."""
    _write_check(
        tmp_path,
        "web",
        "web_fixed_rubric",
        severity={"model": "fixed", "default": "low", "rubric": "judge it"},
    )
    assert "severity-contextual-field-on-fixed" in _codes(_verify(tmp_path))


def test_range_and_signals_on_a_fixed_check_are_violations(tmp_path):
    _write_check(
        tmp_path,
        "web",
        "web_fixed_range",
        severity={
            "model": "fixed",
            "default": "low",
            "range": ["info", "high"],
            "signals": ["response_text"],
        },
    )
    violations = [v for v in _verify(tmp_path) if v.code == "severity-contextual-field-on-fixed"]
    assert len(violations) == 2


def test_observations_map_on_a_contextual_check_is_a_violation(tmp_path):
    _write_check(
        tmp_path,
        "ai",
        "ai_map",
        severity={"model": "contextual", "default": "medium", "observations": {"x": "high"}},
    )
    assert "severity-observations-on-contextual" in _codes(_verify(tmp_path))


def test_inverted_range_is_a_violation(tmp_path):
    _write_check(
        tmp_path,
        "ai",
        "ai_inverted",
        severity={"model": "contextual", "default": "medium", "range": ["critical", "info"]},
    )
    assert "severity-range-malformed" in _codes(_verify(tmp_path))


def test_single_element_range_is_a_violation(tmp_path):
    _write_check(
        tmp_path,
        "ai",
        "ai_short_range",
        severity={"model": "contextual", "default": "medium", "range": ["high"]},
    )
    assert "severity-range-malformed" in _codes(_verify(tmp_path))


def test_default_outside_declared_range_is_a_violation(tmp_path):
    _write_check(
        tmp_path,
        "ai",
        "ai_outside",
        severity={"model": "contextual", "default": "critical", "range": ["info", "low"]},
    )
    assert "severity-default-outside-range" in _codes(_verify(tmp_path))


def test_violations_accumulate_rather_than_fail_fast(tmp_path):
    _write_check(tmp_path, "ai", "ai_one", severity={"model": "contextual"})
    _write_check(tmp_path, "web", "web_two", severity={"model": "fixed"})
    assert _codes(_verify(tmp_path)) == {
        "severity-contextual-without-default",
        "severity-fixed-without-severities",
    }


# ── wiring: contract -> check instance ───────────────────────────────


class _Probe(BaseCheck):
    name = "probe"
    description = "test double"

    async def run(self, context):  # pragma: no cover - never executed here
        raise NotImplementedError


def _build(severity=None):
    contract = CheckContract(
        id=str(uuid.uuid4()),
        name="probe",
        description="test double",
        entry="check.py:_Probe",
        suite="web",
        **({"severity": severity} if severity is not None else {}),
    )
    config = ConfigResolver(env={}).resolve("probe", _Probe, ComponentConfig(), None)
    return _Probe.from_config(contract, config)


def test_undeclared_contract_leaves_the_class_attributes_alone():
    check = _build()
    assert check.severity == {}
    assert check.provisional_severity == "info"


def test_contextual_default_becomes_the_provisional_severity():
    check = _build({"model": "contextual", "default": "high", "range": ["info", "critical"]})
    assert check.provisional_severity == "high"
    assert check.severity["model"] == "contextual"
    assert check.severity["rubric"] == ""


def test_fixed_observations_map_resolves_per_discriminator():
    check = _build({"model": "fixed", "observations": {"weak-csp": "high", "no-hsts": "medium"}})
    assert check.provisional_for("weak-csp") == "high"
    assert check.provisional_for("no-hsts") == "medium"


def test_unmapped_discriminator_falls_back_to_the_default():
    check = _build({"model": "fixed", "default": "low", "observations": {"weak-csp": "high"}})
    assert check.provisional_for("something-else") == "low"


def test_unmapped_discriminator_with_no_default_falls_back_to_the_class():
    check = _build({"model": "fixed", "observations": {"weak-csp": "high"}})
    assert check.provisional_for("something-else") == "info"


def test_create_candidate_takes_its_severity_from_the_map():
    check = _build({"model": "fixed", "observations": {"weak-csp": "high"}})
    assert check.create_candidate("h", discriminator="weak-csp").provisional_severity == "high"


def test_an_explicit_severity_still_beats_the_contract():
    check = _build({"model": "fixed", "observations": {"weak-csp": "high"}})
    candidate = check.create_candidate("h", discriminator="weak-csp", severity="info")
    assert candidate.provisional_severity == "info"


def test_severity_is_per_instance_not_shared_across_checks():
    declared = _build({"model": "fixed", "default": "high"})
    undeclared = _build()
    assert declared.severity and undeclared.severity == {}
