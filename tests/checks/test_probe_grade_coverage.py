"""
Suite-wide probe/grade coverage guard (Phase 57.4 exit condition, §8).

The migration is complete: every built-in check separates probe from grade.
These tests keep it that way, and they are what lets success criterion 1 (§10)
hold for *every* check rather than for the handful a unit test exercises:

- **Every built-in entry class has a `grade()`.** A check without one still
  works — its candidates come out `ungraded` — but it has quietly left the
  probe/grade model, and nothing else would notice.
- **No probe constructs an observation.** The grading stage is the only place
  that stamps `grading_state`, `grading_tier`, `evidence_ids` and
  `evidence_source` on an observation (`app/grading/stage.py`). A check that
  appends a hand-built observation bypasses it, and that observation traces to
  no evidence and names no tier.

`custom`-suite checks are excluded on purpose: the Chainsmith agent scaffolds
them in the legacy shape (O-5, parked).
"""

import ast
import importlib
from pathlib import Path

import pytest
import yaml

from app.component_loader import _module_for, parse_entry
from app.grading import is_graded_check

pytestmark = pytest.mark.unit

CHECKS_ROOT = Path(__file__).resolve().parents[2] / "app" / "checks"

# Calls that build an observation outside the grading stage.
_DIRECT_EMITTERS = {"build_observation", "create_observation", "Observation"}


def _builtin_checks() -> list[tuple[Path, dict]]:
    checks = []
    for contract_path in sorted(CHECKS_ROOT.rglob("contract.yaml")):
        raw = yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
        if raw.get("suite") == "custom":
            continue
        checks.append((contract_path.parent, raw))
    return checks


BUILTIN = _builtin_checks()
IDS = [comp_dir.name for comp_dir, _ in BUILTIN]


def test_the_guard_is_not_vacuous():
    assert BUILTIN, f"no built-in check contracts found under {CHECKS_ROOT}"


@pytest.mark.parametrize(("comp_dir", "raw"), BUILTIN, ids=IDS)
def test_every_builtin_check_has_a_grader(comp_dir, raw):
    filename, class_name = parse_entry(raw["entry"])
    entry_cls = getattr(importlib.import_module(_module_for(comp_dir, filename)), class_name)
    assert is_graded_check(entry_cls), (
        f"{raw['name']} has no grade(): its candidates would be reported ungraded forever. "
        "Split it into probe and grade (phase 57 §0.11)."
    )


@pytest.mark.parametrize(("comp_dir", "raw"), BUILTIN, ids=IDS)
def test_no_builtin_probe_builds_an_observation(comp_dir, raw):
    filename, _ = parse_entry(raw["entry"])
    tree = ast.parse((comp_dir / filename).read_text(encoding="utf-8"))

    called = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            called.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            called.add(node.func.attr)

    direct = sorted(called & _DIRECT_EMITTERS)
    assert not direct, (
        f"{raw['name']} calls {direct}: an observation built in the probe bypasses the "
        "grading stage and carries no grading tier or evidence. Return a Candidate and "
        "a Verdict instead."
    )
