"""
B-12: `chainsmith dev new-check` scaffolds a check that passes every gate.

The contract template had no `severity:` block, so a freshly scaffolded
built-in check failed `verify-contracts` (`severity-undeclared`). The check
template was also in the pre-57.4 shape, with no `grade()`, which the probe/grade
coverage guard rejects for built-in checks.
"""

import ast
import subprocess
import sys

import pytest

from app.checks.base import CheckResult, Service
from app.component_loader import discover_components, verify_contracts
from app.dev.scaffold import new_check
from app.grading import grade_result, is_graded_check

pytestmark = pytest.mark.unit


@pytest.fixture
def scaffolded(tmp_path, monkeypatch):
    """Scaffold `web_widget` into an importable synthetic root under tmp_path."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    root = tmp_path / "synthetic_scaffold_root"
    (root / "web").mkdir(parents=True)
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "web" / "__init__.py").write_text("", encoding="utf-8")
    result = new_check("web_widget", "web", checks_root=root.relative_to(tmp_path))
    return root, result


def test_the_scaffold_passes_verify_contracts(scaffolded):
    root, _ = scaffolded
    assert verify_contracts(root, "check", env={}) == []


def test_the_scaffold_is_a_probe_grade_check(scaffolded):
    root, _ = scaffolded
    [check] = discover_components(root, "check")
    assert is_graded_check(check)

    source = (root / "web" / "web_widget" / "check.py").read_text(encoding="utf-8")
    called = {
        node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
    }
    assert not called & {"build_observation", "create_observation", "Observation"}


async def test_the_scaffold_runs_and_grades_to_nothing(scaffolded):
    root, _ = scaffolded
    [check] = discover_components(root, "check")
    service = Service(url="http://t.test", host="t.test", port=80, scheme="http")

    result = await check.check_service(service, {})
    assert isinstance(result, CheckResult)
    assert len(result.candidates) == 1

    await grade_result(check, result, {})
    assert result.observations == []


def test_the_scaffold_is_ruff_clean(scaffolded):
    root, res = scaffolded
    py_files = [str(p) for p in res.files if p.suffix == ".py"]
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-cache", "--isolated", *py_files],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
