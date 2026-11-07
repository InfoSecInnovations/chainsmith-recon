"""
D-6: a broken custom check is logged and skipped, not fatal to discovery.

Custom checks (`app/checks/custom/`) are written by operators and students. One
that fails its contract or fails to import used to raise from
`discover_components`, which took every check down with it. Now only that check
is skipped. A broken built-in check is still a hard error.
"""

import uuid

import pytest
import yaml

from app.component_loader import ComponentLoadError, discover_components

pytestmark = pytest.mark.unit

_ENTRY = """\
from app.checks.base import BaseCheck, CheckResult


class Foo(BaseCheck):
    async def run(self, context):
        return CheckResult(success=True)
"""


@pytest.fixture
def root(tmp_path, monkeypatch):
    """An importable synthetic check root: <tmp>/<pkg>/<suite>/<check>/check.py."""
    pkg = f"synthetic_checks_{uuid.uuid4().hex[:8]}"
    base = tmp_path / pkg
    base.mkdir()
    (base / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    return base


def _write(root, suite, name, *, entry=_ENTRY, severity=True, contract_name=None):
    suite_dir = root / suite
    suite_dir.mkdir(exist_ok=True)
    (suite_dir / "__init__.py").write_text("", encoding="utf-8")
    d = suite_dir / name
    d.mkdir()
    (d / "__init__.py").write_text("", encoding="utf-8")
    contract = {
        "id": str(uuid.uuid4()),
        "name": contract_name or name,
        "type": "check",
        "description": f"{name} description",
        "entry": "check.py:Foo",
        "suite": suite,
    }
    if severity:
        contract["severity"] = {"model": "fixed", "default": "info"}
    (d / "contract.yaml").write_text(yaml.safe_dump(contract), encoding="utf-8")
    (d / "check.py").write_text(entry, encoding="utf-8")


def _names(checks):
    return sorted(c.name for c in checks)


def test_a_custom_check_that_fails_to_import_is_skipped(root, caplog):
    _write(root, "web", "web_ok")
    _write(root, "custom", "custom_boom", entry="raise RuntimeError('boom')\n" + _ENTRY)

    with caplog.at_level("ERROR", logger="app.component_loader"):
        checks = discover_components(root, "check")

    assert _names(checks) == ["web_ok"]
    assert "custom_boom" in caplog.text


def test_a_custom_check_with_a_contract_violation_is_skipped(root, caplog):
    _write(root, "web", "web_ok")
    _write(root, "custom", "custom_noclass", entry="class NotFoo:\n    pass\n")

    with caplog.at_level("ERROR", logger="app.component_loader"):
        checks = discover_components(root, "check")

    assert _names(checks) == ["web_ok"]
    assert "entry-class-missing" in caplog.text


def test_a_custom_check_shadowing_a_built_in_name_is_the_one_skipped(root):
    # "custom" sorts before "web", so the duplicate violation lands on the web
    # folder. It must still be blamed on the custom one.
    _write(root, "web", "web_ok")
    _write(root, "custom", "web_ok_shadow", contract_name="web_ok")

    checks = discover_components(root, "check")

    assert _names(checks) == ["web_ok"]
    assert type(checks[0]).__module__.split(".")[1] == "web"


def test_good_custom_checks_still_load(root):
    _write(root, "web", "web_ok")
    _write(root, "custom", "custom_ok", severity=False)

    assert _names(discover_components(root, "check")) == ["custom_ok", "web_ok"]


def test_a_built_in_import_error_still_raises(root):
    _write(root, "web", "web_boom", entry="raise RuntimeError('boom')\n" + _ENTRY)

    with pytest.raises(RuntimeError, match="boom"):
        discover_components(root, "check")


def test_a_built_in_contract_violation_still_raises(root):
    _write(root, "web", "web_noclass", entry="class NotFoo:\n    pass\n")
    _write(root, "custom", "custom_ok", severity=False)

    with pytest.raises(ComponentLoadError):
        discover_components(root, "check")
