"""
app/dev/scaffold.py - `chainsmith dev new-check`.

Generates a fresh component folder (check.py, contract.yaml with a stubbed UUID,
config.yaml, tests/test_<name>.py, __init__.py re-export) so contributors never
hand-write a UUID or edit `check_resolver.py`. Used for all post-56.1 new work.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "component"


def _class_name_from(name: str) -> str:
    """Default CamelCase entry class name from a slug (e.g. robots_txt → RobotsTxtCheck)."""
    base = "".join(part.capitalize() for part in name.split("_"))
    return f"{base}Check"


def _render(template_name: str, **kw: str) -> str:
    text = (_TEMPLATE_DIR / template_name).read_text(encoding="utf-8")
    return text.format(**kw)


@dataclass
class ScaffoldResult:
    folder: Path
    files: list[Path]


def new_check(
    name: str,
    suite: str,
    checks_root: Path = Path("app/checks"),
    description: str = "",
    class_name: str | None = None,
) -> ScaffoldResult:
    """Scaffold a new check component folder. Raises if the folder already exists."""
    if "__" in name:
        raise ValueError(f"component name '{name}' must not contain '__' (§5.1 lint)")
    class_name = class_name or _class_name_from(name)
    description = description or f"{name} check"
    folder = Path(checks_root) / suite / name
    if folder.exists():
        raise FileExistsError(f"{folder} already exists")
    package = ".".join((*Path(checks_root).parts, suite, name))

    folder.mkdir(parents=True)
    (folder / "tests").mkdir()

    ctx = {
        "name": name,
        "suite": suite,
        "description": description,
        "class_name": class_name,
        "package": package,
        "entry_stem": "check",
        "uuid": str(uuid.uuid4()),
    }

    written: list[Path] = []
    for tmpl, dest in [
        ("check.py.tmpl", folder / "check.py"),
        ("contract.yaml.tmpl", folder / "contract.yaml"),
        ("config.yaml.tmpl", folder / "config.yaml"),
        ("__init__.py.tmpl", folder / "__init__.py"),
        ("test.py.tmpl", folder / "tests" / f"test_{name}.py"),
    ]:
        dest.write_text(_render(tmpl, **ctx), encoding="utf-8")
        written.append(dest)

    return ScaffoldResult(folder=folder, files=written)
