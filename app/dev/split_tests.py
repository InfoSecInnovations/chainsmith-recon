"""
app/dev/split_tests.py - Co-locate tests into component folders.

Splits a shared test file (e.g. tests/checks/test_web_api.py) so each test class
moves next to the check it exercises (app/checks/<suite>/<check>/tests/). A class
is mapped to a check by which imported check class it instantiates:

- exactly one check class referenced  → co-locate to that check's folder
- zero or multiple (cross-cutting, e.g. registry/coverage tests) → keep in place

Module-level imports + fixtures/helpers are copied into each co-located file;
unused imports are pruned afterward with `ruff --fix --select F401,F811`. The
original file is deleted if no classes remain, else rewritten with the residue.

Deterministic (AST-driven), so it's reliable even when interactive output is
unreliable — pytest collection is the oracle.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SplitPlan:
    source: Path
    # check folder (Path) -> list of class source segments
    per_check: dict[Path, list[str]] = field(default_factory=dict)
    residual_classes: list[str] = field(default_factory=list)
    preamble: str = ""  # imports + module-level fixtures/helpers (shared)
    written: list[Path] = field(default_factory=list)
    deleted_source: bool = False


def _check_class_to_folder(tree: ast.Module, checks_root: Path) -> dict[str, Path]:
    """Map a check *class name* -> its component folder.

    Import-path-independent: scans every component's contract.yaml for its `entry`
    class name and keys on that. This works whether a test imports the class via
    the suite package (`from app.checks.web import CorsCheck`), the component
    package (`from app.checks.web.web_cors import CorsCheck`), or the `.check`
    submodule — all three bind the same class name, and we map by name. (The
    `tree` arg is unused now but kept for signature stability.)
    """
    import yaml

    mapping: dict[str, Path] = {}
    for contract_path in Path(checks_root).rglob("contract.yaml"):
        folder = contract_path.parent
        try:
            data = yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        entry = data.get("entry", "")
        _, _, class_name = entry.partition(":")
        if class_name:
            mapping[class_name] = folder
    return mapping


def _names_used(node: ast.AST) -> set[str]:
    used: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            used.add(n.id)
    return used


def plan_split(source: Path, checks_root: Path = Path("app/checks")) -> SplitPlan:
    src = Path(source).read_text(encoding="utf-8")
    tree = ast.parse(src)
    src_lines = src.splitlines(keepends=True)

    def seg(node: ast.AST) -> str:
        # NB: node.lineno (and ast.get_source_segment) start at the `def`/`class`
        # line, DROPPING any decorators. For a module-level `@pytest.fixture`
        # that silently demotes the fixture to a plain function, breaking every
        # test that depends on it. Start the slice at the first decorator instead.
        start = node.lineno
        decorators = getattr(node, "decorator_list", None)
        if decorators:
            start = min(start, min(d.lineno for d in decorators))
        return "".join(src_lines[start - 1 : node.end_lineno]).rstrip("\n")

    class_to_folder = _check_class_to_folder(tree, checks_root)
    check_class_names = set(class_to_folder)

    plan = SplitPlan(source=Path(source))

    # Preamble = everything that is NOT a test class def: imports, module fixtures,
    # helper functions, constants. (Anything at module level except ClassDef.)
    # The original module docstring is dropped — apply_split prepends its own
    # co-location header, and keeping both leaves a bare string expr before the
    # imports (ruff E402: import not at top of file).
    preamble_parts: list[str] = []
    for idx, node in enumerate(tree.body):
        if (
            idx == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        if isinstance(node, ast.ClassDef):
            used = _names_used(node) & check_class_names
            folders = {class_to_folder[n] for n in used}
            if len(folders) == 1:
                folder = next(iter(folders))
                plan.per_check.setdefault(folder, []).append(seg(node))
            else:
                # 0 or >1 check classes → cross-cutting; keep in residual.
                plan.residual_classes.append(seg(node))
        else:
            preamble_parts.append(seg(node))

    plan.preamble = "\n".join(preamble_parts)
    return plan


def apply_split(plan: SplitPlan, dry_run: bool = False) -> SplitPlan:
    for folder, classes in plan.per_check.items():
        header = f'"""Tests for {folder.name}."""\n\n'
        tests_dir = folder / "tests"
        out = tests_dir / f"test_{folder.name}.py"
        # Collision: a co-located file already exists because another source file
        # also maps to this check. Do NOT append — appending glues on preamble-less
        # classes and silently drops THIS source's fixtures/helpers (e.g. a unique
        # mock_client_multi). Write a distinct file that carries its own full
        # preamble instead.
        if out.exists():
            suffix = plan.source.stem
            for pre in ("test_web_", "test_"):
                if suffix.startswith(pre):
                    suffix = suffix[len(pre) :]
                    break
            out = tests_dir / f"test_{folder.name}__{suffix}.py"
        body = header + plan.preamble + "\n\n\n" + "\n\n\n".join(classes) + "\n"
        if not dry_run:
            tests_dir.mkdir(exist_ok=True)
            out.write_text(body, encoding="utf-8")
        plan.written.append(out)

    # Rewrite or delete the source.
    if not dry_run:
        if plan.residual_classes:
            residual = plan.preamble + "\n\n\n" + "\n\n\n".join(plan.residual_classes) + "\n"
            plan.source.write_text(residual, encoding="utf-8")
        else:
            plan.source.unlink()
            plan.deleted_source = True
    return plan


def split_test_file(
    source: Path, checks_root: Path = Path("app/checks"), dry_run: bool = False
) -> SplitPlan:
    return apply_split(plan_split(source, checks_root), dry_run=dry_run)
