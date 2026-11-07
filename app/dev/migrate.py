"""
app/dev/migrate.py - `migrate-check` / `migrate-suite`.

Takes a flat check file (e.g. `app/checks/web/robots.py`) and produces a
component folder (`app/checks/web/robots_txt/` with check.py, contract.yaml,
config.yaml, __init__.py re-export), codemods broken import paths, and removes
the entry from `check_resolver.get_real_checks()`.

Field derivation (§8.2) reads the **actual class attributes** by importing the
module — the most faithful reading of "read the existing `conditions`/`produces`
class attribute." (The *loader* never imports during validation, §6; the
migration tool is a dev-time generator and may.) `inspect` enumerates the concrete
BaseCheck subclasses defined in the file.

Folder name comes from the `name` *class attribute* (Category-A rename map
applied, §8.7) — never the filename. Per §8.5, only the four config tunables are
externalized into config.yaml and stripped from the class; identity/wiring/
helpers stay on the class and are mirrored (not moved) into contract.yaml.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.dev import codemod
from app.dev.scaffold import _TEMPLATE_DIR  # reuse the __init__ re-export template

# The four tunables externalized to config.yaml.defaults and stripped from the class (§8.5).
_CONFIG_TUNABLES = (
    "timeout_seconds",
    "requests_per_second",
    "retry_count",
    "delay_between_targets",
)

_NETWORK_HINTS = ("AsyncHttpClient", "httpx", "requests", "aiohttp", "socket", "dns")
_DB_HINTS = ("sqlite3", "sqlalchemy", "aiosqlite")
_FS_HINTS = ("open(", "pathlib", "Path(")


@dataclass
class MigrateResult:
    source: Path
    folders: list[Path] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)
    codemod_files: list[Path] = field(default_factory=list)
    removed_from_resolver: list[str] = field(default_factory=list)
    dry_run: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Module / class discovery
# ─────────────────────────────────────────────────────────────────────────────


def _dotted_package(directory: Path) -> str:
    parts: list[str] = []
    d = directory
    while (d / "__init__.py").exists():
        parts.append(d.name)
        d = d.parent
    return ".".join(reversed(parts))


def module_name_for_file(path: Path) -> str:
    pkg = _dotted_package(path.parent)
    return f"{pkg}.{path.stem}" if pkg else path.stem


def _concrete_check_classes(module: Any, module_name: str) -> list[type]:
    """Concrete BaseCheck subclasses *defined in* this module (not imported, not abstract)."""
    from app.checks.base import BaseCheck

    found: list[type] = []
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(obj, BaseCheck)
            and obj.__module__ == module_name
            and not inspect.isabstract(obj)
        ):
            found.append(obj)
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Field derivation (§8.2)
# ─────────────────────────────────────────────────────────────────────────────


def _description_for(cls: type) -> str:
    desc = getattr(cls, "description", "") or ""
    if desc and desc != "Base check - override this":
        return desc
    doc = inspect.getdoc(cls) or ""
    return doc.splitlines()[0].strip() if doc else f"{cls.name} check"


def _derive_side_effects(source_text: str) -> list[str]:
    effects: list[str] = []
    if any(h in source_text for h in _NETWORK_HINTS):
        effects.append("network")
    if any(h in source_text for h in _DB_HINTS):
        effects.append("db")
    if any(h in source_text for h in _FS_HINTS):
        effects.append("filesystem")
    return effects or ["none"]


def derive_contract(cls: type, suite: str, folder_name: str, source_text: str) -> dict[str, Any]:
    depends_on: list[dict[str, Any]] = []
    for cond in getattr(cls, "conditions", []) or []:
        entry: dict[str, Any] = {"output_name": cond.output_name, "operator": cond.operator}
        if getattr(cond, "value", None) is not None:
            entry["value"] = cond.value
        depends_on.append(entry)

    return {
        "id": str(uuid.uuid4()),
        "name": folder_name,
        "type": "check",
        "description": _description_for(cls),
        "entry": f"check.py:{cls.__name__}",
        "suite": suite,
        "depends_on": depends_on,
        "produces": list(getattr(cls, "produces", []) or []),
        "intrusive": bool(getattr(cls, "intrusive", False)),
        "service_types": list(getattr(cls, "service_types", []) or []),
        "parallel_safe": not bool(getattr(cls, "sequential", True)),
        "outputs": {"observations": ["Observation"]},
        "side_effects": _derive_side_effects(source_text),
        "techniques": list(getattr(cls, "techniques", []) or []),
        "references": list(getattr(cls, "references", []) or []),
        "reason": getattr(cls, "reason", "") or "",
    }


def derive_config(cls: type, enabled: bool = True) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "on_critical": "annotate",
        "defaults": {
            "timeout_seconds": getattr(cls, "timeout_seconds", 30.0),
            "requests_per_second": getattr(cls, "requests_per_second", 10.0),
            "retry_count": getattr(cls, "retry_count", 1),
            "delay_between_targets": getattr(cls, "delay_between_targets", 0.1),
        },
    }


def collect_todos(contract: dict[str, Any]) -> list[str]:
    todos: list[str] = []
    if not contract["description"] or contract["description"].startswith("TODO"):
        todos.append("description")
    if contract["side_effects"] == ["none"]:
        todos.append("side_effects (defaulted to none — verify)")
    return todos


# ─────────────────────────────────────────────────────────────────────────────
# Source rewriting
# ─────────────────────────────────────────────────────────────────────────────


def split_multiclass_source(source_text: str, class_names: list[str]) -> dict[str, str]:
    """Split a multi-check module into one self-contained source per check class.

    Each result reuses the module's shared *preamble* (docstring + imports —
    everything before the first class) plus exactly one class body, so every
    output is shaped like an ordinary single-class `check.py`. `ruff --fix`
    prunes whichever imports a given class doesn't use.

    Multi-class split is only safe when the classes are independent: it raises
    if the module has any shared module-level helper (a top-level function or
    assignment) or a non-check top-level class, because those would need a
    sibling helper module (§8.7) rather than being silently dropped/duplicated.
    """
    tree = ast.parse(source_text)
    lines = source_text.splitlines()
    spans: dict[str, tuple[int, int]] = {}
    first_class_line: int | None = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            start = node.lineno
            if node.decorator_list:
                start = min(d.lineno for d in node.decorator_list)
            spans[node.name] = (start, node.end_lineno or node.lineno)
            first_class_line = start if first_class_line is None else min(first_class_line, start)
            if node.name not in class_names:
                raise NotImplementedError(
                    f"top-level class '{node.name}' is not a check; multi-class split "
                    "needs a sibling helper module (§8.7)"
                )
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue  # module docstring / bare string
        else:
            raise NotImplementedError(
                "module has a shared module-level helper "
                f"({type(node).__name__} at line {node.lineno}); multi-class split "
                "needs a sibling helper module (§8.7)"
            )

    if first_class_line is None:
        raise ValueError("no class definitions to split")
    preamble = "\n".join(lines[: first_class_line - 1]).rstrip()
    out: dict[str, str] = {}
    for name in class_names:
        start, end = spans[name]
        body = "\n".join(lines[start - 1 : end]).rstrip()
        out[name] = f"{preamble}\n\n\n{body}\n"
    return out


def strip_config_tunables(source_text: str) -> str:
    """Remove class-body assignments of the four externalized tunables (§8.5)."""
    pattern = re.compile(rf"^[ \t]+({'|'.join(_CONFIG_TUNABLES)})\s*[:=].*\n", re.MULTILINE)
    return pattern.sub("", source_text)


def sanitize_self_imports(check_py: str, new_pkg_dotted: str) -> tuple[str, list[str]]:
    """Remove any self-referential import from the generated check.py.

    A freshly-migrated `check.py` lives at `<new_pkg_dotted>.check`; an import line
    `from <new_pkg_dotted>...` (e.g. `from app.checks.web.web_cors.check import ...`)
    is always wrong — it makes the module import from itself. This defends against
    a class of codemod edge cases observed in 56.2 (cors/openapi) regardless of the
    exact trigger. Returns (clean_text, removed_lines).
    """
    removed: list[str] = []
    out_lines: list[str] = []
    for line in check_py.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(f"from {new_pkg_dotted}"):
            removed.append(line.rstrip("\n"))
            continue
        out_lines.append(line)
    return "".join(out_lines), removed


def _yaml_dump(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def remove_from_resolver(class_names: list[str], resolver_path: Path) -> list[str]:
    """Remove a check's import-tuple entry and its `ClassName()` instantiation line."""
    text = resolver_path.read_text(encoding="utf-8")
    removed: list[str] = []
    for cn in class_names:
        # matches `    RobotsTxtCheck,` (import tuple) and `    RobotsTxtCheck(),` (instantiation)
        pat = re.compile(rf"^[ \t]*{re.escape(cn)}(\(\))?,[ \t]*(#.*)?\n", re.MULTILINE)
        text, n = pat.subn("", text)
        if n:
            removed.append(cn)
    resolver_path.write_text(text, encoding="utf-8")
    return removed


def cleanup_empty_suite_import(suite: str, resolver_path: Path, checks_root: Path) -> bool:
    """Remove a now-empty `from <pkg>.<suite> import (...)` block from the resolver.

    When an entire suite is migrated, all its names are removed from the import
    tuple, leaving `from ...web import (\\n)` — a SyntaxError. Collapse it.
    """
    pkg = ".".join(Path(checks_root).parts)
    text = resolver_path.read_text(encoding="utf-8")
    # `from app.checks.web import (` followed by only whitespace/commas then `)`
    pat = re.compile(
        rf"^[ \t]*from {re.escape(pkg)}\.{re.escape(suite)} import \([\s,]*\)\n",
        re.MULTILINE,
    )
    new_text, n = pat.subn("", text)
    if n:
        resolver_path.write_text(new_text, encoding="utf-8")
    return bool(n)


# ─────────────────────────────────────────────────────────────────────────────
# migrate-check
# ─────────────────────────────────────────────────────────────────────────────


def migrate_check(
    path: Path,
    rename_map: dict[str, str] | None = None,
    checks_root: Path = Path("app/checks"),
    dry_run: bool = False,
    resolver_path: Path = Path("app/check_resolver.py"),
    search_roots: list[Path] | None = None,
    enabled_names: set[str] | None = None,
) -> MigrateResult:
    """Migrate one flat check file into component folder(s).

    A file declaring one check becomes one folder. A multi-check file (the only
    one is `ai/endpoints.py`) becomes one folder per independent check — each
    shaped exactly like a single-class folder (§8.7). `enabled_names`, when given,
    is the set of check names currently registered; any check NOT in it gets
    `config.yaml enabled: false` so `discover_components` skips it, preserving a
    dormant check's dormancy across the migration (no-op when every check in the
    suite is registered, as with web/network).
    """
    path = Path(path)
    rename_map = rename_map or {}
    search_roots = search_roots or [Path("app"), Path("tests")]
    result = MigrateResult(source=path, dry_run=dry_run)

    suite = path.parent.name
    module_name = module_name_for_file(path)
    module = importlib.import_module(module_name)
    classes = _concrete_check_classes(module, module_name)
    if not classes:
        raise ValueError(f"No concrete BaseCheck subclass found in {path}")

    source_text = path.read_text(encoding="utf-8")
    old_dotted = module_name  # e.g. app.checks.web.robots
    init_tmpl = (_TEMPLATE_DIR / "__init__.py.tmpl").read_text(encoding="utf-8")
    checks_parts = Path(checks_root).parts

    # Per-class source: the whole file for a single check, else split by class (§8.7).
    if len(classes) > 1:
        class_bodies = split_multiclass_source(source_text, [c.__name__ for c in classes])
    else:
        class_bodies = {classes[0].__name__: source_text}

    class_to_pkg: dict[str, str] = {}  # imported class name → new package (multi-class codemod)
    for cls in classes:
        raw_name = cls.name
        folder_name = rename_map.get(raw_name, raw_name)
        enabled = enabled_names is None or raw_name in enabled_names
        contract = derive_contract(cls, suite, folder_name, source_text)
        config = derive_config(cls, enabled=enabled)
        result.todos.extend(collect_todos(contract))

        folder = Path(checks_root) / suite / folder_name
        package = ".".join((*checks_parts, suite, folder_name))
        new_pkg_dotted = package
        class_to_pkg[cls.__name__] = package

        check_py = strip_config_tunables(class_bodies[cls.__name__])
        # Category-A rename (§8.7): propagate to the `name` attr so class and
        # contract agree. Only rewrites on an actual rename.
        if folder_name != raw_name:
            check_py = re.sub(
                rf'(^\s*name\s*=\s*)["\']{re.escape(raw_name)}["\']',
                rf'\g<1>"{folder_name}"',
                check_py,
                count=1,
                flags=re.MULTILINE,
            )
        # Defensive: never emit a self-referential import (§56.2 cors/openapi guard).
        check_py, removed_self = sanitize_self_imports(check_py, new_pkg_dotted)
        if removed_self:
            result.todos.append(f"removed self-import(s): {removed_self}")

        if not dry_run:
            folder.mkdir(parents=True, exist_ok=False)
            (folder / "tests").mkdir(exist_ok=True)
            (folder / "check.py").write_text(check_py, encoding="utf-8")
            (folder / "contract.yaml").write_text(_yaml_dump(contract), encoding="utf-8")
            (folder / "config.yaml").write_text(_yaml_dump(config), encoding="utf-8")
            (folder / "__init__.py").write_text(
                init_tmpl.format(package=package, entry_stem="check", class_name=cls.__name__),
                encoding="utf-8",
            )

        result.folders.append(folder)
        result.todos.append(
            f"tests: extract {cls.__name__} tests into "
            f"{folder / 'tests' / f'test_{folder_name}.py'} "
            f"(patch target → {new_pkg_dotted}.check.<symbol>)"
        )

    # Remove the original flat module once all folders exist (refs codemodded below).
    if not dry_run:
        path.unlink()

    # Codemod broken references. Multi-class needs combined imports split per class
    # (each class moved to a different package); single-class uses the package
    # re-export rewrite + `.check` insertion for attribute/patch refs.
    if len(classes) > 1:
        cm = codemod.rewrite_imports_multiclass(
            old_dotted,
            class_to_pkg,
            search_roots,
            dry_run=dry_run,
            exclude_dirs=result.folders,
        )
        result.todos.append(
            "multi-class: attribute/patch refs to the old module are left for "
            "test co-location to disambiguate per-folder"
        )
    else:
        cm = codemod.rewrite_imports(
            old_dotted,
            class_to_pkg[classes[0].__name__],
            "check",
            search_roots,
            dry_run=dry_run,
            exclude_dirs=result.folders,
        )
    result.codemod_files = [r.file for r in cm]

    # Remove every migrated class from the hand-maintained resolver list.
    if not dry_run:
        result.removed_from_resolver = remove_from_resolver(
            [c.__name__ for c in classes], Path(resolver_path)
        )

    return result


def _currently_registered_names() -> set[str]:
    """Names in the live registry now — used to preserve a check's enabled state.

    Captured once, before any file is migrated, so a check that is dormant today
    (present as a flat file but absent from `get_real_checks()`) is migrated with
    `enabled: false` rather than being silently activated by auto-discovery.
    """
    from app.check_resolver import get_real_checks

    return {c.name for c in get_real_checks()}


def migrate_suite(
    suite: str,
    rename_map: dict[str, str] | None = None,
    checks_root: Path = Path("app/checks"),
    dry_run: bool = False,
) -> list[MigrateResult]:
    """Run migrate_check for every flat check file in a suite (§8.1 driver)."""
    suite_dir = Path(checks_root) / suite
    enabled_names = _currently_registered_names()
    results: list[MigrateResult] = []
    for py in sorted(suite_dir.glob("*.py")):
        if py.name in ("__init__.py",):
            continue
        try:
            results.append(
                migrate_check(py, rename_map, checks_root, dry_run, enabled_names=enabled_names)
            )
        except (ValueError, NotImplementedError) as e:
            r = MigrateResult(source=py, dry_run=dry_run)
            r.todos.append(f"SKIPPED: {e}")
            results.append(r)
    # If the whole suite migrated, its resolver import block is now empty — collapse it.
    if not dry_run:
        cleanup_empty_suite_import(suite, Path("app/check_resolver.py"), checks_root)
    return results
