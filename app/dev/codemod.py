"""
app/dev/codemod.py - Import-path rewriting for moved component modules.

When a flat check file moves into a component folder whose name differs from the
old filename (98 of 133 checks — suite-prefixed `mcp_`/`agent_`/`rag_`/`cag_` and
abbreviated AI files), the old module path vanishes. This rewrites the broken
references across `app/` and `tests/`.

Two reference *forms* need different targets, because the folder `__init__.py`
re-exports only the entry class (§3.1):

- **Import statements** — `from app.checks.<suite>.<oldstem> import X`
  → `from app.checks.<suite>.<folder> import X`
  (resolves through the package re-export; preserves class identity).

- **Attribute / string references** — e.g. `patch("app.checks.<suite>.<oldstem>.AsyncHttpClient")`
  → `...<folder>.check.AsyncHttpClient`
  (a module-level symbol that the package `__init__` does NOT re-export, so it must
  point at the `check` submodule where it's actually bound).

Same-name checks (folder == old stem) need no rewrite: the package transparently
replaces the old module.

Word-boundary safe: `app.checks.web.robots` is rewritten but the already-correct
`app.checks.web.robots_txt` is left untouched (the trailing `_` is a word char, so
no boundary match).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CodemodResult:
    file: Path
    replacements: int


def _import_pattern(old_dotted: str) -> re.Pattern[str]:
    # `from <old_dotted> import`  — only the bare-module import form.
    return re.compile(rf"(\bfrom\s+){re.escape(old_dotted)}(\s+import\b)")


def _attr_pattern(old_dotted: str) -> re.Pattern[str]:
    # `<old_dotted>.` followed by an attribute, NOT continuing the identifier
    # (so robots_txt is excluded) and NOT the `import` keyword form.
    return re.compile(rf"(?<![\w.]){re.escape(old_dotted)}(?=\.)")


def rewrite_text(
    text: str, old_dotted: str, new_pkg_dotted: str, entry_stem: str
) -> tuple[str, int]:
    """Rewrite one file's text. Returns (new_text, replacement_count)."""
    count = 0
    new_module_dotted = f"{new_pkg_dotted}.{entry_stem}"

    # 1. Import statements → package re-export path.
    text, n = _import_pattern(old_dotted).subn(rf"\g<1>{new_pkg_dotted}\g<2>", text)
    count += n

    # 2. Remaining attribute/string references → the .check submodule.
    #    (Import lines were already rewritten above, so these are the patch/attr forms.)
    text, n = _attr_pattern(old_dotted).subn(new_module_dotted, text)
    count += n

    return text, count


def _split_import_names(names: str) -> list[str]:
    """Parse the names part of `from X import <names>` into individual items.

    Handles parenthesized lists and `as` aliases. Returns items verbatim (e.g.
    `"Foo"`, `"Bar as B"`), so the alias is preserved when re-emitting.
    """
    return [s.strip() for s in names.strip().strip("()").split(",") if s.strip()]


def rewrite_imports_multiclass(
    old_dotted: str,
    class_to_pkg: dict[str, str],
    search_roots: list[Path],
    *,
    dry_run: bool = False,
    exclude_dirs: list[Path] | None = None,
) -> list[CodemodResult]:
    """Split combined imports from a multi-class module across its new packages.

    A flat file declaring N checks (e.g. `ai/endpoints.py` → LLMEndpointCheck +
    EmbeddingEndpointCheck) becomes N folders, so a single
    `from app.checks.ai.endpoints import EmbeddingEndpointCheck, LLMEndpointCheck`
    must split into one line per class, each pointing at that class's new package
    (`class_to_pkg` maps the *imported name* → new package dotted path).

    Only single-line `from <old_dotted> import …` statements are rewritten — the
    only form these modules use. Attribute/patch references
    (`<old_dotted>.AsyncHttpClient`) are intentionally left untouched: in a
    multi-class split the symbol lands in *every* new folder, so the correct
    target is ambiguous at the module level and is resolved per-file during test
    co-location (each co-located test file is single-folder by then).
    """
    import_re = re.compile(
        rf"^(?P<indent>[ \t]*)from {re.escape(old_dotted)} import (?P<names>.+?)[ \t]*$"
    )
    results: list[CodemodResult] = []
    seen: set[Path] = set()
    excludes = [Path(d).resolve() for d in (exclude_dirs or [])]
    for root in search_roots:
        for py in sorted(Path(root).rglob("*.py")):
            if py in seen:
                continue
            seen.add(py)
            resolved = py.resolve()
            if any(ex in resolved.parents for ex in excludes):
                continue
            original = py.read_text(encoding="utf-8")
            if old_dotted not in original:
                continue
            out: list[str] = []
            count = 0
            for line in original.splitlines():
                m = import_re.match(line)
                if not m:
                    out.append(line)
                    continue
                indent = m.group("indent")
                resolved_lines: list[str] = []
                unresolved: list[str] = []
                for item in _split_import_names(m.group("names")):
                    bound = item.split(" as ")[0].strip()
                    pkg = class_to_pkg.get(bound)
                    if pkg:
                        resolved_lines.append(f"{indent}from {pkg} import {item}")
                    else:
                        unresolved.append(item)
                if not resolved_lines:
                    out.append(line)  # nothing matched — leave as-is
                    continue
                out.extend(sorted(resolved_lines))
                if unresolved:
                    out.append(f"{indent}from {old_dotted} import {', '.join(unresolved)}")
                count += 1
            if count:
                new_text = "\n".join(out)
                if original.endswith("\n"):
                    new_text += "\n"
                if new_text != original and not dry_run:
                    py.write_text(new_text, encoding="utf-8")
                if new_text != original:
                    results.append(CodemodResult(py, count))
    return results


def rewrite_imports(
    old_dotted: str,
    new_pkg_dotted: str,
    entry_stem: str,
    search_roots: list[Path],
    *,
    dry_run: bool = False,
    exclude_dirs: list[Path] | None = None,
) -> list[CodemodResult]:
    """Rewrite every reference to `old_dotted` under the given roots.

    Run even when `old_dotted == new_pkg_dotted` (a same-name check): the import
    rewrite is then a no-op, but attribute/patch references still need the
    `.{entry_stem}` insertion because the package `__init__` re-exports only the
    entry class, not module-level symbols (e.g. AsyncHttpClient).

    Args:
        old_dotted: e.g. "app.checks.web.web_cors"
        new_pkg_dotted: the new folder package, e.g. "app.checks.web.web_cors"
        entry_stem: the entry module stem inside the folder, e.g. "check"
        search_roots: directories to scan for *.py files.
        dry_run: if True, do not write; only report what would change.
        exclude_dirs: directories to skip (e.g. the newly-created component folder,
            whose own `__init__.py`/`check.py` already use the correct paths and
            must not be double-rewritten).
    """
    results: list[CodemodResult] = []
    seen: set[Path] = set()
    excludes = [Path(d).resolve() for d in (exclude_dirs or [])]
    for root in search_roots:
        for py in sorted(Path(root).rglob("*.py")):
            if py in seen:
                continue
            seen.add(py)
            resolved = py.resolve()
            if any(ex in resolved.parents for ex in excludes):
                continue
            original = py.read_text(encoding="utf-8")
            if old_dotted not in original:
                continue
            new_text, count = rewrite_text(original, old_dotted, new_pkg_dotted, entry_stem)
            if count and new_text != original:
                if not dry_run:
                    py.write_text(new_text, encoding="utf-8")
                results.append(CodemodResult(py, count))
    return results
