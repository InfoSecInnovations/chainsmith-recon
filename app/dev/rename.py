"""
app/dev/rename.py - `rename-check` / `rename-suite`.

56.7 renames an *already-migrated* component folder so every check name becomes
`<suite>_<name>` (collision-proof by construction; §14.1). This is NOT the
flat-file → folder `migrate` flow — all suites are already in folder shape — so
it is a distinct, simpler operation: a folder rename + a dotted-package prefix
swap + a surgical, allowlisted name-string sweep.

Per check, `rename_check(suite, old, new)` does:

  Auto (safe, mechanical):
    1. Rename the folder `app/checks/<suite>/<old>/` → `.../<new>/`.
    2. Rewrite `contract.yaml` `name:` and the `check.py` `name = "<old>"` attr.
    3. Module-path codemod: `app.checks.<suite>.<old>` → `…<new>` across app/+tests/
       (word-boundary safe; a folder→folder rename is a plain prefix swap with NO
       `.check` insertion — refs already point at `.check`, unlike `migrate`).

  Surgical name-string sweep (allowlist, exact-quoted only):
    4. Replace `"<old>"` / `'<old>'` and finding-key `"<old>-…"` in chains.py,
       scan_analysis_advisor.py, scenario.json `expected_findings`, tests, and
       scan.html. NEVER simulations or data keys — see _NAME_REF_GLOBS / §14.3.

`infer_suite` is made prefix-aware-with-fallback separately (check_resolver.py)
so it stays correct while the sweep is mid-flight (some suites prefixed, some not).
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Allowlist for the name-string sweep (§14.3). Globs are resolved relative to cwd.
# Simulations are deliberately absent (out of regression scope, don't-touch) and
# their quoted path strings (`"network/foo.yaml"`) can't match an exact-quoted name
# anyway. Look-alike modules (app/tools/port_scan.py) are not in the list.
_NAME_REF_GLOBS = (
    "app/engine/chains.py",
    "app/advisors/scan_analysis/advisor.py",  # FOLLOW_UP_RULES trigger/suggest check-name refs
    "scenarios/*/scenario.json",
    "tests/**/*.py",
    "app/checks/*/*/tests/*.py",  # co-located check tests live under app/checks, not tests/
    "app/advisors/*/tests/*.py",  # co-located advisor tests (folder shape, 56.11)
    "app/gates/*/tests/*.py",  # co-located gate tests (folder shape, 56.12)
    "app/data/presets.yaml",  # preset `checks:` allowlists may name checks (56.14)
    "static/scan.html",
)
# NOT swept (separate namespaces, intentionally): app/advisors/check_proof/ keys
# proof templates by `check_type` (its own taxonomy, with a category fallback), and
# simulation YAMLs are out of regression scope. Matches the proven 56.5 MCP sweep.


@dataclass
class RenameResult:
    suite: str
    old_name: str
    new_name: str
    folder_from: Path
    folder_to: Path
    module_codemod_files: list[Path] = field(default_factory=list)
    name_ref_files: list[Path] = field(default_factory=list)
    dry_run: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Module-path codemod (folder→folder; plain prefix swap, no `.check` insertion)
# ─────────────────────────────────────────────────────────────────────────────


def _module_path_pattern(old_dotted: str) -> re.Pattern[str]:
    """Match `old_dotted` as a whole dotted path segment.

    Leading `(?<![\\w.])` so it isn't the tail of a longer path; trailing
    `(?=[.\\s"'\\)])` so it's followed by `.attr`, ` import`, a quote, or `)` —
    and crucially NOT `_` (so `…network.port_scan` never matches inside a
    hypothetical `…network.port_scan_v2`, and the already-renamed
    `…network.network_port_scan` is left alone).
    """
    return re.compile(rf"(?<![\w.]){re.escape(old_dotted)}(?=[.\s\"'\)])")


def rewrite_module_paths(
    old_dotted: str,
    new_dotted: str,
    search_roots: list[Path],
    *,
    dry_run: bool = False,
) -> list[Path]:
    """Swap every `old_dotted` package reference to `new_dotted` under the roots."""
    pat = _module_path_pattern(old_dotted)
    changed: list[Path] = []
    seen: set[Path] = set()
    for root in search_roots:
        for py in sorted(Path(root).rglob("*.py")):
            if py in seen:
                continue
            seen.add(py)
            original = py.read_text(encoding="utf-8")
            if old_dotted not in original:
                continue
            new_text, n = pat.subn(new_dotted, original)
            if n and new_text != original:
                if not dry_run:
                    py.write_text(new_text, encoding="utf-8")
                changed.append(py)
    return changed


# ─────────────────────────────────────────────────────────────────────────────
# Name-string sweep (allowlist, exact-quoted only)
# ─────────────────────────────────────────────────────────────────────────────


def collision_data_keys(checks_root: Path = Path("app/checks")) -> set[str]:
    """Every data key (`produces` + `depends_on` `output_name`) across all contracts.

    A check NAME that is also in this set (e.g. `dns_records`, produced as a data
    dependency *and* the name of a check) cannot be blanket-swept: the same quoted
    string means a check in one place and a data key in another. For such names we
    use anchored check-name patterns only (§14.3 collision handling).
    """
    keys: set[str] = set()
    for contract in Path(checks_root).rglob("contract.yaml"):
        raw = yaml.safe_load(contract.read_text(encoding="utf-8")) or {}
        for p in raw.get("produces", []) or []:
            keys.add(str(p))
        for c in raw.get("depends_on", []) or []:
            if isinstance(c, dict) and c.get("output_name"):
                keys.add(str(c["output_name"]))
    return keys


def _blanket_subs(old: str, new: str) -> list[tuple[re.Pattern[str], str]]:
    """Exact-quoted + finding-key replacement — safe only for non-collision names."""
    o = re.escape(old)
    return [
        (re.compile(rf'"{o}"'), f'"{new}"'),  # "port_scan"      → "network_port_scan"
        (re.compile(rf"'{o}'"), f"'{new}'"),  # 'port_scan'      → 'network_port_scan'
        (re.compile(rf'"{o}-'), f'"{new}-'),  # "port_scan-host" → "network_port_scan-host"
        (re.compile(rf"'{o}-"), f"'{new}-"),  # 'port_scan-host' → 'network_port_scan-host'
    ]


def _anchored_subs(old: str, new: str) -> list[tuple[re.Pattern[str], str]]:
    """Replace a check NAME only in unambiguous check-name contexts (collision-safe).

    Used for names that are ALSO data keys: `.name ==`, `.check_name ==`, kwarg /
    dict `check_name`/`check`/`name`, `emulates`, advisor `trigger_check`/`suggest`,
    `infer_suite("X")`, `"X" in …` membership, and finding-key `"X-…"`. NEVER the
    bare-quoted form, so `output_name == "X"`, `outputs["X"]`, `produces`, and
    `run({"X": …})` (all data-key uses) are left untouched.
    """
    o = re.escape(old)
    q = r"[\"']"
    nv = f'"{new}"'  # normalized double-quoted value (ruff format tolerates)
    return [
        (re.compile(rf"(\.name\s*==\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (re.compile(rf"(\.check_name\s*==\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (re.compile(rf"(\bcheck_name\s*=\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (re.compile(rf"({q}check_name{q}\s*:\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (re.compile(rf"({q}check{q}\s*:\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (re.compile(rf"({q}name{q}\s*:\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (
            re.compile(
                rf"({q}(?:trigger_check|suggest|suggest_check|emulates){q}\s*:\s*){q}{o}{q}"
            ),
            rf"\g<1>{nv}",
        ),
        (re.compile(rf"(\bemulates\s*=\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        (re.compile(rf"(infer_suite\(\s*){q}{o}{q}"), rf"\g<1>{nv}"),
        # membership ONLY in check-name collections — NOT `in produces`/`in
        # result.outputs`/`in e`, which are data-key contexts.
        (re.compile(rf"{q}{o}{q}(\s+in\s+(?:names|check_names|all_check_names)\b)"), rf"{nv}\g<1>"),
        (re.compile(rf"({q}){o}-"), rf"\g<1>{new}-"),  # finding key "X-host"
    ]


def _iter_name_ref_files(globs: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in globs:
        for p in sorted(Path().glob(pattern)):
            rp = p.resolve()
            # belt-and-suspenders: never sweep a simulations tree
            if "simulations" in p.parts:
                continue
            if rp not in seen and p.is_file():
                seen.add(rp)
                files.append(p)
    return files


def sweep_name_refs(
    old: str,
    new: str,
    globs: tuple[str, ...] = _NAME_REF_GLOBS,
    *,
    is_collision: bool = False,
    dry_run: bool = False,
) -> list[Path]:
    """Replace occurrences of the check NAME across the allowlist.

    `is_collision=True` (the name is also a data key) → anchored check-name
    patterns only; otherwise blanket exact-quoted replacement (§14.3).
    """
    subs = _anchored_subs(old, new) if is_collision else _blanket_subs(old, new)
    changed: list[Path] = []
    for f in _iter_name_ref_files(globs):
        original = f.read_text(encoding="utf-8")
        if old not in original:
            continue
        text = original
        for pat, repl in subs:
            text = pat.sub(repl, text)
        if text != original:
            if not dry_run:
                f.write_text(text, encoding="utf-8")
            changed.append(f)
    return changed


# ─────────────────────────────────────────────────────────────────────────────
# rename-check / rename-suite
# ─────────────────────────────────────────────────────────────────────────────


def _rewrite_name_attr(check_py: Path, old: str, new: str, dry_run: bool) -> None:
    text = check_py.read_text(encoding="utf-8")
    new_text = re.sub(
        rf'(^\s*name\s*=\s*)["\']{re.escape(old)}["\']',
        rf'\g<1>"{new}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if new_text == text:
        raise ValueError(f'could not find `name = "{old}"` in {check_py}')
    if not dry_run:
        check_py.write_text(new_text, encoding="utf-8")


def _rewrite_contract_name(contract: Path, old: str, new: str, dry_run: bool) -> None:
    text = contract.read_text(encoding="utf-8")
    new_text = re.sub(rf"^name:\s*{re.escape(old)}\s*$", f"name: {new}", text, count=1, flags=re.M)
    if new_text == text:
        raise ValueError(f"could not find `name: {old}` in {contract}")
    if not dry_run:
        contract.write_text(new_text, encoding="utf-8")


def rename_check(
    suite: str,
    old_name: str,
    new_name: str,
    *,
    checks_root: Path = Path("app/checks"),
    search_roots: list[Path] | None = None,
    name_ref_globs: tuple[str, ...] = _NAME_REF_GLOBS,
    data_keys: set[str] | None = None,
    dry_run: bool = False,
) -> RenameResult:
    """Rename one already-migrated check folder `<old_name>` → `<new_name>` (§14.3)."""
    if "__" in new_name:
        raise ValueError(f"new name '{new_name}' must not contain '__' (§5.1)")
    search_roots = search_roots or [Path("app"), Path("tests")]
    checks_root = Path(checks_root)
    src = checks_root / suite / old_name
    dst = checks_root / suite / new_name
    if not (src / "contract.yaml").exists():
        raise ValueError(f"{src} is not a migrated check folder (no contract.yaml)")
    if dst.exists():
        raise ValueError(f"target folder already exists: {dst}")

    result = RenameResult(
        suite=suite,
        old_name=old_name,
        new_name=new_name,
        folder_from=src,
        folder_to=dst,
        dry_run=dry_run,
    )

    old_dotted = ".".join((*checks_root.parts, suite, old_name))
    new_dotted = ".".join((*checks_root.parts, suite, new_name))

    # 1. Rename the folder (drop stale bytecode so the moved source recompiles clean).
    if not dry_run:
        pycache = src / "__pycache__"
        if pycache.exists():
            shutil.rmtree(pycache)
        src.rename(dst)
        edit_dir = dst
    else:
        edit_dir = src  # dry-run reads the still-in-place source

    # 2. contract.yaml + check.py name.
    _rewrite_contract_name(edit_dir / "contract.yaml", old_name, new_name, dry_run)
    _rewrite_name_attr(edit_dir / "check.py", old_name, new_name, dry_run)

    # 3. Module-path codemod (covers the moved folder's own __init__ + suite __init__).
    result.module_codemod_files = rewrite_module_paths(
        old_dotted, new_dotted, search_roots, dry_run=dry_run
    )

    # 4. Surgical name-string sweep across the allowlist. A name that is also a
    #    data key (produces/output_name) is collision-prone → anchored patterns only.
    if data_keys is None:
        data_keys = collision_data_keys(checks_root)
    result.name_ref_files = sweep_name_refs(
        old_name, new_name, name_ref_globs, is_collision=(old_name in data_keys), dry_run=dry_run
    )

    return result


def _suite_check_names(suite: str, checks_root: Path) -> list[str]:
    """Folder names under a suite that are migrated checks (have a contract.yaml)."""
    suite_dir = Path(checks_root) / suite
    names: list[str] = []
    for child in sorted(suite_dir.iterdir()):
        if child.is_dir() and (child / "contract.yaml").exists():
            names.append(child.name)
    return names


def append_rename_map(entries: dict[str, str], rename_map_path: Path) -> None:
    """Append `old: new` lines to the rename-map (diff-registry applies them, §14.5)."""
    lines = [f"{old}: {new}\n" for old, new in entries.items()]
    with rename_map_path.open("a", encoding="utf-8") as fh:
        fh.writelines(lines)


def rename_suite(
    suite: str,
    prefix: str,
    *,
    checks_root: Path = Path("app/checks"),
    rename_map_path: Path | None = None,
    dry_run: bool = False,
) -> list[RenameResult]:
    """Add `prefix` to every check in `suite` (§14.2). Skips already-prefixed checks."""
    results: list[RenameResult] = []
    applied: dict[str, str] = {}
    data_keys = collision_data_keys(checks_root)
    for old_name in _suite_check_names(suite, checks_root):
        if old_name.startswith(prefix):
            continue  # already prefixed — idempotent
        new_name = f"{prefix}{old_name}"
        results.append(
            rename_check(
                suite,
                old_name,
                new_name,
                checks_root=checks_root,
                data_keys=data_keys,
                dry_run=dry_run,
            )
        )
        applied[old_name] = new_name
    if applied and rename_map_path and not dry_run:
        append_rename_map(applied, Path(rename_map_path))
    return results
