"""
app/component_loader.py - Auto-discovery loader.

Replaces the hand-maintained import list in `check_resolver.get_real_checks()`.
Discovery is mechanical: walk a type root recursively for folders containing
`contract.yaml`; the folder name is the canonical slug.

Two public entry points:

- `verify_contracts(root, type)` — passes 1-3 only. Parses + validates contracts
  and folder hygiene WITHOUT importing any entry module, returning an accumulated
  list of `Violation`. This is the shared validator called from the loader, the
  `tests/test_contract_integrity.py` CI gate, and `chainsmith dev verify-contracts`
  (§8.6) — so "what CI enforces" can never drift from "what the loader enforces."

- `discover_components(root, type)` — runs `verify_contracts`, raises once with the
  full violation list if any, then imports the survivors and builds them via
  `from_config()` with the resolved config baseline (§5.1).

Validation is global-first and does NOT fail-fast per folder: a per-folder failure
(e.g. a name mismatch) can mask the real root cause (e.g. a duplicate UUID from a
copy-paste). Errors accumulate and are reported together (§6).
"""

from __future__ import annotations

import ast
import importlib
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.components.config_models import ComponentConfig, SuiteConfig
from app.components.config_resolver import (
    ENV_DELIM,
    ConfigResolver,
    active_env_overrides,
    detect_env_problems,
)
from app.components.contracts import contract_model_for

logger = logging.getLogger(__name__)

ComponentType = str  # "check" | "agent" | "advisor" | "gate"


@dataclass(frozen=True)
class Violation:
    """A single contract-integrity problem, surfaced by `verify_contracts`."""

    path: Path  # the component folder (or test file) at fault
    code: str  # machine-readable category, e.g. "duplicate-uuid"
    message: str  # human-readable detail

    def __str__(self) -> str:
        return f"[{self.code}] {self.path}: {self.message}"


class ComponentLoadError(Exception):
    """Raised by `discover_components` when `verify_contracts` finds violations."""

    def __init__(self, violations: list[Violation]):
        self.violations = violations
        body = "\n".join(f"  - {v}" for v in violations)
        super().__init__(f"{len(violations)} component contract violation(s):\n{body}")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def parse_entry(entry: str) -> tuple[str, str]:
    """Split an `entry` string ("check.py:ClassName") into (filename, class_name)."""
    filename, _, class_name = entry.partition(":")
    return filename, class_name


def _dotted_package(component_dir: Path) -> str:
    """Derive the importable dotted package for a folder by walking up through
    parents that are packages (have `__init__.py`). cwd-independent."""
    parts: list[str] = []
    d = component_dir
    while (d / "__init__.py").exists():
        parts.append(d.name)
        d = d.parent
    return ".".join(reversed(parts))


def _module_for(component_dir: Path, entry_filename: str) -> str:
    """Dotted module path for an entry file inside a component folder."""
    stem = Path(entry_filename).stem
    pkg = _dotted_package(component_dir)
    return f"{pkg}.{stem}" if pkg else stem


def find_component_dir(
    root: Path, name: str, component_type: ComponentType = "check"
) -> Path | None:
    """Locate a component's folder under `root` by its contract `name` (56.17).

    Walks `contract.yaml` files and returns the folder whose contract name matches,
    or None. Import-free (parses the contract only) and covers disabled components.
    Used by the "save as default" config-write endpoint to find which `config.yaml`
    to edit. Folder name == contract name is a loader invariant, but matching on the
    parsed name keeps this honest even mid-rename.
    """
    root = Path(root)
    if not root.exists():
        return None
    model_cls = contract_model_for(component_type)
    for contract_path in sorted(root.rglob("contract.yaml")):
        try:
            model = model_cls(**(yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}))
        except Exception:
            continue
        if model.name == name:
            return contract_path.parent
    return None


def _entry_class_def(tree: ast.Module, class_name: str) -> ast.ClassDef | None:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node
    return None


def _required_arg_names(func: ast.FunctionDef) -> list[str]:
    """Names of required (no-default) parameters of a function, excluding `self`."""
    a = func.args
    positional = a.posonlyargs + a.args
    # defaults align to the tail of positional params
    n_required_positional = len(positional) - len(a.defaults)
    required = [p.arg for p in positional[:n_required_positional] if p.arg != "self"]
    # keyword-only without a default are also required for a bare cls()
    required += [p.arg for p, d in zip(a.kwonlyargs, a.kw_defaults, strict=False) if d is None]
    return required


# Required constructor params that are legitimately *injected* by a component
# type's factory, so they don't violate the no-arg rule (§6). Checks are built
# no-arg by discover_components; agents are built per request/session by
# app/agents/registry.py with an injected LLMClient (56.10), so `client` is
# allowed to be a required positional there.
_INJECTED_REQUIRED: dict[str, set[str]] = {
    "agent": {"client"},
}

# Component types whose entry class is constructed by its CALLER with per-call
# data (not by the loader or a factory), so the no-arg/injected-required rule
# does not apply at all. Advisors (56.11) are deterministic but parameterized —
# the scan path / route builds them with launcher state or request scope it
# already holds. Gates (56.12) are the same shape: the scan route/scanner/
# launcher build a Guardian per scan via `from_scope(...)` with the operator's
# scope. They are still parsed, identity-checked, and folder-hygiene checked;
# only the __init__ constructibility assertion is skipped.
_CALLER_CONSTRUCTED: set[str] = {"advisor", "gate"}


# ─────────────────────────────────────────────────────────────────────────────
# verify_contracts — passes 1-3 (no imports)
# ─────────────────────────────────────────────────────────────────────────────


def verify_contracts(
    root: Path,
    component_type: ComponentType = "check",
    env: Mapping[str, str] | None = None,
) -> list[Violation]:
    """Validate every `contract.yaml` under `root` and folder hygiene (§6, §8.6).

    Never imports an entry module. Accumulates and returns all violations.

    As of 56.16 this also validates the tunable-config side (`config.yaml`,
    `suite.yaml`) against their schemas and — for the check root only — the
    per-component env-override namespace (`CHAINSMITH__<C>__<P>`): a var that
    names no known (check, knob) pair or carries an uncoercible value is a hard
    violation, so a typo'd deployment override fails at load instead of silently
    doing nothing. `env` defaults to `os.environ`; inject it in tests. CI sets no
    such vars, so the env pass is a clean no-op there.
    """
    root = Path(root)
    violations: list[Violation] = []
    if not root.exists():
        return violations

    model_cls = contract_model_for(component_type)

    # ── Pass 1: parse & collect (fail only on unparseable YAML) ──
    entries: list[tuple[Path, dict, object | None]] = []
    for contract_path in sorted(root.rglob("contract.yaml")):
        comp_dir = contract_path.parent
        try:
            raw = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            violations.append(Violation(comp_dir, "yaml-parse", f"contract.yaml unparseable: {e}"))
            continue
        if not isinstance(raw, dict):
            violations.append(Violation(comp_dir, "yaml-parse", "contract.yaml is not a mapping"))
            continue
        model = None
        try:
            model = model_cls(**raw)
        except Exception as e:  # pydantic ValidationError (and any constructor error)
            for line in str(e).splitlines():
                violations.append(Violation(comp_dir, "contract-schema", line.strip()))
        entries.append((comp_dir, raw, model))

    # ── Pass 2: global identity (canonical invariants, accumulate) ──
    by_uuid: dict[str, Path] = {}
    by_name: dict[str, Path] = {}
    for comp_dir, raw, model in entries:
        uid = str(model.id) if model is not None else raw.get("id")
        name = model.name if model is not None else raw.get("name")
        if uid:
            if uid in by_uuid:
                violations.append(
                    Violation(
                        comp_dir,
                        "duplicate-uuid",
                        f"UUID {uid} also used by {by_uuid[uid]}",
                    )
                )
            else:
                by_uuid[uid] = comp_dir
        if name:
            if name in by_name:
                violations.append(
                    Violation(
                        comp_dir,
                        "duplicate-name",
                        f"name '{name}' also used by {by_name[name]}",
                    )
                )
            else:
                by_name[name] = comp_dir

    # ── Pass 3: per-component hygiene (accumulate) ──
    for comp_dir, raw, model in entries:
        name = model.name if model is not None else raw.get("name")
        if name:
            if comp_dir.name != name:
                violations.append(
                    Violation(
                        comp_dir,
                        "folder-name-mismatch",
                        f"folder '{comp_dir.name}' != contract.name '{name}'",
                    )
                )
            if ENV_DELIM in name:
                violations.append(
                    Violation(
                        comp_dir,
                        "double-underscore",
                        f"component name '{name}' must not contain '{ENV_DELIM}'",
                    )
                )
        if model is not None:
            violations.extend(_verify_entry_constructible(comp_dir, model.entry, component_type))
            if component_type == "check":
                violations.extend(
                    _verify_severity(
                        comp_dir, getattr(model, "severity", None), getattr(model, "suite", None)
                    )
                )

    # ── Pass 3 (cont.): test-placement guard (§10 risk 2) ──
    for test_file in sorted(root.rglob("test_*.py")):
        parent = test_file.parent
        if parent.name != "tests" or not (parent.parent / "contract.yaml").exists():
            violations.append(
                Violation(
                    test_file,
                    "test-misplaced",
                    "test_*.py under a component root must live in <component>/tests/",
                )
            )

    # ── Pass 4: tunable-config schema (config.yaml + suite.yaml) (56.16) ──
    # The loader re-parses these during instantiation, but folding validation here
    # means the shared gate (loader + CI + `dev verify-contracts`) catches a bad
    # config the same way it catches a bad contract — accumulated, not a raw
    # pydantic error thrown mid-build.
    violations.extend(_verify_tunable_config(root, [comp_dir for comp_dir, _, _ in entries]))

    # ── Pass 5: env-override namespace (check root only) (56.16) ──
    # The env knobs are consumed only by checks (via ConfigResolver in
    # discover_components); other component types have their own registries.
    if component_type == "check":
        component_names = [
            (model.name if model is not None else raw.get("name")) for _, raw, model in entries
        ]
        component_names = [n for n in component_names if n]
        active_env = os.environ if env is None else env
        for _key, code, message in detect_env_problems(component_names, active_env):
            violations.append(Violation(root, code, message))

    return violations


def _verify_severity(
    comp_dir: Path, severity: object | None, suite: str | None = None
) -> list[Violation]:
    """Cross-field rules on a `contract.yaml` `severity:` block.

    **`severity-undeclared`** comes first: since §8's exit condition every
    built-in check declares a block, because without one `on_critical` has no
    provisional severity and a grader no model to honour. `custom`-suite checks
    are exempt — the Chainsmith agent scaffolds them without one (O-5, parked),
    and `discover_components` raises on *any* violation, so one scaffolded
    folder would otherwise fail discovery for every check. A custom check that
    does declare a block gets the same cross-field rules as any other.

    The *shape* is pydantic's job — unknown model, unknown level, stray key all
    surface as `contract-schema` during pass 1. What is left are the rules that
    span fields, and the one that matters is
    **`severity-contextual-without-default`**: a contextual check with no
    declared default has no answer for `on_critical`, which reads severity the
    moment the check finishes and long before a grader has placed one (§6.1).
    Phase 56.15 made that enforcement real, so letting a contextual check ship
    without a default would take `on_critical`'s input away exactly where it is
    used.

    The rest are anti-drift rules. `rubric`/`signals`/`range` on a `fixed`
    check are inert forever — not "inert until 58" — so an author who wrote one
    has misunderstood which model they picked, and silence would let that sit
    in the tree looking load-bearing.
    """
    if severity is None:
        if suite == "custom":
            return []
        return [
            Violation(
                comp_dir,
                "severity-undeclared",
                "a built-in check must declare a `severity:` block (model + default "
                "or observations) — on_critical reads it before any grader runs "
                "(§6.1, §8 exit condition)",
            )
        ]

    from app.components.contracts import SEVERITY_ORDER

    violations: list[Violation] = []
    model = getattr(severity, "model", None)
    default = getattr(severity, "default", None)
    observations = dict(getattr(severity, "observations", {}) or {})
    rng = list(getattr(severity, "range", []) or [])
    rubric = (getattr(severity, "rubric", "") or "").strip()
    signals = list(getattr(severity, "signals", []) or [])

    if model == "contextual":
        if not default:
            violations.append(
                Violation(
                    comp_dir,
                    "severity-contextual-without-default",
                    "model: contextual requires `default:` — on_critical reads "
                    "severity before a grader has placed one (§6.1)",
                )
            )
        if observations:
            violations.append(
                Violation(
                    comp_dir,
                    "severity-observations-on-contextual",
                    "`observations:` is a fixed-model map; a contextual check "
                    "declares `range:` and `rubric:` instead",
                )
            )
        if rng:
            if len(rng) != 2:
                violations.append(
                    Violation(
                        comp_dir,
                        "severity-range-malformed",
                        f"`range:` must be [weakest, strongest]; got {rng}",
                    )
                )
            elif SEVERITY_ORDER.index(rng[0]) > SEVERITY_ORDER.index(rng[1]):
                violations.append(
                    Violation(
                        comp_dir,
                        "severity-range-malformed",
                        f"`range: {rng}` is inverted; weakest comes first",
                    )
                )
            elif default and not (
                SEVERITY_ORDER.index(rng[0])
                <= SEVERITY_ORDER.index(default)
                <= SEVERITY_ORDER.index(rng[1])
            ):
                violations.append(
                    Violation(
                        comp_dir,
                        "severity-default-outside-range",
                        f"`default: {default}` is outside `range: {rng}`",
                    )
                )

    elif model == "fixed":
        if not observations and not default:
            violations.append(
                Violation(
                    comp_dir,
                    "severity-fixed-without-severities",
                    "model: fixed needs an `observations:` map (or a `default:`) "
                    "— otherwise it declares no severity at all",
                )
            )
        for field, value in (("rubric", rubric), ("signals", signals), ("range", rng)):
            if value:
                violations.append(
                    Violation(
                        comp_dir,
                        "severity-contextual-field-on-fixed",
                        f"`{field}:` applies to model: contextual; a fixed check "
                        "never calls a grader that would read it",
                    )
                )

    return violations


def _verify_tunable_config(root: Path, comp_dirs: list[Path]) -> list[Violation]:
    """Validate each component's `config.yaml` and each suite's `suite.yaml` against
    their Pydantic schemas (§5). Missing files are fine (defaults apply); only a
    present-but-invalid file is a violation. Accumulates, never imports."""
    violations: list[Violation] = []

    for comp_dir in comp_dirs:
        cfg_path = comp_dir / "config.yaml"
        if not cfg_path.exists():
            continue
        try:
            raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            violations.append(
                Violation(comp_dir, "config-yaml-parse", f"config.yaml unparseable: {e}")
            )
            continue
        if not isinstance(raw, dict):
            violations.append(
                Violation(comp_dir, "config-yaml-parse", "config.yaml is not a mapping")
            )
            continue
        try:
            ComponentConfig(**raw)
        except Exception as e:  # pydantic ValidationError (extra/type/enum)
            for line in str(e).splitlines():
                violations.append(Violation(comp_dir, "config-schema", line.strip()))

    # suite.yaml lives one level under root (root/<suite>/suite.yaml). Derive the
    # suite dirs from the component folders so non-suited trees (agents) are a no-op.
    suite_dirs = sorted({root / comp_dir.relative_to(root).parts[0] for comp_dir in comp_dirs})
    for suite_dir in suite_dirs:
        suite_yaml = suite_dir / "suite.yaml"
        if not suite_yaml.exists():
            continue
        try:
            raw = yaml.safe_load(suite_yaml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            violations.append(
                Violation(suite_dir, "suite-yaml-parse", f"suite.yaml unparseable: {e}")
            )
            continue
        if not isinstance(raw, dict):
            violations.append(
                Violation(suite_dir, "suite-yaml-parse", "suite.yaml is not a mapping")
            )
            continue
        raw.setdefault("name", suite_dir.name)
        try:
            SuiteConfig(**raw)
        except Exception as e:
            for line in str(e).splitlines():
                violations.append(Violation(suite_dir, "suite-schema", line.strip()))

    return violations


def _verify_entry_constructible(
    comp_dir: Path, entry: str, component_type: ComponentType = "check"
) -> list[Violation]:
    """AST-assert the entry class exists and its `__init__` requires only params
    the type's factory injects (§6/§8.6). Checks must be no-arg; agents may
    require the injected `client` (see `_INJECTED_REQUIRED`); caller-constructed
    types (advisors, `_CALLER_CONSTRUCTED`) are exempt from the __init__ rule
    entirely but still get the entry-exists/class-present checks."""
    violations: list[Violation] = []
    filename, class_name = parse_entry(entry)
    if not filename or not class_name:
        return [Violation(comp_dir, "entry-malformed", f"entry '{entry}' must be 'file.py:Class'")]
    entry_path = comp_dir / filename
    if not entry_path.exists():
        return [Violation(comp_dir, "entry-missing", f"entry file '{filename}' not found")]
    try:
        tree = ast.parse(entry_path.read_text(encoding="utf-8"))
    except SyntaxError as e:
        return [Violation(comp_dir, "entry-syntax", f"{filename}: {e}")]
    class_def = _entry_class_def(tree, class_name)
    if class_def is None:
        return [
            Violation(comp_dir, "entry-class-missing", f"class '{class_name}' not in {filename}")
        ]
    if component_type in _CALLER_CONSTRUCTED:
        return violations  # caller builds it with per-call data — no __init__ rule
    injected = _INJECTED_REQUIRED.get(component_type, set())
    for node in class_def.body:
        if isinstance(node, ast.FunctionDef) and node.name == "__init__":
            unexpected = [r for r in _required_arg_names(node) if r not in injected]
            if unexpected:
                violations.append(
                    Violation(
                        comp_dir,
                        "entry-not-constructible",
                        f"{class_name}.__init__ requires {unexpected}; "
                        f"must be constructible with only injected params {sorted(injected) or '[]'}",
                    )
                )
            break
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# discover_components — adds pass 4 (import + construct)
# ─────────────────────────────────────────────────────────────────────────────


def _load_suite_config(root: Path, suite: str) -> SuiteConfig | None:
    """Read `<root>/<suite>/suite.yaml` for precedence layer 2 (§5.2). Missing is fine."""
    suite_yaml = root / suite / "suite.yaml"
    if not suite_yaml.exists():
        return None
    raw = yaml.safe_load(suite_yaml.read_text(encoding="utf-8")) or {}
    raw.setdefault("name", suite)
    return SuiteConfig(**raw)


@dataclass(frozen=True)
class ComponentMeta:
    """Lightweight, import-free metadata for one component.

    Unlike `discover_components`, this surfaces DISABLED components too (and never
    imports an entry module), so the API/WebUI can list every check with an
    enable/disable toggle (§17 D7/D8). `enabled` is the *effective* value (the
    component's own flag AND its suite's `suite.yaml` enabled).
    """

    name: str
    suite: str
    component_type: str
    enabled: bool
    reason: str  # config.yaml `reason` (e.g. why disabled), "" if unset
    on_critical: str  # resolved against suite.yaml (no class default — import-free)
    description: str
    # The contract's declared `severity:` block, {} when undeclared (57.4, §7).
    severity: dict


def discover_component_metadata(
    root: Path, component_type: ComponentType = "check"
) -> list[ComponentMeta]:
    """List metadata for every component under `root`, INCLUDING disabled ones.

    Reads `contract.yaml` + `config.yaml` (+ `suite.yaml`) only — never imports an
    entry module — so it is safe to call for components the loader would skip.
    Malformed contracts are silently omitted here (the `verify_contracts` gate is
    the place that reports them); this function is for display, not validation.
    """
    root = Path(root)
    out: list[ComponentMeta] = []
    if not root.exists():
        return out

    model_cls = contract_model_for(component_type)
    for contract_path in sorted(root.rglob("contract.yaml")):
        comp_dir = contract_path.parent
        try:
            contract = model_cls(
                **(yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {})
            )
        except Exception:
            continue  # malformed — verify_contracts surfaces it; skip for display

        cfg_path = comp_dir / "config.yaml"
        if cfg_path.exists():
            comp_cfg = ComponentConfig(
                **(yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {})
            )
        else:
            comp_cfg = ComponentConfig()

        suite = comp_dir.relative_to(root).parts[0]
        suite_cfg = _load_suite_config(root, suite)
        suite_enabled = suite_cfg.enabled if suite_cfg is not None else True

        out.append(
            ComponentMeta(
                name=contract.name,
                suite=suite,
                component_type=component_type,
                enabled=comp_cfg.enabled and suite_enabled,
                reason=comp_cfg.reason,
                on_critical=ConfigResolver._resolve_on_critical(comp_cfg.on_critical, suite_cfg),
                description=getattr(contract, "description", "") or "",
                severity=(
                    declared.model_dump()
                    if (declared := getattr(contract, "severity", None)) is not None
                    else {}
                ),
            )
        )

    out.sort(key=lambda m: (m.suite, m.name))
    return out


_CUSTOM_SUITE = "custom"


def _custom_component_dir(root: Path, component_type: str, path: Path) -> Path | None:
    """The `custom/<check>` folder `path` sits in, or None if it is not in one.

    Only the check root has a custom suite.
    """
    if component_type != "check":
        return None
    try:
        parts = Path(path).resolve().relative_to(root.resolve()).parts
    except ValueError:
        return None
    if len(parts) < 2 or parts[0] != _CUSTOM_SUITE:
        return None
    return (root / parts[0] / parts[1]).resolve()


def _is_custom_check(root: Path, component_type: str, comp_dir: Path) -> bool:
    return _custom_component_dir(root, component_type, comp_dir) is not None


def _split_custom_violations(
    root: Path, component_type: str, violations: list[Violation]
) -> tuple[set[Path], list[Violation]]:
    """Separate violations that belong to a custom check from the rest (D-6).

    Returns the custom folders to skip, and the violations that must still
    raise. A duplicate name or UUID between a custom check and a built-in one is
    blamed on the custom check, whichever folder sorts first. A custom check may
    not shadow a built-in one.
    """
    skip: set[Path] = set()
    remaining: list[Violation] = []
    custom_root = (root / _CUSTOM_SUITE).resolve()

    for violation in violations:
        comp = _custom_component_dir(root, component_type, violation.path)
        if comp is None and violation.code in ("duplicate-uuid", "duplicate-name"):
            # The message names the other folder: "... also used by <path>".
            other = violation.message.rsplit(" also used by ", 1)[-1]
            if str(custom_root) in str(Path(other).resolve()):
                comp = _custom_component_dir(root, component_type, Path(other))
        if comp is None:
            remaining.append(violation)
            continue
        skip.add(comp)
        logger.error("Skipping custom check at %s: %s", comp.name, violation)

    return skip, remaining


def discover_components(root: Path, component_type: ComponentType = "check") -> list:
    """Discover, validate, and instantiate every enabled component under `root` (§6).

    Returns a suite-grouped, stable-sorted list (deterministic discovery output;
    runtime execution order is decided later by check_launcher.py over the
    conditions/produces DAG).
    """
    root = Path(root)
    violations = verify_contracts(root, component_type)
    # D-6: a broken *custom* check (operator- or student-written) is logged and
    # skipped, so it costs only itself. A built-in violation is a bug in the tree
    # and still stops discovery. `dev verify-contracts` and CI report both.
    skipped_custom, violations = _split_custom_violations(root, component_type, violations)
    if violations:
        raise ComponentLoadError(violations)

    model_cls = contract_model_for(component_type)

    # Layer 5 (57.1b): the active workspace's `workspace.yaml`, if it has one.
    # A malformed file raises rather than being skipped — a config the operator
    # wrote and Chainsmith ignored is the failure this layer exists to prevent.
    from app.workspace import load_workspace_config

    resolver = ConfigResolver(workspace_config=load_workspace_config())
    built: list[tuple[str, str, object]] = []

    for contract_path in sorted(root.rglob("contract.yaml")):
        comp_dir = contract_path.parent
        if comp_dir.resolve() in skipped_custom:
            continue
        contract = model_cls(**yaml.safe_load(contract_path.read_text(encoding="utf-8")))

        # config.yaml (per-component) — disabled components are skipped (§6).
        cfg_path = comp_dir / "config.yaml"
        if cfg_path.exists():
            comp_cfg = ComponentConfig(
                **(yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {})
            )
        else:
            comp_cfg = ComponentConfig()
        if not comp_cfg.enabled:
            logger.info("Skipping disabled component: %s", contract.name)
            continue

        suite = comp_dir.relative_to(root).parts[0]
        suite_cfg = _load_suite_config(root, suite)
        if suite_cfg is not None and not suite_cfg.enabled:
            logger.info("Skipping component in disabled suite '%s': %s", suite, contract.name)
            continue

        try:
            filename, class_name = parse_entry(contract.entry)
            module_name = _module_for(comp_dir, filename)
            mod = importlib.import_module(module_name)
            entry_cls = getattr(mod, class_name)

            resolved = resolver.resolve(contract.name, entry_cls, comp_cfg, suite_cfg)
            instance = entry_cls.from_config(contract, resolved)
        except Exception:
            if not _is_custom_check(root, component_type, comp_dir):
                raise
            # D-6: an import or construction error in one custom check skips it.
            logger.error(
                "Skipping custom check '%s': it failed to load", contract.name, exc_info=True
            )
            continue
        built.append((suite, contract.name, instance))

    built.sort(key=lambda t: (t[0], t[1]))
    logger.info("Discovered %d %s component(s)", len(built), component_type)

    # Startup surfacing (56.16): one-line summary of which per-component env
    # overrides are actually in effect. Checks-only (the lone env-knob consumer).
    if component_type == "check":
        overrides = active_env_overrides([name for _, name, _ in built], os.environ)
        if overrides:
            summary = ", ".join(f"{name}.{param}={value}" for name, param, value in overrides)
            logger.info("Active env config override(s) [%d]: %s", len(overrides), summary)

    return [inst for _, _, inst in built]
