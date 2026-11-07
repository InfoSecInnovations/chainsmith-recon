"""
app/dev/registry_diff.py - Check-registry snapshot + diff.

The migration safety check. Confirms every pre-existing check still loads with
the same `(name, suite, conditions, produces)` identity across a structural
migration — catching silent drops or reorderings.

Hybrid by design (§8.1):
- **Snapshot core:** `save_baseline()` dumps the live registry to JSON while the
  old loader is live; `compare()` diffs the current registry against it. Because
  the baseline is captured before any `contract.yaml` exists, it works across the
  structural migration.
- `--rename-map`: a deliberate Category-A cleanup rename (§8.7) is treated as
  *expected* — "zero regressions" means identical set **after** applying the map.

"Suite" is derived with the existing `infer_suite()` (checks carry no suite
attribute), so the same derivation applies to hand-listed and discovered checks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _check_identity(check: Any) -> dict[str, Any]:
    """Capture the regression-relevant identity of one check instance."""
    from app.check_resolver import infer_suite

    return {
        "name": check.name,
        "suite": infer_suite(check.name),
        "conditions": sorted(str(c) for c in getattr(check, "conditions", [])),
        "produces": sorted(getattr(check, "produces", []) or []),
    }


def build_registry_snapshot() -> dict[str, dict[str, Any]]:
    """Snapshot the live check registry, keyed by check name.

    Uses the same resolution path the scanner uses (`get_real_checks()`), so it
    reflects hand-listed checks, discovered components, and custom checks alike.
    """
    from app.check_resolver import get_real_checks

    snapshot: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for check in get_real_checks():
        identity = _check_identity(check)
        if identity["name"] in snapshot:
            duplicates.append(identity["name"])
        snapshot[identity["name"]] = identity
    if duplicates:
        # Surface duplicate names loudly — a migration that double-loads a check
        # would otherwise be masked by dict overwrite.
        raise ValueError(f"Duplicate check names in live registry: {sorted(set(duplicates))}")
    return snapshot


def save_baseline(path: Path) -> int:
    """Dump the live registry to `path` (JSON). Returns the check count."""
    snapshot = build_registry_snapshot()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    return len(snapshot)


def _load_rename_map(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in raw.items()}


def _apply_rename(baseline: dict[str, dict], rename: dict[str, str]) -> dict[str, dict]:
    """Apply old_name → new_name to a baseline snapshot (keys + the `name` field)."""
    out: dict[str, dict] = {}
    for name, identity in baseline.items():
        new_name = rename.get(name, name)
        renamed = dict(identity)
        renamed["name"] = new_name
        out[new_name] = renamed
    return out


def compare(baseline_path: Path, rename_map_path: Path | None = None) -> dict[str, Any]:
    """Diff the current live registry against a saved baseline.

    Returns a report dict: {clean: bool, added, removed, changed}. `added`/`removed`
    are name lists; `changed` maps name → {field: [baseline, current]}.
    """
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    baseline = _apply_rename(baseline, _load_rename_map(rename_map_path))
    current = build_registry_snapshot()

    baseline_names = set(baseline)
    current_names = set(current)
    added = sorted(current_names - baseline_names)
    removed = sorted(baseline_names - current_names)

    changed: dict[str, dict[str, list]] = {}
    for name in sorted(baseline_names & current_names):
        b, c = baseline[name], current[name]
        diffs = {
            field: [b.get(field), c.get(field)]
            for field in ("suite", "conditions", "produces")
            if b.get(field) != c.get(field)
        }
        if diffs:
            changed[name] = diffs

    return {
        "clean": not (added or removed or changed),
        "baseline_count": len(baseline),
        "current_count": len(current),
        "added": added,
        "removed": removed,
        "changed": changed,
    }
