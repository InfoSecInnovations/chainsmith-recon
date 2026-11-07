"""app/scan_overrides.py - Per-check scan-time overrides (§5.1 **layer 6b**, 56.17).

The runtime *scalpel*: explicit per-check tunable overrides supplied with a single
scan, layered on top of everything below it — including a preset's knob bundle
(layer 6a). So `apply_check_overrides` runs AFTER `scan_presets.apply_runtime`
(6b > 6a). Each override targets one check by name and assigns the set fields onto
that already-resolved instance, exactly like `apply_runtime` does for presets.

Ephemeral by construction: it mutates the per-scan instances and touches nothing
on disk. The persistent sibling — writing a value into a check's `config.yaml`
(layer 3) — is the `PUT /api/v1/checks/{name}/config` "save as default" endpoint.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# The numeric knobs an override may set (same set BaseCheck.from_config applies).
_KNOBS = (
    "timeout_seconds",
    "requests_per_second",
    "retry_count",
    "delay_between_targets",
)


def apply_check_overrides(checks: list, overrides) -> list:
    """Assign per-check tunable overrides onto resolved instances (layer 6b).

    `overrides` maps check name → a `CheckOverride` model (or a plain dict) with
    optional `timeout_seconds` / `requests_per_second` / `retry_count` /
    `delay_between_targets` / `on_critical` / `capture`. Only set (non-None)
    fields apply.

    An override for a check that isn't in `checks` (deselected, disabled, or an
    unknown name) is silently skipped — there is no instance to scalpel. An
    `on_critical: inherit` is ignored (meaningless once the baseline is resolved).
    Returns `checks`; a no-op when `overrides` is empty.
    """
    if not overrides:
        return checks

    by_name = {c.name: c for c in checks}
    touched = 0
    for name, ov in overrides.items():
        check = by_name.get(name)
        if check is None:
            continue
        data = ov if isinstance(ov, dict) else ov.model_dump()
        applied = False
        for knob in _KNOBS:
            value = data.get(knob)
            if value is not None:
                setattr(check, knob, value)
                applied = True
        on_critical = data.get("on_critical")
        if on_critical is not None and on_critical != "inherit":
            check.on_critical = on_critical
            applied = True
        capture = data.get("capture")
        if capture is not None and capture != "inherit":
            check.capture = capture
            applied = True
        if applied:
            touched += 1

    if touched:
        logger.info("Applied per-check override(s) to %d check(s) (layer 6b)", touched)
    return checks
