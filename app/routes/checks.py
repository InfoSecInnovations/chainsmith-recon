"""
app/routes/checks.py - Check Info Routes

Endpoints for:
- Listing available checks
- Check metadata and details
"""

import logging
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException

from app.api_models import CheckOverride
from app.check_resolver import get_all_check_metadata
from app.component_loader import find_component_dir
from app.components.config_models import ComponentConfig
from app.engine.scanner import AVAILABLE_CHECKS, get_check_info, rebuild_available_checks
from app.scenarios import get_scenario_manager

logger = logging.getLogger(__name__)

router = APIRouter()

# The numeric knobs that live under config.yaml `defaults:` (on_critical is top-level).
_KNOB_FIELDS = (
    "timeout_seconds",
    "requests_per_second",
    "retry_count",
    "delay_between_targets",
)
_CHECKS_ROOT = Path(__file__).resolve().parent.parent / "checks"


def _disabled_check_entry(meta) -> dict:
    """Shape a disabled check's metadata like a check-info dict (enabled=False).

    Disabled checks are never instantiated, so only contract/config metadata is
    available; execution-wiring fields default to empty for shape parity.
    """
    return {
        "name": meta.name,
        "description": meta.description,
        "reason": meta.reason,
        "references": [],
        "frameworks": {},
        "techniques": [],
        "conditions": [],
        "produces": [],
        "suite": meta.suite,
        "intrusive": False,
        "severity": dict(meta.severity or {}),
        "on_critical": meta.on_critical,
        # Shape parity with enabled entries (56.16). Disabled checks are never
        # imported, so the numeric knobs aren't resolved — only on_critical (from
        # the import-free metadata) is known; provenance is unavailable.
        "config": {
            "timeout_seconds": None,
            "requests_per_second": None,
            "retry_count": None,
            "delay_between_targets": None,
            "on_critical": meta.on_critical,
            "provenance": {},
        },
        "enabled": False,
    }


@router.get("/api/v1/checks")
async def get_available_checks(include_disabled: bool = False):
    """Get info about all available checks (reflects scenario mode).

    When a scenario is active, simulated checks overlay the real check
    registry (matched by name).  Real checks without a simulation are
    still included so the full suite is always visible.

    With `?include_disabled=true`, checks/suites turned off via `config.yaml`
    /`suite.yaml` `enabled: false` are appended (marked `enabled: false` with
    their `reason`), so the WebUI can offer a re-enable toggle.
    """
    mgr = get_scenario_manager()
    if mgr.is_active:
        simulations = mgr.get_simulations()
        # Build merged list: real checks + simulated overlays
        merged = dict(AVAILABLE_CHECKS)  # copy real checks
        for sim in simulations:
            info = get_check_info(sim)
            info["simulated"] = True
            merged[sim.name] = info  # replace real with sim
        checks = list(merged.values())
        scenario = mgr.active.name
        simulated = bool(simulations)
    else:
        checks = list(AVAILABLE_CHECKS.values())
        scenario = None
        simulated = False

    if include_disabled:
        # `enabled: true` on the live entries for shape parity (copy — don't
        # mutate the shared AVAILABLE_CHECKS dicts), then append the disabled
        # ones (those not present in the live, enabled-only registry).
        live_names = {c["name"] for c in checks}
        checks = [{**c, "enabled": True} for c in checks]
        checks += [
            _disabled_check_entry(m)
            for m in get_all_check_metadata()
            if not m.enabled and m.name not in live_names
        ]

    result = {"checks": checks, "simulated": simulated}
    if scenario is not None:
        result["scenario"] = scenario
    return result


@router.get("/api/v1/checks/{check_name}")
async def get_check_details(check_name: str):
    """Get detailed info about a specific check."""
    mgr = get_scenario_manager()
    if mgr.is_active:
        # Look in simulated checks first
        for check in mgr.get_simulations():
            if check.name == check_name:
                return get_check_info(check)
    if check_name not in AVAILABLE_CHECKS:
        raise HTTPException(404, f"Check '{check_name}' not found")
    return AVAILABLE_CHECKS[check_name]


@router.put("/api/v1/checks/{check_name}/config")
async def save_check_config_default(check_name: str, body: CheckOverride):
    """Persist tunable overrides into a check's `config.yaml` (§5.1 layer 3 — 56.17).

    The "save as default" sibling of the per-scan scalpel: the set fields are written
    into the check's `config.yaml` (`on_critical` and `capture` at top level; the
    numeric knobs under `defaults:`), so they become the resolved baseline for every
    future scan.
    Other config keys (`enabled`, `reason`, `parameters`) are preserved.

    NOTE: the file is rewritten with PyYAML, which does NOT preserve comments — the
    config.yaml header comments are lost on save (surfaced in the response `note`).
    The merged result is schema-validated before writing, and the in-memory display
    registry is refreshed so the change is visible immediately (no restart).
    """
    data = body.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(
            400, "No fields to save; provide at least one knob, on_critical, or capture."
        )

    comp_dir = find_component_dir(_CHECKS_ROOT, check_name)
    if comp_dir is None:
        raise HTTPException(404, f"Check '{check_name}' not found")

    cfg_path = comp_dir / "config.yaml"
    raw = {}
    if cfg_path.exists():
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise HTTPException(500, f"Existing config.yaml for '{check_name}' is not a mapping.")

    defaults = dict(raw.get("defaults") or {})
    for knob in _KNOB_FIELDS:
        if knob in data:
            defaults[knob] = data[knob]
    if defaults:
        raw["defaults"] = defaults
    if "on_critical" in data:
        raw["on_critical"] = data["on_critical"]
    if "capture" in data:
        raw["capture"] = data["capture"]

    # Validate the merged document still parses before touching the file.
    try:
        ComponentConfig(**raw)
    except Exception as e:
        raise HTTPException(400, f"Resulting config.yaml is invalid: {e}") from e

    cfg_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    rebuild_available_checks()  # refresh the display cache so the modal reflects it
    logger.info("Saved config default(s) for '%s': %s", check_name, data)

    return {
        "status": "saved",
        "check": check_name,
        "config_path": str(cfg_path),
        "saved": data,
        "note": "config.yaml comments are not preserved on save",
    }
