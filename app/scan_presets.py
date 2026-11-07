"""app/scan_presets.py - Scan presets.

A **preset** is a named, scan-time bundle that layers on top of the per-component
config baseline (§5.1 **layer 6a**). It is orthogonal to the preference/profile
system (`app/preferences.py`, which tunes *behavior* — rate, LLM, network): a
preset says *what runs* and with *which per-check knobs*, and the two can be
active at once.

A preset carries two halves:

* **selection** — which checks run: ``suites`` / ``checks`` (name allowlist) /
  ``intrusive`` (``false`` → drop active-probing checks, the "passive" lens) /
  ``port_profile``.
* **defaults** — per-check knob overrides (``timeout_seconds`` /
  ``requests_per_second`` / ``retry_count`` / ``delay_between_targets``) plus
  ``on_critical``, applied onto every selected check instance at scan time.

**Precedence (§5.1 layer 6).** An explicit CLI/API selection (``--suite`` /
``--checks`` / ``--port-profile``) is the scalpel and BEATS a preset's selection
(6b > 6a). There is no per-scan param scalpel yet, so a preset's knob overrides
just apply (the 6b param slot is reserved for 56.15/56.17).

**Externalized + fallback-first.** Definitions live in ``app/data/presets.yaml``,
loaded via the :mod:`app.lib.datafiles` loader (56.13). ``_FALLBACK_PRESETS`` below
is byte-equivalent, so a missing/unparseable file degrades to exactly this set.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.check_resolver import _SUITE_NAMES
from app.checks.network.port_profiles import PROFILES as _PORT_PROFILES
from app.components.config_models import Defaults
from app.lib.datafiles import load_data

logger = logging.getLogger(__name__)

# on_critical values a preset may set. "inherit" is excluded on purpose: at scan
# time a check's on_critical is already resolved to a concrete value (§5.2), so a
# preset re-introducing "inherit" would be meaningless.
_PRESET_ON_CRITICAL = frozenset({"annotate", "skip_downstream", "stop"})

_PORT_PROFILE_NAMES = frozenset(_PORT_PROFILES)


# In-code fallback — kept byte-equivalent to app/data/presets.yaml (the test
# `test_shipped_presets_match_fallback` asserts this). If the data file is
# missing or unparseable, scans still get exactly these presets.
_FALLBACK_PRESETS: dict[str, dict] = {
    "quick": {
        "description": (
            "Fast surface-level recon — network + web suites only, narrow web "
            "port profile, single attempt per check. For a quick first look."
        ),
        "suites": ["network", "web"],
        "port_profile": "web",
        "defaults": {"retry_count": 1},
    },
    "thorough": {
        "description": (
            "Deep recon across every suite with the widest port profile and an "
            "extra retry. The slowest, most complete sweep."
        ),
        "port_profile": "lab",
        "defaults": {"retry_count": 2},
    },
    "passive": {
        "description": (
            "Non-intrusive checks only — no active probing, injection, or auth "
            "attempts. Lower request rate to stay quiet."
        ),
        "intrusive": False,
        "defaults": {"requests_per_second": 5.0},
    },
    "ai-focused": {
        "description": (
            "AI/LLM attack surface — ai, agent, rag, cag, and mcp suites. Skips "
            "the generic network/web checks to concentrate on model-facing "
            "weaknesses."
        ),
        "suites": ["ai", "agent", "rag", "cag", "mcp"],
    },
}


class Preset(BaseModel):
    """A parsed, validated scan preset (one entry from ``presets.yaml``)."""

    model_config = ConfigDict(extra="forbid")

    description: str = ""
    # selection
    suites: list[str] | None = None
    checks: list[str] | None = None
    intrusive: bool | None = None  # False → drop intrusive checks; None/True → no filter
    port_profile: str | None = None
    # scan-time knob overrides (layer 6a)
    defaults: Defaults = Field(default_factory=Defaults)
    on_critical: str | None = None

    @field_validator("suites")
    @classmethod
    def _known_suites(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            unknown = [s for s in v if s not in _SUITE_NAMES]
            if unknown:
                raise ValueError(f"unknown suite(s) {unknown}; known: {sorted(_SUITE_NAMES)}")
        return v

    @field_validator("port_profile")
    @classmethod
    def _known_port_profile(cls, v: str | None) -> str | None:
        if v is not None and v not in _PORT_PROFILE_NAMES:
            raise ValueError(f"unknown port_profile '{v}'; known: {sorted(_PORT_PROFILE_NAMES)}")
        return v

    @field_validator("on_critical")
    @classmethod
    def _known_on_critical(cls, v: str | None) -> str | None:
        if v is not None and v not in _PRESET_ON_CRITICAL:
            raise ValueError(f"on_critical '{v}' must be one of {sorted(_PRESET_ON_CRITICAL)}")
        return v


def _raw_presets() -> dict[str, dict]:
    """Load the raw preset table (fallback-first). Not cached — the file is tiny
    and resolution happens at most once per scan."""
    data = load_data("presets.yaml", _FALLBACK_PRESETS)
    if not isinstance(data, dict):
        logger.warning("presets.yaml is not a mapping; using inline fallback")
        return _FALLBACK_PRESETS
    return data


def preset_names() -> list[str]:
    """Sorted names of the available presets."""
    return sorted(_raw_presets())


def list_presets() -> dict[str, str]:
    """Map of preset name → description (for CLI/API/WebUI discovery)."""
    out: dict[str, str] = {}
    for name in sorted(_raw_presets()):
        p = get_preset(name)
        if p is not None:
            out[name] = p.description
    return out


def get_preset(name: str) -> Preset | None:
    """Parse and validate a single preset by name, or None if it doesn't exist.

    A malformed preset entry raises (it's an authoring error in presets.yaml,
    surfaced loudly rather than silently dropped).
    """
    raw = _raw_presets().get(name)
    if raw is None:
        return None
    return Preset(**raw)


def resolve_selection(
    preset: Preset | None,
    *,
    suites: list[str] | None,
    checks: list[str] | None,
    port_profile: str | None,
) -> tuple[list[str] | None, list[str] | None, str | None]:
    """Merge a preset's selection with explicit CLI/API selection (§5.1 layer 6).

    Explicit input is the scalpel and wins over the preset bundle (6b > 6a). Each
    field is resolved independently, so ``--preset quick --suite ai`` runs the AI
    suite (explicit) while still inheriting quick's port_profile + knobs.
    """
    eff_suites = suites if suites else (preset.suites if preset else None)
    eff_checks = checks if checks else (preset.checks if preset else None)
    eff_port_profile = port_profile if port_profile else (preset.port_profile if preset else None)
    return eff_suites, eff_checks, eff_port_profile


def apply_runtime(preset: Preset | None, checks: list) -> list:
    """Apply a preset's scan-time runtime layer to already-resolved checks.

    Two effects, both layer-6a (§5.1):
      1. **Intrusive filter** — ``intrusive: false`` drops every check whose
         ``intrusive`` attribute is truthy (the "passive" lens). Returns the
         filtered list. Any other value applies no filter.
      2. **Knob overrides** — each non-None field of ``defaults`` (+ ``on_critical``)
         is assigned onto the surviving check instances, overriding the load-time
         baseline `from_config` set.

    No-op (returns ``checks`` unchanged) when ``preset`` is None.
    """
    if preset is None:
        return checks

    if preset.intrusive is False:
        before = len(checks)
        checks = [c for c in checks if not getattr(c, "intrusive", False)]
        logger.info("Preset intrusive filter: %d → %d checks (passive)", before, len(checks))

    overrides: dict[str, object] = {
        knob: value
        for knob in (
            "timeout_seconds",
            "requests_per_second",
            "retry_count",
            "delay_between_targets",
        )
        if (value := getattr(preset.defaults, knob, None)) is not None
    }
    if preset.on_critical is not None:
        overrides["on_critical"] = preset.on_critical

    if overrides:
        for check in checks:
            for attr, value in overrides.items():
                setattr(check, attr, value)
        logger.info("Preset applied knob overrides %s to %d checks", overrides, len(checks))

    return checks
