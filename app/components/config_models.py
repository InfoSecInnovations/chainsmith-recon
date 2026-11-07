"""
app/components/config_models.py - `config.yaml` / `suite.yaml` source models.

These are the per-source Pydantic models the `ConfigResolver` (§5.1) layers
together. Tunable knobs are `Optional` (None = "unset at this layer") so the
resolver can merge general→specific with last-non-None winning, without a
broad layer clobbering a narrow one with a default.

Identity lives in `contract.yaml`; these hold only runtime knobs an operator
may safely retune (§5.3 ownership rule). The two config systems
(`ChainsmithConfig` and this) stay separate — see §5.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# What to do when this component yields a CRITICAL observation.
# `inherit` resolves to the suite's on_critical, then the global default (§5.2).
OnCritical = Literal["annotate", "skip_downstream", "stop", "inherit"]

# Global fallback when nothing sets on_critical anywhere.
DEFAULT_ON_CRITICAL: str = "annotate"

# How much of what a component sends gets recorded as evidence.
# `inherit` resolves to the suite's policy, then the global
# default, exactly as `on_critical` does.
#
#   all                every exchange the check makes
#   observations_only  only the exchanges of a run that produced observations
#   none               nothing; the check is silent in the corpus
#
# The knob exists because HTTP path-probing is the real volume case:
# `web_path_probe`, `web_config_exposure`, `web_default_creds` and friends fire
# many requests each, mostly 404s, and HTTP captures by default. The check
# author knows their own volume; a scan-level flag cannot.
CapturePolicy = Literal["all", "observations_only", "none", "inherit"]

# Global fallback when nothing sets capture anywhere. Recording by default is
# the posture that makes a corpus; a check that should not be in it says so.
DEFAULT_CAPTURE_POLICY: str = "all"


class Defaults(BaseModel):
    """The standard tunable knob set (§8.2). All optional for layering."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: float | None = None
    requests_per_second: float | None = None
    retry_count: int | None = None
    delay_between_targets: float | None = None


class ComponentConfig(BaseModel):
    """Parsed `config.yaml` for a single component (§5).

    `parameters` holds per-component custom knobs that fall outside the standard
    `defaults` set. For *checks* it stays empty — their custom tunables remain
    class attributes until the phase-17 WebUI wave (§5 note). For *agents* it
    carries construction/engine knobs migrated out of `ChainsmithConfig` in
    56.10c (e.g. coach `memory_cap`, researcher `offline_mode`, the adjudicator/
    triage `context_file`, triage `kb_path`). `from_spec()` forwards the subset
    the agent constructor accepts; the rest are read via the registry accessor.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # false → loader skips the component
    reason: str = ""  # optional human note (e.g. why disabled); surfaced in introspection (56.15)
    on_critical: OnCritical = "annotate"
    capture: CapturePolicy = "inherit"  # how much evidence this check records (57.2)
    defaults: Defaults = Field(default_factory=Defaults)
    parameters: dict[str, object] = Field(default_factory=dict)


# Keys an operator might reasonably expect in `workspace.yaml` that no phase
# consumes yet. Declaring them inert would be worse than rejecting them: an
# operator who writes `scope:` and believes the engagement boundary is enforced,
# when it is not, is in a worse position than one who gets an error. Each maps
# to the phase that will make it real.
UNIMPLEMENTED_WORKSPACE_KEYS: dict[str, str] = {
    "scope": "not consumed yet — Guardian still takes scope per scan",
    "exclusions": "not consumed yet — Guardian still takes exclusions per scan",
    "scan_window": "not consumed yet — Guardian still takes the window per scan",
    "capture": "not consumed yet — arrives with evidence capture (57.2)",
    "retention": "not consumed yet — arrives with evidence capture (57.2)",
    "report": "not consumed yet — report headers are not workspace-aware",
}


class WorkspaceConfig(BaseModel):
    """Parsed `workspace.yaml` — config layer 5, the per-engagement policy layer.

    Deliberately narrow. `config_resolver.py` reserved layer 5 for a
    "user-override file", and this fills that slot, but it is **not** a general
    override mechanism: it carries only what is a property of the engagement
    rather than of a component. Today that is the standard knob set, which is
    what "this client is 2 rps, always" means.

    Note the layering is intentionally broad-beats-specific: a workspace default
    overrides a component's own `config.yaml`. That inverts the general→specific
    rule the lower layers follow, and it is the point — this layer expresses an
    operator policy ceiling for one engagement, not a better default. Per-check
    surgery belongs to layer 6b (`scan_overrides`, 56.17), which is scan-scoped
    and visible in the UI.
    """

    model_config = ConfigDict(extra="forbid")

    defaults: Defaults = Field(default_factory=Defaults)


class SuiteConfig(BaseModel):
    """Parsed `suite.yaml` — defaults shared by every check in a suite (§5.2)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool = True  # false → loader skips the whole suite
    on_critical: OnCritical = "annotate"  # parent for a check's on_critical: inherit
    capture: CapturePolicy = "inherit"  # parent for a check's capture: inherit (57.2)
    defaults: Defaults = Field(default_factory=Defaults)


@dataclass
class ResolvedConfig:
    """The fully-resolved load-time baseline (§5.1 layers 1-4) for one component.

    Produced by `ConfigResolver.resolve()` and applied onto the instance by
    `BaseCheck.from_config()`. Per-scan overrides (layer 6) are applied later in
    the scan path, never baked in here.
    """

    enabled: bool
    on_critical: str
    #: How much of this component's traffic is recorded.
    capture: str
    timeout_seconds: float
    requests_per_second: float
    retry_count: int
    delay_between_targets: float

    # Per-value layer attribution: knob/on_critical → the precedence
    # layer (§5.1) that won it — "class_default" | "suite" | "config" | "env"
    # (on_critical also: "default"). Surfaced read-only on /api/v1/checks +
    # `dev show-config`; never affects resolution. Defaulted so the few non-resolver
    # construction sites (tests) stay valid.
    provenance: dict[str, str] = field(default_factory=dict)
