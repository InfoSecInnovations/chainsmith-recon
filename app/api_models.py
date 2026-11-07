"""
app/api_models.py - API Request/Response Models

Pydantic models for HTTP API endpoints.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# ─── Scope Models ─────────────────────────────────────────────


class ScopeInput(BaseModel):
    """Basic scope input."""

    target: str
    exclude: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)  # Empty = all techniques


class ScanWindowInput(BaseModel):
    """Time window for authorized testing."""

    start: str  # ISO format
    end: str  # ISO format


class ProofSettingsInput(BaseModel):
    """Proof of scope settings."""

    traffic_logging: bool = True
    screenshot_observations: bool = False
    hash_responses: bool = True


class OnCriticalSettings(BaseModel):
    """On-critical observation behavior settings."""

    default: str = "annotate"  # annotate, skip_downstream, stop
    overrides: dict[str, str] = Field(default_factory=dict)  # per-suite overrides


class ScanBehaviorSettings(BaseModel):
    """Scan behavior settings (on_critical + intrusive gating)."""

    on_critical: OnCriticalSettings | None = None
    intrusive_web: bool = False


class ExtendedScopeInput(BaseModel):
    """Extended scope with scan window and proof settings."""

    target: str
    exclude: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    scan_window: ScanWindowInput | None = None
    proof_of_scope: ProofSettingsInput | None = None
    scan_behavior: ScanBehaviorSettings | None = None


# ─── Scan Start Models ───────────────────────────────────────


class CheckOverride(BaseModel):
    """Per-check tunable override (§5.1 **layer 6b** — the runtime scalpel, 56.17).

    All fields optional; only the ones set override the resolved baseline. Used two
    ways with the SAME shape:
      * per-scan (ephemeral) — carried in `ScanStartInput.check_overrides` and
        applied onto the matching check instance AFTER the preset layer (6b > 6a);
      * save-as-default (persistent) — `PUT /api/v1/checks/{name}/config` writes the
        set fields into the check's `config.yaml` (layer 3).

    `on_critical: inherit` is valid layer-3 config but meaningless at scan time (the
    baseline is already resolved), so the scan path ignores it; it is accepted only
    so the one shape can also persist to config.yaml.
    """

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: float | None = Field(default=None, gt=0)
    requests_per_second: float | None = Field(default=None, gt=0)
    retry_count: int | None = Field(default=None, ge=0)
    delay_between_targets: float | None = Field(default=None, ge=0)
    on_critical: Literal["annotate", "skip_downstream", "stop", "inherit"] | None = None
    # How much of this check's traffic is recorded. Same
    # inherit caveat as on_critical — valid layer-3 config, ignored at scan time.
    capture: Literal["all", "observations_only", "none", "inherit"] | None = None


class CaptureInput(BaseModel):
    """Per-scan evidence-capture posture.

    Off by default and deliberately so: the machinery is complete, but nothing
    writes a byte of evidence until an operator asks for it and the growth
    number from §9 is understood. Turning it on is one flag.
    """

    enabled: bool = False
    #: Protocols to record. Empty means the defaults (http + llm); the socket
    #: and resolver protocols are opt-in because a `dns` row on a wide
    #: enumeration is cheap to write and rarely what a grader reads.
    protocols: list[str] = Field(default_factory=list)
    #: Record everything, overriding each check's own `capture:` policy.
    full_capture: bool = False
    #: Record probes that never completed, with `error` set and no response.
    capture_failures: bool = False


class ScanStartInput(BaseModel):
    """Optional body for POST /api/scan with check/suite filtering."""

    checks: list[str] = Field(default_factory=list)  # Run only these check names
    suites: list[str] = Field(default_factory=list)  # Run only checks from these suites
    port_profile: Literal["web", "ai", "full", "lab"] | None = None
    preset: str | None = None  # Named scan preset; explicit checks/suites/port_profile win over it
    # Per-check, per-scan tunable overrides (layer 6b). Keyed by check name; applied
    # after the preset's knob layer so an explicit edit beats a preset bundle.
    check_overrides: dict[str, CheckOverride] = Field(default_factory=dict)
    acknowledge_outside_window: bool = False  # Per-scan override for scan-window gate
    capture: CaptureInput | None = None  # Evidence capture posture (57.2); off unless asked


# ─── Settings Models ──────────────────────────────────────────


class ScanSettings(BaseModel):
    """Scan configuration settings."""

    parallel: bool = False
    rate_limit: float = 10.0
    default_techniques: list[str] = Field(default_factory=list)


# ─── Status/Info Models ───────────────────────────────────────


class ScanStatus(BaseModel):
    """Scan status response."""

    status: str
    phase: str
    target: str | None = None
    checks_total: int = 0
    checks_completed: int = 0
    current_check: str | None = None
    observations_count: int = 0
    error: str | None = None
    # Advertise SSE stream availability. UI opens an EventSource
    # only when {"stream": true} is present. Absence means fall back to polling.
    capabilities: dict[str, bool] = {}


class CheckInfo(BaseModel):
    """Check metadata."""

    name: str
    description: str
    reason: str = ""
    references: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    simulated: bool = False


class ObservationDetail(BaseModel):
    """Detailed observation information."""

    id: str
    title: str
    description: str
    severity: str
    evidence: str
    target_url: str | None = None
    check_name: str | None = None
    host: str | None = None


class ChainStatus(BaseModel):
    """Chain analysis status."""

    status: str
    chains_count: int = 0
    error: str | None = None


# ─── Scenario Models ──────────────────────────────────────────


class ScenarioLoadRequest(BaseModel):
    """Request to load a scenario."""

    name: str


# ─── Preferences/Profiles Models ──────────────────────────────


class PreferencesUpdateInput(BaseModel):
    """Update preferences."""

    parallel: bool | None = None
    rate_limit: float | None = None
    timeout_seconds: float | None = None
    max_observations_per_check: int | None = None
    politeness_delay: float | None = None
    llm_provider: str | None = None
    enabled_checks: list[str] | None = None
    disabled_checks: list[str] | None = None


class ProfileCreateInput(BaseModel):
    """Create a new profile."""

    name: str
    description: str = ""
    settings: dict = Field(default_factory=dict)


class ProfileUpdateInput(BaseModel):
    """Update an existing profile."""

    description: str | None = None
    settings: dict | None = None


# ─── Severity Override Models ────────────────────────────────────


class SeverityOverrideScope(BaseModel):
    """Scope for a scan severity override."""

    check_name: str | None = None
    title: str | None = None


class ScanSeverityOverrideInput(BaseModel):
    """Add/update a scan-specific severity override."""

    scope: SeverityOverrideScope
    severity: str
    reason: str | None = None


class ScanSeverityOverrideDeleteInput(BaseModel):
    """Remove a scan-specific severity override by scope."""

    scope: SeverityOverrideScope


class PreRunSeverityOverridesInput(BaseModel):
    """Full pre-run severity override config (replaces entire file)."""

    check_level: dict[str, str] = Field(default_factory=dict)
    check_title_level: dict[str, dict[str, str]] = Field(default_factory=dict)


class PreRunCheckOverrideInput(BaseModel):
    """Set a check-level severity override."""

    severity: str


class PreRunTitleOverrideInput(BaseModel):
    """Set a check+title severity override."""

    title: str
    severity: str
