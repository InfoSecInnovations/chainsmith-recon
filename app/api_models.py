"""
app/api_models.py - API Request/Response Models

Pydantic models for HTTP API endpoints.
"""

from pydantic import BaseModel

# ─── Scope Models ─────────────────────────────────────────────


class ScopeInput(BaseModel):
    """Basic scope input."""

    target: str
    exclude: list[str] = []
    techniques: list[str] = []  # Empty = all techniques


class EngagementWindowInput(BaseModel):
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
    network: str | None = None
    web: str | None = None
    ai: str | None = None
    mcp: str | None = None
    agent: str | None = None
    rag: str | None = None
    cag: str | None = None


class ScanBehaviorSettings(BaseModel):
    """Scan behavior settings (on_critical + intrusive gating)."""

    on_critical: OnCriticalSettings | None = None
    intrusive_web: bool = False


class ExtendedScopeInput(BaseModel):
    """Extended scope with engagement window and proof settings."""

    target: str
    exclude: list[str] = []
    techniques: list[str] = []
    engagement_window: EngagementWindowInput | None = None
    proof_of_scope: ProofSettingsInput | None = None
    scan_behavior: ScanBehaviorSettings | None = None


# ─── Scan Start Models ───────────────────────────────────────


class ScanStartInput(BaseModel):
    """Optional body for POST /api/scan with check/suite filtering."""

    checks: list[str] = []  # Run only these check names
    suites: list[str] = []  # Run only checks from these suites
    engagement_id: str | None = None  # Link scan to an engagement
    port_profile: str | None = None  # Port profile: web, ai, full, lab


class AdjudicateRequest(BaseModel):
    """Optional body for POST /api/adjudicate."""

    approach: str | None = None  # structured_challenge, adversarial_debate, evidence_rubric, auto


# ─── Settings Models ──────────────────────────────────────────


class ScanSettings(BaseModel):
    """Scan configuration settings."""

    parallel: bool = False
    rate_limit: float = 10.0
    default_techniques: list[str] = []


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


class CheckInfo(BaseModel):
    """Check metadata."""

    name: str
    description: str
    reason: str = ""
    references: list[str] = []
    techniques: list[str] = []
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
    settings: dict = {}


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

    check_level: dict[str, str] = {}
    check_title_level: dict[str, dict[str, str]] = {}


class PreRunCheckOverrideInput(BaseModel):
    """Set a check-level severity override."""

    severity: str


class PreRunTitleOverrideInput(BaseModel):
    """Set a check+title severity override."""

    title: str
    severity: str
