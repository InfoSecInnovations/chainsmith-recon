"""
app/api_models.py - API Request/Response Models

Pydantic models for HTTP API endpoints.
"""

from typing import Optional
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
    end: str    # ISO format


class ProofSettingsInput(BaseModel):
    """Proof of scope settings."""
    traffic_logging: bool = True
    screenshot_findings: bool = False
    hash_responses: bool = True


class OnCriticalSettings(BaseModel):
    """On-critical finding behavior settings."""
    default: str = "annotate"  # annotate, skip_downstream, stop
    network: Optional[str] = None
    web: Optional[str] = None
    ai: Optional[str] = None
    mcp: Optional[str] = None
    agent: Optional[str] = None
    rag: Optional[str] = None
    cag: Optional[str] = None


class ScanBehaviorSettings(BaseModel):
    """Scan behavior settings (on_critical + intrusive gating)."""
    on_critical: Optional[OnCriticalSettings] = None
    intrusive_web: bool = False


class ExtendedScopeInput(BaseModel):
    """Extended scope with engagement window and proof settings."""
    target: str
    exclude: list[str] = []
    techniques: list[str] = []
    engagement_window: Optional[EngagementWindowInput] = None
    proof_of_scope: Optional[ProofSettingsInput] = None
    scan_behavior: Optional[ScanBehaviorSettings] = None


# ─── Scan Start Models ───────────────────────────────────────

class ScanStartInput(BaseModel):
    """Optional body for POST /api/scan with check/suite filtering."""
    checks: list[str] = []   # Run only these check names
    suites: list[str] = []   # Run only checks from these suites
    engagement_id: Optional[str] = None  # Link scan to an engagement
    port_profile: Optional[str] = None   # Port profile: web, ai, full, lab


# ─── Settings Models ──────────────────────────────────────────

class ScanSettings(BaseModel):
    """Scan configuration settings."""
    parallel: bool = False
    rate_limit: float = 10.0
    default_techniques: list[str] = []
    verification_level: str = "none"  # none, sample, half, all


# ─── Status/Info Models ───────────────────────────────────────

class ScanStatus(BaseModel):
    """Scan status response."""
    status: str
    phase: str
    target: Optional[str] = None
    checks_total: int = 0
    checks_completed: int = 0
    current_check: Optional[str] = None
    findings_count: int = 0
    error: Optional[str] = None


class CheckInfo(BaseModel):
    """Check metadata."""
    name: str
    description: str
    reason: str = ""
    references: list[str] = []
    techniques: list[str] = []
    simulated: bool = False


class FindingDetail(BaseModel):
    """Detailed finding information."""
    id: str
    title: str
    description: str
    severity: str
    evidence: str
    target_url: Optional[str] = None
    check_name: Optional[str] = None
    host: Optional[str] = None


class AttackChain(BaseModel):
    """Attack chain combining multiple findings."""
    id: str
    title: str
    description: str
    severity: str
    findings: list[str]  # Finding IDs
    exploitation_steps: list[str]


class ChainStatus(BaseModel):
    """Chain analysis status."""
    status: str
    chains_count: int = 0
    error: Optional[str] = None


# ─── Scenario Models ──────────────────────────────────────────

class ScenarioLoadRequest(BaseModel):
    """Request to load a scenario."""
    name: str


# ─── Preferences/Profiles Models ──────────────────────────────

class PreferencesUpdateInput(BaseModel):
    """Update preferences."""
    parallel: Optional[bool] = None
    rate_limit: Optional[float] = None
    timeout_seconds: Optional[float] = None
    max_findings_per_check: Optional[int] = None
    politeness_delay: Optional[float] = None
    llm_provider: Optional[str] = None
    enabled_checks: Optional[list[str]] = None
    disabled_checks: Optional[list[str]] = None


class ProfileCreateInput(BaseModel):
    """Create a new profile."""
    name: str
    description: str = ""
    settings: dict = {}


class ProfileUpdateInput(BaseModel):
    """Update an existing profile."""
    description: Optional[str] = None
    settings: Optional[dict] = None


# ─── Severity Override Models ────────────────────────────────────


class SeverityOverrideScope(BaseModel):
    """Scope for a scan severity override."""
    check_name: Optional[str] = None
    title: Optional[str] = None


class ScanSeverityOverrideInput(BaseModel):
    """Add/update a scan-specific severity override."""
    scope: SeverityOverrideScope
    severity: str
    reason: Optional[str] = None


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
