"""
Pydantic Models for Recon Agent

Data models for observations, chains, scope, and agent state.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ComponentType(StrEnum):
    # Agents (LLM-powered)
    VERIFIER = "verifier"
    ADJUDICATOR = "adjudicator"
    TRIAGE = "triage"
    CHAINSMITH = "chainsmith"
    RESEARCHER = "researcher"
    COACH = "coach"

    # Gates (deterministic enforcement)
    GUARDIAN = "guardian"

    # Advisors (deterministic analysis)
    CHECK_PROOF_ADVISOR = "check_proof_advisor"


# Temporary alias for migration — remove after all references updated
AgentType = ComponentType


class ObservationSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ObservationStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    HALLUCINATION = "hallucination"


class EvidenceQuality(StrEnum):
    """Quality of evidence supporting a verification verdict."""

    DIRECT_OBSERVATION = "direct_observation"
    INFERRED = "inferred"
    CLAIMED_NO_PROOF = "claimed_no_proof"


class EventType(StrEnum):
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    OBSERVATION_VERIFIED = "observation_verified"
    OBSERVATION_REJECTED = "observation_rejected"
    HALLUCINATION_CAUGHT = "hallucination_caught"
    SCOPE_VIOLATION = "scope_violation"
    ADJUDICATION_START = "adjudication_start"
    ADJUDICATION_COMPLETE = "adjudication_complete"
    SEVERITY_UPHELD = "severity_upheld"
    SEVERITY_ADJUSTED = "severity_adjusted"
    TRIAGE_START = "triage_start"
    TRIAGE_COMPLETE = "triage_complete"
    TRIAGE_ACTION = "triage_action"
    RESEARCH_REQUESTED = "research_requested"
    RESEARCH_COMPLETE = "research_complete"
    CHAINSMITH_VALIDATION_START = "chainsmith_validation_start"
    CHAINSMITH_VALIDATION_COMPLETE = "chainsmith_validation_complete"
    CHAINSMITH_ISSUE_FOUND = "chainsmith_issue_found"
    CHAINSMITH_FIX_APPLIED = "chainsmith_fix_applied"
    CHAINSMITH_CUSTOM_CHECK_CREATED = "chainsmith_custom_check_created"
    CHAINSMITH_UPSTREAM_DIFF = "chainsmith_upstream_diff"
    ERROR = "error"
    INFO = "info"


class EventImportance(StrEnum):
    """Visual hierarchy for UI display."""

    HIGH = "high"  # 🔴 Red - significant observations
    MEDIUM = "medium"  # 🟡 Yellow - under verification
    LOW = "low"  # ⚪ Gray - routine enumeration


# ─── Scope Models ──────────────────────────────────────────────


class ScopeDefinition(BaseModel):
    """Rules of engagement for the recon operation."""

    in_scope_domains: list[str] = Field(default_factory=list)
    out_of_scope_domains: list[str] = Field(default_factory=list)
    in_scope_ports: list[int] = Field(default_factory=list)
    allowed_techniques: list[str] = Field(default_factory=list)
    forbidden_techniques: list[str] = Field(default_factory=list)
    time_window: str | None = None
    notes: str | None = None
    defined_at: datetime | None = None

    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in scope."""
        domain_lower = domain.lower()

        # Check explicit out-of-scope first
        for oos in self.out_of_scope_domains:
            if oos.lower() in domain_lower or domain_lower in oos.lower():
                return False

        # Check if matches in-scope patterns
        for in_scope in self.in_scope_domains:
            if in_scope.startswith("*."):
                # Wildcard match
                base = in_scope[2:].lower()
                if domain_lower.endswith(base) or domain_lower == base:
                    return True
            elif in_scope.lower() == domain_lower:
                return True

        return False

    def is_technique_allowed(self, technique: str) -> bool:
        """Check if a technique is allowed."""
        if technique in self.forbidden_techniques:
            return False
        return not (self.allowed_techniques and technique not in self.allowed_techniques)


# ─── Observation Models ────────────────────────────────────────


class RawEvidence(BaseModel):
    """Raw evidence captured during reconnaissance."""

    tool_name: str
    timestamp: datetime
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    status_code: int | None = None
    response_time_ms: float | None = None


class Observation(BaseModel):
    """A discovered observation from reconnaissance."""

    id: str
    observation_type: str
    title: str
    description: str
    severity: ObservationSeverity
    status: ObservationStatus = ObservationStatus.PENDING
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

    # Source information
    check_name: str | None = None
    discovered_at: datetime
    target_url: str | None = None
    target_service: str | None = None

    # Evidence
    raw_evidence: RawEvidence | None = None
    evidence_summary: str | None = None

    # Verification
    verified_by: ComponentType | None = None
    verified_at: datetime | None = None
    verification_notes: str | None = None
    evidence_quality: EvidenceQuality | None = None

    # Research enrichment (populated by Researcher agent)
    research_enrichment: "ResearchEnrichment | None" = None

    # For hallucinations
    is_hallucination: bool = False
    hallucination_reason: str | None = None

    # Exploitation hints
    exploitation_techniques: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    # Chain building
    chains_with: list[str] = Field(default_factory=list)
    severity_multiplier: float = 1.0

    # Adjudication (populated by AdjudicatorAgent)
    adjudicated_risk: "AdjudicatedRisk | None" = None


# ─── Adjudication Models ────────────────────────────────────���────


class AdjudicationApproach(StrEnum):
    """Approaches for severity adjudication.

    Only EVIDENCE_RUBRIC is actively used. The others are retained for
    backward compatibility with historical DB records. See
    docs/future-ideas/adjudicator-strategies-reference.md.
    """

    EVIDENCE_RUBRIC = "evidence_rubric"
    # Retired — kept for historical DB record deserialization
    STRUCTURED_CHALLENGE = "structured_challenge"
    ADVERSARIAL_DEBATE = "adversarial_debate"
    AUTO = "auto"


class AdjudicatedRisk(BaseModel):
    """Result of severity adjudication for a single observation."""

    observation_id: str
    original_severity: ObservationSeverity
    adjudicated_severity: ObservationSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    approach_used: AdjudicationApproach
    rationale: str
    factors: dict[str, Any] = Field(default_factory=dict)
    adjudicated_at: datetime = Field(default_factory=datetime.utcnow)
    adjudicated_by: ComponentType = ComponentType.ADJUDICATOR


class OperatorAssetContext(BaseModel):
    """Operator-declared context for a specific asset/domain."""

    domain: str
    exposure: str = "unknown"  # internet-facing, vpn-only, internal, unknown
    criticality: str = "medium"  # critical, high, medium, low
    notes: str | None = None


class OperatorContext(BaseModel):
    """Operator context loaded from ~/.chainsmith/adjudicator_context.yaml."""

    assets: list[OperatorAssetContext] = Field(default_factory=list)
    defaults: dict[str, str] = Field(
        default_factory=lambda: {"exposure": "unknown", "criticality": "medium"}
    )


# ─── Chain Models ──────────────────────────────────────────────


class AttackChain(BaseModel):
    """An attack chain combining multiple observations."""

    id: str
    title: str
    description: str
    impact_statement: str

    # Component observations
    observation_ids: list[str]

    # Severity
    individual_severities: list[ObservationSeverity]
    combined_severity: ObservationSeverity
    severity_reasoning: str

    # Attack path
    attack_steps: list[str]
    prerequisites: list[str] = Field(default_factory=list)

    # Metadata
    identified_by: ComponentType = ComponentType.CHAINSMITH
    identified_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)

    # References
    pattern_id: str | None = None
    references: list[str] = Field(default_factory=list)


# ─── Triage Models ─────────────────────────────────────────────


class ActionFeasibility(StrEnum):
    DIRECT = "direct"  # team can execute this action
    ESCALATE = "escalate"  # requires capabilities team lacks
    BLOCKED = "blocked"  # targets off-limits area


class TeamContext(BaseModel):
    """Team capabilities loaded from ~/.chainsmith/triage_context.yaml."""

    deployment_velocity: str | None = None  # yes | with_approval | no
    incident_response: str | None = None  # yes | partially | no
    remediation_surface: str | None = None  # both | app_only | infra_only | neither
    team_size: str | None = None  # solo | 2_to_3 | 4_plus
    off_limits: str | None = None  # free-text or None
    answered_at: datetime | None = None


class TriageAction(BaseModel):
    """A single prioritized remediation action."""

    priority: int
    action: str
    targets: list[str] = Field(default_factory=list)  # observation IDs
    chains_neutralized: list[str] = Field(default_factory=list)  # chain IDs
    reasoning: str
    effort_estimate: Literal["low", "medium", "high"]
    impact_estimate: Literal["low", "medium", "high"]
    feasibility: ActionFeasibility = ActionFeasibility.DIRECT
    remediation_guidance: list[str] = Field(default_factory=list)
    observations_resolved: list[str] = Field(default_factory=list)
    category: str = ""


class TriagePlan(BaseModel):
    """Complete prioritized remediation plan."""

    scan_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    actions: list[TriageAction] = Field(default_factory=list)
    summary: str = ""
    team_context_available: bool = False
    caveat: str | None = None
    quick_wins: int = 0
    strategic_fixes: int = 0
    workstreams: list[dict[str, Any]] | None = None


# ─── Research Enrichment Models ────────────────────────────────


class CVEDetail(BaseModel):
    """Structured CVE information from Researcher."""

    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    severity: str = ""
    published_date: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class ExploitInfo(BaseModel):
    """Public exploit information from Researcher."""

    source: str  # exploitdb, github, etc.
    url: str = ""
    description: str = ""
    verified: bool = False


class AdvisoryInfo(BaseModel):
    """Vendor advisory information from Researcher."""

    url: str
    summary: str = ""
    date: str | None = None
    vendor: str = ""


class ResearchEnrichment(BaseModel):
    """Structured enrichment data produced by Researcher agent."""

    observation_id: str
    cve_details: list[CVEDetail] = Field(default_factory=list)
    exploit_availability: list[ExploitInfo] = Field(default_factory=list)
    vendor_advisories: list[AdvisoryInfo] = Field(default_factory=list)
    version_vulnerabilities: list[str] = Field(default_factory=list)
    enriched_at: datetime = Field(default_factory=datetime.utcnow)
    data_sources: list[str] = Field(default_factory=list)
    offline_mode: bool = False


# ─── Proof Guidance Models ─────────────────────────────────────


class ProofStep(BaseModel):
    """A single reproduction step for proving a finding."""

    tool: str  # curl, nmap, burp, browser, etc.
    command: str  # exact command to run
    expected_output: str  # what confirms the finding
    screenshot_worthy: bool = False


class EvidenceChecklistItem(BaseModel):
    """An item in the evidence checklist for a finding."""

    description: str
    captured: bool = False  # false = operator still needs this


class ProofGuidance(BaseModel):
    """Complete proof guidance for a single finding."""

    finding_id: str
    finding_title: str
    verification_status: str
    evidence_quality: str | None = None

    proof_steps: list[ProofStep] = Field(default_factory=list)
    evidence_checklist: list[EvidenceChecklistItem] = Field(default_factory=list)
    severity_rationale: str = ""
    false_positive_indicators: list[str] = Field(default_factory=list)
    common_mistakes: list[str] = Field(default_factory=list)


# ─── Event Models ──────────────────────────────────────────────


class AgentEvent(BaseModel):
    """Event emitted by agents for the live feed."""

    event_type: EventType
    agent: ComponentType
    importance: EventImportance = EventImportance.LOW
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Content
    message: str
    details: dict[str, Any] | None = None

    # Related objects
    observation_id: str | None = None
    chain_id: str | None = None
    tool_name: str | None = None

    # For scope violations
    violation_url: str | None = None
    requires_approval: bool = False


# ─── Session Models ────────────────────────────────────────────


class SessionState(BaseModel):
    """Current state of a recon session."""

    session_id: str
    created_at: datetime

    # Scope
    scope_defined: bool = False
    scope: ScopeDefinition | None = None

    # Status
    is_running: bool = False
    is_paused: bool = False
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Observations
    observations: list[Observation] = Field(default_factory=list)
    chains: list[AttackChain] = Field(default_factory=list)

    # Stats
    total_tool_calls: int = 0
    hallucinations_caught: int = 0
    scope_violations: int = 0

    # Active randomizations
    active_observations: list[str] = Field(default_factory=list)
    active_hallucinations: list[str] = Field(default_factory=list)


# ─── Routing Models ───────────────────────────────────────────


class RouteDecision(BaseModel):
    """Result of prompt classification by the Prompt Router."""

    target: ComponentType | None
    method: Literal["context", "keyword", "llm", "direct"]
    confidence: float = 1.0
    redirect_message: str | None = None
    needs_clarification: bool = False
    clarification_prompt: str | None = None


# ─── API Request/Response Models ───────────────────────────────


class ScopeRequest(BaseModel):
    """Request for scoping conversation."""

    message: str


class ScopeResponse(BaseModel):
    """Response from scoping conversation."""

    response: str
    scope_complete: bool = False
    scope: ScopeDefinition | None = None


class LaunchRequest(BaseModel):
    """Request to launch recon."""

    pass


class LaunchResponse(BaseModel):
    """Response from launching recon."""

    status: str
    session_id: str
    message: str


class DirectiveRequest(BaseModel):
    """Request to direct an agent."""

    agent: ComponentType
    directive: str


class DirectiveResponse(BaseModel):
    """Response from directing an agent."""

    status: str
    message: str


class ObservationsResponse(BaseModel):
    """Response containing observations."""

    observations: list[Observation]
    total: int
    verified: int
    pending: int
    rejected: int


class ChainsResponse(BaseModel):
    """Response containing attack chains."""

    chains: list[AttackChain]
    total: int


class ExportResponse(BaseModel):
    """Response containing exported report."""

    report: dict[str, Any]
    generated_at: datetime


# Resolve forward references
Observation.model_rebuild()
