"""
Pydantic Models for Recon Agent

Data models for observations, chains, scope, and agent state.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AgentType(StrEnum):
    SCOUT = "scout"
    VERIFIER = "verifier"
    CHAINSMITH = "chainsmith"
    GUARDIAN = "guardian"
    ADJUDICATOR = "adjudicator"


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


class EventType(StrEnum):
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    OBSERVATION_DISCOVERED = "observation_discovered"
    OBSERVATION_VERIFIED = "observation_verified"
    OBSERVATION_REJECTED = "observation_rejected"
    HALLUCINATION_CAUGHT = "hallucination_caught"
    CHAIN_IDENTIFIED = "chain_identified"
    SCOPE_VIOLATION = "scope_violation"
    SCOPE_APPROVED = "scope_approved"
    SCOPE_DENIED = "scope_denied"
    ADJUDICATION_START = "adjudication_start"
    ADJUDICATION_COMPLETE = "adjudication_complete"
    SEVERITY_UPHELD = "severity_upheld"
    SEVERITY_ADJUSTED = "severity_adjusted"
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
    discovered_by: AgentType
    discovered_at: datetime
    target_url: str | None = None
    target_service: str | None = None

    # Evidence
    raw_evidence: RawEvidence | None = None
    evidence_summary: str | None = None

    # Verification
    verified_by: AgentType | None = None
    verified_at: datetime | None = None
    verification_notes: str | None = None

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
    """Approaches for severity adjudication."""

    STRUCTURED_CHALLENGE = "structured_challenge"
    ADVERSARIAL_DEBATE = "adversarial_debate"
    EVIDENCE_RUBRIC = "evidence_rubric"
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
    adjudicated_by: AgentType = AgentType.ADJUDICATOR


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
    identified_by: AgentType = AgentType.CHAINSMITH
    identified_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)

    # References
    pattern_id: str | None = None
    references: list[str] = Field(default_factory=list)


# ─── Event Models ──────────────────────────────────────────────


class AgentEvent(BaseModel):
    """Event emitted by agents for the live feed."""

    event_type: EventType
    agent: AgentType
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

    agent: AgentType
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


# Resolve forward reference for Observation.adjudicated_risk
Observation.model_rebuild()
