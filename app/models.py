"""
Pydantic Models for Recon Agent

Data models for findings, chains, scope, and agent state.
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


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    HALLUCINATION = "hallucination"


class EventType(StrEnum):
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    FINDING_DISCOVERED = "finding_discovered"
    FINDING_VERIFIED = "finding_verified"
    FINDING_REJECTED = "finding_rejected"
    HALLUCINATION_CAUGHT = "hallucination_caught"
    CHAIN_IDENTIFIED = "chain_identified"
    SCOPE_VIOLATION = "scope_violation"
    SCOPE_APPROVED = "scope_approved"
    SCOPE_DENIED = "scope_denied"
    ERROR = "error"
    INFO = "info"


class EventImportance(StrEnum):
    """Visual hierarchy for UI display."""

    HIGH = "high"  # 🔴 Red - significant findings
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


# ─── Finding Models ────────────────────────────────────────────


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


class Finding(BaseModel):
    """A discovered finding from reconnaissance."""

    id: str
    finding_type: str
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.PENDING
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


# ─── Chain Models ──────────────────────────────────────────────


class AttackChain(BaseModel):
    """An attack chain combining multiple findings."""

    id: str
    title: str
    description: str
    impact_statement: str

    # Component findings
    finding_ids: list[str]

    # Severity
    individual_severities: list[FindingSeverity]
    combined_severity: FindingSeverity
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
    finding_id: str | None = None
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

    # Findings
    findings: list[Finding] = Field(default_factory=list)
    chains: list[AttackChain] = Field(default_factory=list)

    # Stats
    total_tool_calls: int = 0
    hallucinations_caught: int = 0
    scope_violations: int = 0

    # Active randomizations
    active_findings: list[str] = Field(default_factory=list)
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


class FindingsResponse(BaseModel):
    """Response containing findings."""

    findings: list[Finding]
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
