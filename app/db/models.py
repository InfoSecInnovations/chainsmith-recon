"""
app/db/models.py - SQLAlchemy ORM models for persistent storage.

Core tables: scans, observations, chains, check_log (Phase 1).
Tracking tables: observation_status_history, scan_comparisons (Phase 3).
"""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False)
    target_domain = Column(String, nullable=False)
    status = Column(String, nullable=False)  # running, complete, error, cancelled
    started_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    checks_total = Column(Integer, nullable=True)
    checks_completed = Column(Integer, nullable=True)
    checks_failed = Column(Integer, nullable=True)
    observations_count = Column(Integer, nullable=True)
    scope = Column(JSON, nullable=True)
    settings = Column(JSON, nullable=True)
    profile_name = Column(String, nullable=True)
    scenario_name = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)

    # Optimistic locking
    version = Column(Integer, nullable=False, default=1)

    # Status fields migrated from AppState
    adjudication_status = Column(String, nullable=True, default="idle")
    adjudication_error = Column(Text, nullable=True)
    chain_status = Column(String, nullable=True, default="idle")
    chain_error = Column(Text, nullable=True)
    chain_llm_analysis = Column(JSON, nullable=True)

    # Triage Agent
    triage_status = Column(String, nullable=True, default="idle")
    triage_error = Column(Text, nullable=True)


class ObservationRecord(Base):
    __tablename__ = "observations"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False)
    check_name = Column(String, nullable=False)
    suite = Column(String, nullable=True)
    target_url = Column(String, nullable=True)
    host = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)
    verification_status = Column(String, default="pending")
    evidence_quality = Column(
        String, nullable=True
    )  # direct_observation, inferred, claimed_no_proof
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    fingerprint = Column(String, nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)
    # Monotonic per-scan sequence stamped at insert from
    # ScanSession.next_seq(). Shared id space with the SSE hot ring so the
    # DB-backed replay path can page events older than the ring.
    event_seq = Column(Integer, nullable=True)
    # An observation is a graded candidate. `severity` above is the
    # effective value; these record how it got there — the pre-grade assumption,
    # who graded it, why, and which exchanges the verdict was derived from.
    # Grading state is per observation and never per scan (design §6.3).
    provisional_severity = Column(String, nullable=True)
    grading_state = Column(String, nullable=True, default="ungraded")
    grading_tier = Column(String, nullable=True)  # rule | llm | none
    grading_reasoning = Column(Text, nullable=True)
    evidence_ids = Column(JSON, nullable=True)  # -> evidence.id (D-22 binding)
    evidence_source = Column(String, nullable=True)  # corpus | memory | empty
    signals = Column(JSON, nullable=True)

    __table_args__ = (
        Index("idx_observations_scan_id", "scan_id"),
        Index("idx_observations_grading_state", "grading_state"),
        Index("idx_observations_severity", "severity"),
        Index("idx_observations_host", "host"),
        Index("idx_observations_fingerprint", "fingerprint"),
        Index("idx_observations_scan_severity", "scan_id", "severity"),
        Index("idx_observations_scan_event_seq", "scan_id", "event_seq"),
    )


class Chain(Base):
    __tablename__ = "chains"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False)
    source = Column(String, nullable=False)  # rule-based, llm, both
    observation_ids = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    metadata_ = Column("metadata", JSON, nullable=True)

    __table_args__ = (Index("idx_chains_scan_id", "scan_id"),)


class CheckLog(Base):
    __tablename__ = "check_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    check_name = Column(String, nullable=False)
    suite = Column(String, nullable=True)
    event = Column(String, nullable=False)  # started, completed, failed, skipped
    observations_count = Column(Integer, default=0)
    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    # See ObservationRecord.event_seq.
    event_seq = Column(Integer, nullable=True)

    __table_args__ = (
        Index("idx_check_log_scan_id", "scan_id"),
        Index("idx_check_log_scan_check", "scan_id", "check_name"),
        Index("idx_check_log_scan_event_seq", "scan_id", "event_seq"),
    )

    # Maps `event` values onto SSE event types for SSE streaming.
    # Single source of truth shared by the live publisher (51.1c) and the
    # DB-backed replay path (51.3) — design doc §4.
    _SSE_EVENT_TYPE = {
        "started": "check_started",
        "completed": "check_completed",
        "failed": "check_completed",
        "skipped": "check_skipped",
    }

    def to_sse_event(self) -> tuple[str, dict]:
        """Return (event_type, payload) for this log row.

        Payload excludes the outer envelope (seq/scan_id/ts_ns); the caller
        wraps it. `success` is derived from `event` — there is no explicit
        success column.
        """
        event_type = self._SSE_EVENT_TYPE.get(self.event, "check_started")
        payload: dict = {"name": self.check_name, "suite": self.suite}
        if event_type == "check_completed":
            payload["success"] = self.event == "completed"
            payload["observations"] = self.observations_count or 0
            if self.error_message:
                payload["error"] = self.error_message
        elif event_type == "check_skipped":
            payload["reason"] = self.error_message
        return event_type, payload


class ObservationStatusHistory(Base):
    __tablename__ = "observation_status_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String, nullable=False)
    scan_id = Column(String, nullable=False)
    status = Column(String, nullable=False)  # new, recurring, resolved, regressed
    first_seen_scan = Column(String, nullable=True)
    last_seen_scan = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_osh_fingerprint", "fingerprint"),
        Index("idx_osh_scan_id", "scan_id"),
    )


class ObservationOverride(Base):
    __tablename__ = "observation_overrides"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String, nullable=False, unique=True)
    status = Column(String, nullable=False)  # accepted, false_positive
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (Index("idx_observation_overrides_fingerprint", "fingerprint"),)


class SwarmApiKey(Base):
    __tablename__ = "swarm_api_keys"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    last_used_at = Column(DateTime, nullable=True)


class AdjudicationResult(Base):
    __tablename__ = "adjudication_results"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    observation_id = Column(
        String, ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )
    original_severity = Column(String, nullable=False)
    adjudicated_severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    approach = Column(String, nullable=False)
    rationale = Column(Text, nullable=True)
    factors = Column(JSON, nullable=True)
    operator_context_used = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_adjudication_scan_id", "scan_id"),
        Index("idx_adjudication_observation_id", "observation_id"),
    )


class ScanComparison(Base):
    __tablename__ = "scan_comparisons"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_a_id = Column(String, nullable=False)
    scan_b_id = Column(String, nullable=False)
    new_observations = Column(Integer, nullable=True)
    resolved = Column(Integer, nullable=True)
    recurring = Column(Integer, nullable=True)
    regressed = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (UniqueConstraint("scan_a_id", "scan_b_id", name="uq_scan_comparison"),)


class AdvisorRecommendation(Base):
    __tablename__ = "advisor_recommendations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False)
    category = Column(String, nullable=True)  # e.g. "missing_check", "scope_gap"
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(String, nullable=True)  # high, medium, low
    data = Column(JSON, nullable=True)  # full recommendation payload
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (Index("idx_advisor_rec_scan_id", "scan_id"),)


class TriagePlanRecord(Base):
    __tablename__ = "triage_plans"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    generated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    summary = Column(Text, nullable=True)
    team_context_available = Column(Boolean, default=False)
    caveat = Column(Text, nullable=True)
    quick_wins = Column(Integer, default=0)
    strategic_fixes = Column(Integer, default=0)
    workstreams = Column(JSON, nullable=True)

    __table_args__ = (Index("idx_triage_plans_scan_id", "scan_id"),)


class ResearchEnrichmentRecord(Base):
    __tablename__ = "research_enrichments"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    observation_id = Column(
        String, ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )
    cve_details = Column(JSON, nullable=True)
    exploit_availability = Column(JSON, nullable=True)
    vendor_advisories = Column(JSON, nullable=True)
    version_vulnerabilities = Column(JSON, nullable=True)
    data_sources = Column(JSON, nullable=True)
    offline_mode = Column(Boolean, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_research_scan_id", "scan_id"),
        Index("idx_research_observation_id", "observation_id"),
    )


class ProofGuidanceRecord(Base):
    __tablename__ = "proof_guidance"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    observation_id = Column(
        String, ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )
    observation_title = Column(String, nullable=True)
    verification_status = Column(String, nullable=True)
    evidence_quality = Column(String, nullable=True)
    proof_steps = Column(JSON, nullable=True)
    evidence_checklist = Column(JSON, nullable=True)
    severity_rationale = Column(Text, nullable=True)
    false_positive_indicators = Column(JSON, nullable=True)
    common_mistakes = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_proof_scan_id", "scan_id"),
        Index("idx_proof_observation_id", "observation_id"),
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False)
    scan_id = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    direction = Column(String, nullable=False)  # 'operator' or 'agent'
    agent_type = Column(String, nullable=True)  # null for operator messages
    text = Column(Text, nullable=False)
    route_method = Column(String, nullable=True)  # 'context', 'keyword', 'llm'
    ui_context = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)  # list of Reference objects
    actions = Column(JSON, nullable=True)  # list of SuggestedAction objects
    cleared = Column(Boolean, default=False)  # False=visible, True=cleared by operator

    __table_args__ = (
        Index("idx_chat_session_id", "session_id"),
        Index("idx_chat_scan_id", "scan_id"),
    )


class ChainsmithValidation(Base):
    __tablename__ = "chainsmith_validations"

    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=True)
    validation_type = Column(String, nullable=False)  # 'full', 'upstream_diff'
    status = Column(String, nullable=False)  # 'complete', 'error'
    result = Column(JSON, nullable=True)
    issues_count = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (Index("idx_chainsmith_scan_id", "scan_id"),)


class ChainsmithCustomCheck(Base):
    __tablename__ = "chainsmith_custom_checks"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    suite = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    metadata_ = Column("metadata", JSON, nullable=True)

    __table_args__ = (Index("idx_chainsmith_check_name", "name"),)


class TriageActionRecord(Base):
    __tablename__ = "triage_actions"

    id = Column(String, primary_key=True)
    plan_id = Column(String, ForeignKey("triage_plans.id", ondelete="CASCADE"), nullable=False)
    priority = Column(Integer, nullable=False)
    action = Column(String, nullable=False)
    targets = Column(JSON, nullable=True)
    chains_neutralized = Column(JSON, nullable=True)
    reasoning = Column(Text, nullable=True)
    effort_estimate = Column(String, nullable=True)
    impact_estimate = Column(String, nullable=True)
    feasibility = Column(String, nullable=True)
    remediation_guidance = Column(JSON, nullable=True)
    observations_resolved = Column(JSON, nullable=True)
    category = Column(String, nullable=True)

    __table_args__ = (Index("idx_triage_actions_plan_id", "plan_id"),)


class EvidenceRecord(Base):
    """One captured exchange.

    The bodies and headers live on disk under the workspace's ``evidence/``;
    this row holds the scalars, both hashes, and a pointer. Files rather than
    blobs keeps the database portable and makes a corpus ``rsync``-able for
    offline re-grading, which is the whole point of capturing it.

    ``candidate_id`` is nullable because capture may precede the candidate it
    will support, and the HTTP-shaped columns are nullable because a ``dns`` or
    ``local`` exchange has no method and no URL — ``protocol`` is the
    discriminator that says how to read them.
    """

    __tablename__ = "evidence"

    # The exchange id: a uuid4 hex minted by the writer, and also the on-disk
    # filename. Shared so a row and its document can be found from either side.
    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    check_name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    protocol = Column(String, nullable=False)

    candidate_id = Column(String, nullable=True)
    iteration = Column(Integer, nullable=False, default=0)

    request_method = Column(String, nullable=True)
    request_url = Column(Text, nullable=True)
    response_status = Column(Integer, nullable=True)
    elapsed_ms = Column(Float, nullable=True)
    error = Column(Text, nullable=True)

    #: SHA-256 over the normalised request alone — "is this the same question?"
    probe_hash = Column(String, nullable=False)
    #: SHA-256 over the normalised pair — "is this the same evidence?"
    content_hash = Column(String, nullable=False)
    truncated = Column(Boolean, nullable=False, default=False)

    #: Path to the document, relative to the workspace evidence root. Relative
    #: so a corpus stays valid after it is copied to another machine.
    document_path = Column(String, nullable=False)

    captured_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    __table_args__ = (
        Index("idx_evidence_scan_id", "scan_id"),
        Index("idx_evidence_scan_check", "scan_id", "check_name"),
        # Phase 58 §4 groups sampling iterations of one probe by probe_hash, and
        # §5 keys the grade cache on content_hash. Both are lookup paths, not
        # scan-scoped scans, so they are indexed on their own.
        Index("idx_evidence_probe_hash", "probe_hash"),
        Index("idx_evidence_content_hash", "content_hash"),
    )
