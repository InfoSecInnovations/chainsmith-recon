"""
app/db/models.py - SQLAlchemy ORM models for persistent storage.

Core tables: scans, findings, chains, check_log (Phase 1).
Engagement and tracking tables: engagements, finding_status_history,
scan_comparisons (Phase 3).
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
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


class Engagement(Base):
    __tablename__ = "engagements"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    target_domain = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    client_name = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(String, default="active")  # active, completed, archived
    metadata_ = Column("metadata", JSON, nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    engagement_id = Column(String, nullable=True)  # Optional link to engagement
    session_id = Column(String, nullable=False)
    target_domain = Column(String, nullable=False)
    status = Column(String, nullable=False)  # running, complete, error, cancelled
    started_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    checks_total = Column(Integer, nullable=True)
    checks_completed = Column(Integer, nullable=True)
    checks_failed = Column(Integer, nullable=True)
    findings_count = Column(Integer, nullable=True)
    scope = Column(JSON, nullable=True)
    settings = Column(JSON, nullable=True)
    profile_name = Column(String, nullable=True)
    scenario_name = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=False)
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
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    fingerprint = Column(String, nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)

    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_host", "host"),
        Index("idx_findings_fingerprint", "fingerprint"),
    )


class Chain(Base):
    __tablename__ = "chains"

    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False)
    source = Column(String, nullable=False)  # rule-based, llm, both
    finding_ids = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    metadata_ = Column("metadata", JSON, nullable=True)

    __table_args__ = (
        Index("idx_chains_scan_id", "scan_id"),
    )


class CheckLog(Base):
    __tablename__ = "check_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False)
    check_name = Column(String, nullable=False)
    suite = Column(String, nullable=True)
    event = Column(String, nullable=False)  # started, completed, failed, skipped
    findings_count = Column(Integer, default=0)
    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_check_log_scan_id", "scan_id"),
    )


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String, nullable=False)
    scan_id = Column(String, nullable=False)
    status = Column(String, nullable=False)  # new, recurring, resolved, regressed
    first_seen_scan = Column(String, nullable=True)
    last_seen_scan = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_fsh_fingerprint", "fingerprint"),
        Index("idx_fsh_scan_id", "scan_id"),
    )


class FindingOverride(Base):
    __tablename__ = "finding_overrides"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String, nullable=False, unique=True)
    status = Column(String, nullable=False)  # accepted, false_positive
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_finding_overrides_fingerprint", "fingerprint"),
    )


class SwarmApiKey(Base):
    __tablename__ = "swarm_api_keys"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime, nullable=True)


class ScanComparison(Base):
    __tablename__ = "scan_comparisons"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_a_id = Column(String, nullable=False)
    scan_b_id = Column(String, nullable=False)
    new_findings = Column(Integer, nullable=True)
    resolved = Column(Integer, nullable=True)
    recurring = Column(Integer, nullable=True)
    regressed = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("scan_a_id", "scan_b_id", name="uq_scan_comparison"),
    )
