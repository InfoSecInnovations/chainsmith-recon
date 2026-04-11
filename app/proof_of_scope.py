"""
Proof of Scope Module

Handles traffic logging, scope violation detection, and compliance reporting.
"""

import json
import os
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

# ─── Configuration ─────────────────────────────────────────────

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
TRAFFIC_LOG_FILE = DATA_DIR / "traffic_log.jsonl"
VIOLATIONS_LOG_FILE = DATA_DIR / "violations_log.jsonl"
COMPLIANCE_REPORT_FILE = DATA_DIR / "compliance_report.json"


# ─── Models ────────────────────────────────────────────────────


class TrafficEntryType(StrEnum):
    HTTP_REQUEST = "http_request"
    DNS_LOOKUP = "dns_lookup"
    TOOL_CALL = "tool_call"


class ScopeStatus(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED = "excluded"
    UNKNOWN = "unknown"


class TrafficEntry(BaseModel):
    """Single traffic log entry."""

    timestamp: str
    entry_type: TrafficEntryType

    # Target info
    dst_host: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None

    # Request info
    protocol: str | None = None
    method: str | None = None
    path: str | None = None

    # Context
    check_name: str | None = None
    tool_name: str | None = None

    # Scope status
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN

    # Response info (optional)
    status_code: int | None = None
    response_time_ms: float | None = None


class ViolationEntry(BaseModel):
    """Scope violation log entry."""

    timestamp: str
    violation_type: str  # "out_of_scope", "excluded_target", "outside_window"

    # What was attempted
    target_host: str | None = None
    target_path: str | None = None
    check_name: str | None = None
    tool_name: str | None = None

    # Why it's a violation
    reason: str

    # Action taken
    blocked: bool = False
    user_acknowledged: bool = False


class EngagementWindow(BaseModel):
    """Engagement window configuration."""

    start: str | None = None  # ISO datetime
    end: str | None = None  # ISO datetime

    def is_within_window(self) -> bool:
        """Check if current time is within window."""
        now = datetime.utcnow()

        if self.start:
            start_dt = datetime.fromisoformat(
                self.start.replace("Z", "+00:00").replace("+00:00", "")
            )
            if now < start_dt:
                return False

        if self.end:
            end_dt = datetime.fromisoformat(self.end.replace("Z", "+00:00").replace("+00:00", ""))
            if now > end_dt:
                return False

        return True

    def is_configured(self) -> bool:
        """Check if any window is configured."""
        return bool(self.start or self.end)


class ProofOfScopeSettings(BaseModel):
    """Proof of scope configuration."""

    traffic_logging: bool = True
    block_exclusions: bool = True
    log_violations: bool = True

    # Engagement window
    engagement_window: EngagementWindow = EngagementWindow()

    # Track if user acknowledged outside-window warning
    outside_window_acknowledged: bool = False
    outside_window_acknowledged_at: str | None = None


class ComplianceReport(BaseModel):
    """Exportable compliance report."""

    generated_at: str
    session_id: str

    # Engagement window
    engagement_window: EngagementWindow
    outside_window_acknowledged: bool = False

    # Scope definition
    target: str
    exclusions: list[str]

    # Statistics
    total_requests: int = 0
    in_scope_requests: int = 0
    out_of_scope_attempts: int = 0
    blocked_requests: int = 0

    # Violations
    violations: list[ViolationEntry] = []

    # Settings used
    proof_settings: ProofOfScopeSettings


# ─── Traffic Logger ────────────────────────────────────────────


class TrafficLogger:
    """Handles traffic logging to JSONL file."""

    def __init__(self, data_dir: Path | None = None):
        self._data_dir = data_dir or DATA_DIR
        self._log_file = self._data_dir / "traffic_log.jsonl"

    def _ensure_data_dir(self):
        """Ensure data directory exists."""
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def log_request(
        self,
        dst_host: str,
        method: str = "GET",
        path: str = "/",
        port: int = 80,
        protocol: str = "HTTP",
        check_name: str | None = None,
        tool_name: str | None = None,
        scope_status: ScopeStatus = ScopeStatus.UNKNOWN,
        status_code: int | None = None,
        response_time_ms: float | None = None,
        dst_ip: str | None = None,
    ):
        """Log a traffic entry."""
        entry = TrafficEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            entry_type=TrafficEntryType.HTTP_REQUEST,
            dst_host=dst_host,
            dst_ip=dst_ip,
            dst_port=port,
            protocol=protocol,
            method=method,
            path=path,
            check_name=check_name,
            tool_name=tool_name,
            scope_status=scope_status,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )

        self._append_entry(entry.model_dump())
        return entry

    def log_tool_call(
        self, tool_name: str, check_name: str | None = None, target_info: dict | None = None
    ):
        """Log a tool invocation."""
        entry = TrafficEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            entry_type=TrafficEntryType.TOOL_CALL,
            tool_name=tool_name,
            check_name=check_name,
            dst_host=target_info.get("host") if target_info else None,
            dst_port=target_info.get("port") if target_info else None,
            scope_status=ScopeStatus.IN_SCOPE,  # Assume tool calls are in scope
        )

        self._append_entry(entry.model_dump())
        return entry

    def _append_entry(self, entry: dict):
        """Append entry to JSONL file."""
        self._ensure_data_dir()
        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_entries(self, limit: int = 1000) -> list[dict]:
        """Read traffic log entries."""
        if not self._log_file.exists():
            return []

        entries = []
        with open(self._log_file) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
                    if len(entries) >= limit:
                        break

        return entries

    def clear(self):
        """Clear traffic log."""
        if self._log_file.exists():
            self._log_file.unlink()


# ─── Violation Logger ──────────────────────────────────────────


class ViolationLogger:
    """Handles scope violation logging."""

    def __init__(self, data_dir: Path | None = None):
        self._data_dir = data_dir or DATA_DIR
        self._log_file = self._data_dir / "violations_log.jsonl"

    def log_violation(
        self,
        violation_type: str,
        reason: str,
        target_host: str | None = None,
        target_path: str | None = None,
        check_name: str | None = None,
        tool_name: str | None = None,
        blocked: bool = False,
        user_acknowledged: bool = False,
    ):
        """Log a scope violation."""
        entry = ViolationEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            violation_type=violation_type,
            target_host=target_host,
            target_path=target_path,
            check_name=check_name,
            tool_name=tool_name,
            reason=reason,
            blocked=blocked,
            user_acknowledged=user_acknowledged,
        )

        self._data_dir.mkdir(parents=True, exist_ok=True)
        with open(self._log_file, "a") as f:
            f.write(entry.model_dump_json() + "\n")

        return entry

    def get_violations(self) -> list[ViolationEntry]:
        """Read all violations."""
        if not self._log_file.exists():
            return []

        violations = []
        with open(self._log_file) as f:
            for line in f:
                if line.strip():
                    violations.append(ViolationEntry(**json.loads(line)))

        return violations

    def clear(self):
        """Clear violations log."""
        if self._log_file.exists():
            self._log_file.unlink()


# ─── Compliance Reporter ───────────────────────────────────────


class ComplianceReporter:
    """Generates compliance reports from logs."""

    def __init__(
        self,
        traffic_logger: TrafficLogger,
        violation_logger: ViolationLogger,
        data_dir: Path | None = None,
    ):
        self.traffic_logger = traffic_logger
        self.violation_logger = violation_logger
        self._data_dir = data_dir or DATA_DIR
        self._report_file = self._data_dir / "compliance_report.json"

    def generate_report(
        self,
        session_id: str,
        target: str,
        exclusions: list[str],
        proof_settings: ProofOfScopeSettings,
    ) -> ComplianceReport:
        """Generate a compliance report."""

        # Get traffic entries
        traffic_entries = self.traffic_logger.get_entries(limit=10000)

        # Calculate statistics
        total_requests = len([e for e in traffic_entries if e.get("entry_type") == "http_request"])
        in_scope = len([e for e in traffic_entries if e.get("scope_status") == "in_scope"])
        out_of_scope = len([e for e in traffic_entries if e.get("scope_status") == "out_of_scope"])
        blocked = len([e for e in traffic_entries if e.get("scope_status") == "excluded"])

        # Get violations
        violations = self.violation_logger.get_violations()

        report = ComplianceReport(
            generated_at=datetime.utcnow().isoformat() + "Z",
            session_id=session_id,
            engagement_window=proof_settings.engagement_window,
            outside_window_acknowledged=proof_settings.outside_window_acknowledged,
            target=target,
            exclusions=exclusions,
            total_requests=total_requests,
            in_scope_requests=in_scope,
            out_of_scope_attempts=out_of_scope,
            blocked_requests=blocked,
            violations=violations,
            proof_settings=proof_settings,
        )

        # Save report
        self._data_dir.mkdir(parents=True, exist_ok=True)
        with open(self._report_file, "w") as f:
            f.write(report.model_dump_json(indent=2))

        return report

    def get_latest_report(self) -> ComplianceReport | None:
        """Get the latest compliance report."""
        if not self._report_file.exists():
            return None

        with open(self._report_file) as f:
            data = json.load(f)

        return ComplianceReport(**data)


# ─── Global Instances ──────────────────────────────────────────

traffic_logger = TrafficLogger()
violation_logger = ViolationLogger()
compliance_reporter = ComplianceReporter(traffic_logger, violation_logger)


def reset_proof_of_scope():
    """Reset all proof of scope data."""
    traffic_logger.clear()
    violation_logger.clear()
    if compliance_reporter._report_file.exists():
        compliance_reporter._report_file.unlink()
