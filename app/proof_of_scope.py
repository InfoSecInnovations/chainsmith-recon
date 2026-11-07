"""
Proof of Scope Module

Handles traffic logging, scope violation detection, and compliance reporting.
"""

import json
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from app.lib.timeutils import iso_utc, now_utc, parse_iso_utc

# ─── Configuration ─────────────────────────────────────────────
#
# These files live in the active workspace's `logs/`, resolved
# lazily. The loggers below are module-level singletons constructed at import
# time — before any entry point has selected a workspace — so a constant
# evaluated here would freeze the pre-workspace path. `_resolve_data_dir()`
# defers the lookup to first write instead.
#
# Note this only gives the logs a home. They are still process-global with no
# `scan_id` on records, so concurrent scans pool into one file; that is tracked
# separately in 57.2 (see doc-status-audit-2026-09-10.md F-3).


def _resolve_data_dir(explicit: Path | None = None) -> Path:
    """Return the directory these logs write to: explicit, else workspace logs/."""
    if explicit is not None:
        return explicit
    from app.workspace import get_workspace

    return get_workspace().logs_dir


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
    # Which scan produced this. Without it, concurrent scans pool
    # into one undifferentiated file and no compliance report can honestly
    # claim to describe a single scan. Null for operator-level records made
    # before any scan exists (scope prep).
    scan_id: str | None = None

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
    #: Which scan this violation belongs to; null for operator-level records.
    scan_id: str | None = None

    # Why it's a violation
    reason: str

    # Action taken
    blocked: bool = False
    user_acknowledged: bool = False


class ScanWindow(BaseModel):
    """Scan window configuration."""

    start: str | None = None  # ISO datetime
    end: str | None = None  # ISO datetime

    def is_within_window(self) -> bool:
        """Check if current time is within window."""
        now = now_utc()

        if self.start:
            if now < parse_iso_utc(self.start):
                return False

        if self.end:
            if now > parse_iso_utc(self.end):
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

    # Scan window
    scan_window: ScanWindow = ScanWindow()

    # Track if user acknowledged outside-window warning
    outside_window_acknowledged: bool = False
    outside_window_acknowledged_at: str | None = None


class ComplianceReport(BaseModel):
    """Exportable compliance report."""

    generated_at: str
    session_id: str
    # The scan this report describes. None means it was generated from the
    # operator's current scope prep rather than from a specific scan.
    scan_id: str | None = None

    # Scan window
    scan_window: ScanWindow
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
        self._explicit_dir = data_dir

    @property
    def _data_dir(self) -> Path:
        return _resolve_data_dir(self._explicit_dir)

    @property
    def _log_file(self) -> Path:
        return self._data_dir / "traffic_log.jsonl"

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
        scan_id: str | None = None,
    ):
        """Log a traffic entry."""
        entry = TrafficEntry(
            timestamp=iso_utc(),
            entry_type=TrafficEntryType.HTTP_REQUEST,
            dst_host=dst_host,
            dst_ip=dst_ip,
            dst_port=port,
            protocol=protocol,
            method=method,
            path=path,
            check_name=check_name,
            tool_name=tool_name,
            scan_id=scan_id,
            scope_status=scope_status,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )

        self._append_entry(entry.model_dump())
        return entry

    def log_tool_call(
        self,
        tool_name: str,
        check_name: str | None = None,
        target_info: dict | None = None,
        scan_id: str | None = None,
    ):
        """Log a tool invocation."""
        entry = TrafficEntry(
            timestamp=iso_utc(),
            entry_type=TrafficEntryType.TOOL_CALL,
            tool_name=tool_name,
            check_name=check_name,
            scan_id=scan_id,
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

    def get_entries(self, limit: int = 1000, scan_id: str | None = None) -> list[dict]:
        """Read traffic log entries, optionally only one scan's.

        The file is shared by every scan the workspace has run, so `scan_id` is
        what makes "this scan sent N requests" a true statement rather than an
        aggregate over whatever else was running.
        """
        if not self._log_file.exists():
            return []

        entries = []
        with open(self._log_file) as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if scan_id is not None and entry.get("scan_id") != scan_id:
                    continue
                entries.append(entry)
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
        self._explicit_dir = data_dir

    @property
    def _data_dir(self) -> Path:
        return _resolve_data_dir(self._explicit_dir)

    @property
    def _log_file(self) -> Path:
        return self._data_dir / "violations_log.jsonl"

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
        scan_id: str | None = None,
    ):
        """Log a scope violation."""
        entry = ViolationEntry(
            timestamp=iso_utc(),
            violation_type=violation_type,
            target_host=target_host,
            target_path=target_path,
            check_name=check_name,
            tool_name=tool_name,
            scan_id=scan_id,
            reason=reason,
            blocked=blocked,
            user_acknowledged=user_acknowledged,
        )

        self._data_dir.mkdir(parents=True, exist_ok=True)
        with open(self._log_file, "a") as f:
            f.write(entry.model_dump_json() + "\n")

        return entry

    def get_violations(self, scan_id: str | None = None) -> list[ViolationEntry]:
        """Read violations, optionally only one scan's."""
        if not self._log_file.exists():
            return []

        violations = []
        with open(self._log_file) as f:
            for line in f:
                if not line.strip():
                    continue
                entry = ViolationEntry(**json.loads(line))
                if scan_id is not None and entry.scan_id != scan_id:
                    continue
                violations.append(entry)

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
        self._explicit_dir = data_dir

    @property
    def _data_dir(self) -> Path:
        return _resolve_data_dir(self._explicit_dir)

    @property
    def _report_file(self) -> Path:
        return self._data_dir / "compliance_report.json"

    def generate_report(
        self,
        session_id: str,
        target: str,
        exclusions: list[str],
        proof_settings: ProofOfScopeSettings,
        scan_id: str | None = None,
    ) -> ComplianceReport:
        """Generate a compliance report.

        The scope half of the report (target, exclusions, window, ack) is
        supplied by the caller and should come from the scan being reported
        on, not from live operator state.

        Phase 57.2 closed the counterpart gap: traffic and violation records now
        carry a `scan_id`, so a report for one scan counts only that scan's
        traffic instead of aggregating whatever else was running. A report
        generated without a `scan_id` still aggregates — that is the honest
        answer for an unscoped, workspace-wide report.
        """

        # Get traffic entries
        traffic_entries = self.traffic_logger.get_entries(limit=10000, scan_id=scan_id)

        # Calculate statistics
        total_requests = len([e for e in traffic_entries if e.get("entry_type") == "http_request"])
        in_scope = len([e for e in traffic_entries if e.get("scope_status") == "in_scope"])
        out_of_scope = len([e for e in traffic_entries if e.get("scope_status") == "out_of_scope"])
        blocked = len([e for e in traffic_entries if e.get("scope_status") == "excluded"])

        # Get violations
        violations = self.violation_logger.get_violations(scan_id=scan_id)

        report = ComplianceReport(
            generated_at=iso_utc(),
            session_id=session_id,
            scan_id=scan_id,
            scan_window=proof_settings.scan_window,
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
