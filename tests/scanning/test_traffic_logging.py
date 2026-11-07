"""
B-2: the proof-of-scope traffic log is actually written, per scan.

Nothing called `TrafficLogger.log_request`, so every compliance report claimed
zero requests and zero out-of-scope attempts. Now the HTTP client logs each
request a check sends (scope status from the scan's own Guardian), and Guardian
logs each attempt it blocks.
"""

from __future__ import annotations

import pytest

import app.gates.guardian.gate as gate_mod
import app.proof_of_scope as pos
from app.capture.context import capture_context
from app.gates.guardian import Guardian
from app.lib.http import AsyncHttpClient, HttpResponse
from app.proof_of_scope import (
    ComplianceReporter,
    ProofOfScopeSettings,
    TrafficLogger,
    ViolationLogger,
)
from app.scan_registry import get_registry
from app.scan_session import ScanSession

pytestmark = pytest.mark.unit

SCAN = "scan-traffic-1"


@pytest.fixture
def logs(tmp_path, monkeypatch):
    traffic = TrafficLogger(data_dir=tmp_path)
    violations = ViolationLogger(data_dir=tmp_path)
    monkeypatch.setattr(pos, "traffic_logger", traffic)
    monkeypatch.setattr(gate_mod, "violation_logger", violations)
    return traffic, violations


@pytest.fixture
def session():
    registry = get_registry()
    registry._reset()
    guardian = Guardian.from_scope("example.com", exclude=["admin.example.com"], scan_id=SCAN)
    s = ScanSession(id=SCAN, target="example.com", guardian=guardian)
    s.proof_settings = ProofOfScopeSettings()
    registry.register(s)
    yield s
    registry._reset()


def _resp(url: str, status: int = 200) -> HttpResponse:
    return HttpResponse(url=url, status_code=status, headers={}, body="", elapsed_ms=7.0)


def _send(url: str, check: str = "web_probe") -> None:
    with capture_context(scan_id=SCAN, check_name=check):
        AsyncHttpClient._log_traffic("GET", url, _resp(url))


def test_a_sent_request_is_logged_in_scope_with_its_scan_and_check(logs, session):
    traffic, _ = logs
    _send("https://www.example.com/login")

    [entry] = traffic.get_entries(scan_id=SCAN)
    assert entry["scope_status"] == "in_scope"
    assert entry["check_name"] == "web_probe"
    assert entry["dst_host"] == "www.example.com"
    assert entry["path"] == "/login"
    assert entry["dst_port"] == 443
    assert entry["status_code"] == 200


def test_a_request_that_left_scope_is_logged_out_of_scope(logs, session):
    traffic, _ = logs
    _send("http://other.test/x")
    _send("http://admin.example.com/")  # excluded, but it was sent

    assert [e["scope_status"] for e in traffic.get_entries(scan_id=SCAN)] == [
        "out_of_scope",
        "out_of_scope",
    ]


def test_nothing_is_logged_outside_a_check(logs, session):
    traffic, _ = logs
    AsyncHttpClient._log_traffic(
        "GET", "https://www.example.com/", _resp("https://www.example.com/")
    )
    assert traffic.get_entries() == []


def test_the_traffic_logging_setting_is_honoured(logs, session):
    traffic, _ = logs
    session.proof_settings.traffic_logging = False
    _send("https://www.example.com/")
    assert traffic.get_entries() == []


def test_a_blocked_attempt_is_excluded_traffic_and_a_violation(logs, session):
    traffic, violations = logs
    with capture_context(scan_id=SCAN, check_name="web_probe"):
        assert session.guardian.url_scope_validator("http://admin.example.com/panel") is False

    [entry] = traffic.get_entries(scan_id=SCAN)
    assert entry["scope_status"] == "excluded"
    [violation] = violations.get_violations(scan_id=SCAN)
    assert violation.blocked is True
    assert violation.violation_type == "out_of_scope"
    assert violation.check_name == "web_probe"
    assert violation.target_host == "admin.example.com"


def test_the_report_counts_only_its_own_scan(logs, session, tmp_path):
    traffic, violations = logs
    _send("https://www.example.com/a")
    _send("https://www.example.com/b")
    _send("http://other.test/")
    with capture_context(scan_id=SCAN, check_name="web_probe"):
        session.guardian.url_scope_validator("http://admin.example.com/")
    # Another scan's traffic in the same file.
    traffic.log_request(dst_host="www.example.com", scan_id="someone-else")

    reporter = ComplianceReporter(traffic, violations, data_dir=tmp_path)
    report = reporter.generate_report(
        session_id="op",
        target="example.com",
        exclusions=[],
        proof_settings=ProofOfScopeSettings(),
        scan_id=SCAN,
    )

    assert report.total_requests == 4
    assert report.in_scope_requests == 2
    assert report.out_of_scope_attempts == 1
    assert report.blocked_requests == 1
    assert len(report.violations) == 1


def test_a_scan_this_process_does_not_run_is_not_logged(logs):
    traffic, _ = logs
    get_registry()._reset()
    with capture_context(scan_id="not-registered", check_name="web_probe"):
        AsyncHttpClient._log_traffic("GET", "https://x.test/", _resp("https://x.test/"))
    assert traffic.get_entries() == []
