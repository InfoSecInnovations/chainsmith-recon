"""
Guardian - Scope Enforcement Gate

Single authority for "should this check/URL be allowed to run."
Logic-based checker (not an AI agent) that validates URLs against
in-scope/out-of-scope domains and check names against forbidden
techniques before execution.

Wired into the scan pipeline at two levels:
- CheckLauncher: blocks forbidden check names before execution
- BaseCheck scope_validator: blocks out-of-scope URLs per-service

This is the `gate` component type (§4.1): deterministic, caller-constructed
(the scan route / scanner / launcher build it per scan via `from_scope(...)`).
`app/gates/registry.py` discovers it as a spec for identity + config only.
"""

import logging
from urllib.parse import urlparse

from app.gates.base import BaseGate
from app.models import AgentEvent, ComponentType, EventImportance, EventType, ScopeDefinition
from app.proof_of_scope import ScanWindow, violation_logger

logger = logging.getLogger(__name__)


class Guardian(BaseGate):
    """Scope enforcement for recon operations."""

    def __init__(self, scope: ScopeDefinition, scan_id: str | None = None):
        self.scope = scope
        # Which scan this Guardian is gating. Stamped onto every
        # violation it logs, so a compliance report can be scoped to one scan
        # instead of aggregating over whatever else was running. Null when the
        # Guardian is built before a scan id exists — the pre-flight window gate
        # in the scan route is the case.
        self.scan_id = scan_id
        self.approved_urls: set[str] = set()
        self.denied_urls: set[str] = set()
        self.violation_count = 0
        self.violations: list[dict] = []

    @classmethod
    def from_scope(
        cls,
        target: str,
        exclude: list[str] | None = None,
        forbidden_techniques: list[str] | None = None,
        scan_id: str | None = None,
    ) -> "Guardian":
        """Build a Guardian from target/exclude (the common case at scan start)."""
        scope = ScopeDefinition(
            in_scope_domains=[target],
            out_of_scope_domains=exclude or [],
            forbidden_techniques=forbidden_techniques or [],
        )
        return cls(scope, scan_id=scan_id)

    # ── URL validation ──────────────────────────────────────────

    def extract_domain(self, url: str) -> str | None:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.split(":")[0] if parsed.netloc else None
        except Exception:
            return None

    def check_url(self, url: str) -> tuple[bool, str]:
        """Check if URL is in scope. Returns (is_ok, reason)."""
        domain = self.extract_domain(url)
        if not domain:
            return False, "Invalid URL"

        # Check out-of-scope first
        for oos in self.scope.out_of_scope_domains:
            if oos.lower() in domain.lower():
                return False, f"Domain '{domain}' is out of scope"

        # Check in-scope
        for ins in self.scope.in_scope_domains:
            if ins.startswith("*."):
                base = ins[2:].lower()
                if domain.lower().endswith(base):
                    return True, "In scope"
            elif domain.lower() == ins.lower() or domain.lower().endswith("." + ins.lower()):
                return True, "In scope"

        return False, f"Domain '{domain}' not in scope"

    def url_scope_validator(self, url: str) -> bool:
        """Scope validator callback for BaseCheck.set_scope_validator().

        Returns True if URL is allowed, False if blocked.
        Logs violations and increments counters as a side effect.
        """
        ok, reason = self.check_url(url)
        if not ok:
            self.violation_count += 1
            self.violations.append({"url": url, "reason": reason, "type": "url"})
            logger.warning(f"Guardian blocked URL: {url} — {reason}")
            self._record_blocked(url, reason)
        return ok

    def _record_blocked(self, url: str, reason: str) -> None:
        """Put a blocked attempt on the proof-of-scope record (B-2).

        The request was never sent. It is logged as `excluded` traffic (which
        the compliance report counts as blocked) and as a blocked violation, both
        stamped with this scan and the check that asked. Never raises: the
        block itself already happened.
        """
        try:
            from app.capture.context import current
            from app.proof_of_scope import ScopeStatus, traffic_logger

            active = current()
            check_name = active.check_name if active else None
            parsed = urlparse(url)
            traffic_logger.log_request(
                dst_host=parsed.hostname or url,
                path=parsed.path or "/",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                protocol=(parsed.scheme or "http").upper(),
                check_name=check_name,
                scope_status=ScopeStatus.EXCLUDED,
                scan_id=self.scan_id,
            )
            violation_logger.log_violation(
                violation_type="out_of_scope",
                reason=reason,
                target_host=parsed.hostname,
                target_path=parsed.path or "/",
                check_name=check_name,
                blocked=True,
                scan_id=self.scan_id,
            )
        except Exception:
            logger.debug("Could not record blocked URL %s", url, exc_info=True)

    # ── Scan window gate ────────────────────────────────────────

    def check_scan_window(
        self,
        window: ScanWindow | None,
        acknowledged: bool = False,
    ) -> tuple[bool, str]:
        """Gate a scan request against the configured scan window.

        Returns (allowed, reason). When the window is unconfigured or the
        current time falls within it, the scan is allowed. When outside
        the window, the scan is blocked unless `acknowledged` is True
        (per-scan override). All outcomes that involve a configured
        window are recorded via ViolationLogger for the compliance
        report.
        """
        if window is None or not window.is_configured():
            return True, "No scan window configured"

        if window.is_within_window():
            return True, "Within scan window"

        if acknowledged:
            violation_logger.log_violation(
                violation_type="outside_window",
                reason=(
                    f"Scan started outside scan window "
                    f"(start={window.start}, end={window.end}); operator acknowledged"
                ),
                blocked=False,
                user_acknowledged=True,
                scan_id=self.scan_id,
            )
            return True, "Outside window — operator acknowledged"

        violation_logger.log_violation(
            violation_type="outside_window",
            reason=(
                f"Scan blocked: current time outside scan window "
                f"(start={window.start}, end={window.end})"
            ),
            blocked=True,
            user_acknowledged=False,
            scan_id=self.scan_id,
        )
        return False, (
            f"Outside scan window (start={window.start}, end={window.end}). "
            "Resubmit with acknowledge_outside_window=true to override."
        )

    # ── Technique (check name) validation ───────────────────────

    def check_technique(self, technique: str) -> tuple[bool, str]:
        """Check if a check name is allowed. Returns (is_ok, reason)."""
        if technique in self.scope.forbidden_techniques:
            return False, f"Check '{technique}' is forbidden by scope"
        return True, "Allowed"

    # ── Operator overrides (future: interactive approval flow) ──

    def approve_url(self, url: str):
        """Manually approve an out-of-scope URL."""
        self.approved_urls.add(url)

    def deny_url(self, url: str):
        """Deny an out-of-scope URL."""
        self.denied_urls.add(url)

    # ── Event creation ──────────────────────────────────────────

    def create_violation_event(self, url: str, reason: str) -> AgentEvent:
        """Create event for scope violation."""
        return AgentEvent(
            event_type=EventType.SCOPE_VIOLATION,
            agent=ComponentType.GUARDIAN,
            importance=EventImportance.HIGH,
            message=f"Scope violation: {reason}",
            details={"url": url, "reason": reason},
            violation_url=url,
            requires_approval=False,
        )
