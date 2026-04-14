"""
Guardian - Scope Enforcement Gate

Single authority for "should this check/URL be allowed to run."
Logic-based checker (not an AI agent) that validates URLs against
in-scope/out-of-scope domains and check names against forbidden
techniques before execution.

Wired into the scan pipeline at two levels:
- CheckLauncher: blocks forbidden check names before execution
- BaseCheck scope_validator: blocks out-of-scope URLs per-service
"""

import logging
from urllib.parse import urlparse

from app.models import AgentEvent, ComponentType, EventImportance, EventType, ScopeDefinition
from app.proof_of_scope import EngagementWindow, violation_logger

logger = logging.getLogger(__name__)


class Guardian:
    """Scope enforcement for recon operations."""

    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
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
    ) -> "Guardian":
        """Build a Guardian from target/exclude (the common case at scan start)."""
        scope = ScopeDefinition(
            in_scope_domains=[target],
            out_of_scope_domains=exclude or [],
            forbidden_techniques=forbidden_techniques or [],
        )
        return cls(scope)

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
        return ok

    # ── Engagement window gate ──────────────────────────────────

    def check_engagement_window(
        self,
        window: EngagementWindow | None,
        acknowledged: bool = False,
    ) -> tuple[bool, str]:
        """Gate a scan request against the configured engagement window.

        Returns (allowed, reason). When the window is unconfigured or the
        current time falls within it, the scan is allowed. When outside
        the window, the scan is blocked unless `acknowledged` is True
        (per-scan override). All outcomes that involve a configured
        window are recorded via ViolationLogger for the compliance
        report.
        """
        if window is None or not window.is_configured():
            return True, "No engagement window configured"

        if window.is_within_window():
            return True, "Within engagement window"

        if acknowledged:
            violation_logger.log_violation(
                violation_type="outside_window",
                reason=(
                    f"Scan started outside engagement window "
                    f"(start={window.start}, end={window.end}); operator acknowledged"
                ),
                blocked=False,
                user_acknowledged=True,
            )
            return True, "Outside window — operator acknowledged"

        violation_logger.log_violation(
            violation_type="outside_window",
            reason=(
                f"Scan blocked: current time outside engagement window "
                f"(start={window.start}, end={window.end})"
            ),
            blocked=True,
            user_acknowledged=False,
        )
        return False, (
            f"Outside engagement window (start={window.start}, end={window.end}). "
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
