"""
Guardian - Scope Violation Checker

Simple logic-based checker (not an AI agent) that validates requests
against the defined scope before execution.
"""

from datetime import datetime
from urllib.parse import urlparse
from typing import Optional
import asyncio

from app.models import ScopeDefinition, AgentEvent, EventType, EventImportance, AgentType


class ScopeViolation(Exception):
    """Raised when a request violates scope."""
    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Scope violation: {reason}")


class Guardian:
    """Scope enforcement for recon operations."""
    
    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self.pending_approvals: dict[str, asyncio.Future] = {}
        self.approved_urls: set[str] = set()
        self.denied_urls: set[str] = set()
        self.violation_count = 0
    
    def extract_domain(self, url: str) -> Optional[str]:
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
            elif domain.lower() == ins.lower():
                return True, "In scope"
        
        return False, f"Domain '{domain}' not in scope"
    
    def check_technique(self, technique: str) -> tuple[bool, str]:
        """Check if technique is allowed."""
        if technique in self.scope.forbidden_techniques:
            return False, f"Technique '{technique}' forbidden"
        return True, "Allowed"
    
    async def validate_request(self, url: str, technique: str) -> tuple[bool, Optional[str]]:
        """
        Validate a tool request before execution.
        Returns (should_proceed, violation_reason).
        """
        # Check if already approved/denied
        if url in self.approved_urls:
            return True, None
        if url in self.denied_urls:
            return False, "Previously denied"
        
        # Check technique
        tech_ok, tech_reason = self.check_technique(technique)
        if not tech_ok:
            return False, tech_reason
        
        # Check URL
        url_ok, url_reason = self.check_url(url)
        if not url_ok:
            self.violation_count += 1
            return False, url_reason
        
        return True, None
    
    def approve_url(self, url: str):
        """Manually approve an out-of-scope URL."""
        self.approved_urls.add(url)
        if url in self.pending_approvals:
            self.pending_approvals[url].set_result(True)
    
    def deny_url(self, url: str):
        """Deny an out-of-scope URL."""
        self.denied_urls.add(url)
        if url in self.pending_approvals:
            self.pending_approvals[url].set_result(False)
    
    def create_violation_event(self, url: str, reason: str) -> AgentEvent:
        """Create event for scope violation."""
        return AgentEvent(
            event_type=EventType.SCOPE_VIOLATION,
            agent=AgentType.GUARDIAN,
            importance=EventImportance.HIGH,
            message=f"⚠️ Scope violation: {reason}",
            details={"url": url, "reason": reason},
            violation_url=url,
            requires_approval=True,
        )
