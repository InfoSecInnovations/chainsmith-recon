"""
Check Runner

Executes checks based on satisfied conditions with:
- Scope enforcement (both runner-level and check-level)
- Configurable parallelization
- Progress tracking and events
- Diagnostic output
"""

import asyncio
from typing import Any, Optional, Callable, Awaitable
from urllib.parse import urlparse

from app.checks.base import BaseCheck, CheckResult, CheckStatus, Finding, Service
from app.lib.targets import host_matches_pattern



class CheckRunner:
    """
    Runs checks based on their conditions being satisfied.
    
    Flow:
    1. Start with initial context (target hosts, scope)
    2. Run entry point checks (no conditions)
    3. Find checks whose conditions are now satisfied
    4. Run them (respecting parallelization settings)
    5. Add outputs to context
    6. Repeat until no more checks can run
    """
    
    def __init__(
        self,
        event_callback: Optional[Callable[[Any], Awaitable[None]]] = None,
        parallel: bool = False,
        scope_domains: list[str] = None,
        excluded_domains: list[str] = None
    ):
        self.event_callback = event_callback
        self.parallel = parallel
        self.scope_domains = scope_domains or []
        self.excluded_domains = excluded_domains or []
        
        self.checks: list[BaseCheck] = []
        self.context: dict[str, Any] = {}
        self.findings: list[Finding] = []
        self.finding_counter = 0
        
        self.is_running = False
        self.is_paused = False
        
        # Stats
        self.checks_run = 0
        self.checks_skipped = 0
        self.checks_failed = 0
    
    async def emit(self, event: Any):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)
    
    def register_check(self, check: BaseCheck):
        """Register a check instance."""
        # Set scope validator on check
        check.set_scope_validator(self.is_in_scope)
        self.checks.append(check)
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is within the defined scope.
        
        Rules:
        1. If URL's domain matches excluded_domains -> False
        2. If URL's domain matches scope_domains -> True
        3. If no scope defined -> True (permissive)
        4. Otherwise -> False
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            host_lower = host.lower()
            
            # Check exclusions first
            for excluded in self.excluded_domains:
                if self._domain_matches(host, excluded):
                    return False
            
                        # If no scope defined, allow all (except exclusions)
            if not self.scope_domains:
                return True
            
            # Check if in scope
            for scope in self.scope_domains:
                if self._domain_matches(host, scope):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _domain_matches(self, host: str, pattern: str) -> bool:
        """Check if host matches a domain pattern (supports wildcards)."""
        return host_matches_pattern(host, pattern)
    
    async def run(self, initial_context: dict[str, Any] = None) -> list[Finding]:
        """
        Run all applicable checks starting from initial context.
        
        Args:
            initial_context: Starting context (scope info, etc.)
            
        Returns:
            List of all findings discovered
        """
        self.is_running = True
        self.context = initial_context.copy() if initial_context else {}
        self.findings = []
        self.finding_counter = 0
        self.checks_run = 0
        self.checks_skipped = 0
        self.checks_failed = 0
        
        # Reset all checks
        for check in self.checks:
            check.status = CheckStatus.PENDING
            check.result = None
        
        # Initialize services list in context if not present
        if "services" not in self.context:
            self.context["services"] = []
        
        iteration = 0
        max_iterations = 100  # Safety limit
        
        while self.is_running and iteration < max_iterations:
            iteration += 1
            
            # Handle pause
            while self.is_paused and self.is_running:
                await asyncio.sleep(0.5)
            
            if not self.is_running:
                break
            
            # Find checks that can run
            runnable = self._get_runnable_checks()
            
            if not runnable:
                break
            
            if self.parallel:
                # Run all runnable checks in parallel
                await asyncio.gather(*[
                    self._run_single_check(check)
                    for check in runnable
                ])
            else:
                # Run sequentially
                for check in runnable:
                    if not self.is_running:
                        break
                    await self._run_single_check(check)
        
        self.is_running = False
        return self.findings
    
    def _get_runnable_checks(self) -> list[BaseCheck]:
        """Get checks that are pending and have conditions satisfied."""
        runnable = []
        
        for check in self.checks:
            if check.status != CheckStatus.PENDING:
                continue
            
            if check.can_run(self.context):
                runnable.append(check)
        
        return runnable
    
    async def _run_single_check(self, check: BaseCheck):
        """Run a single check and process results."""
        result = await check.execute(self.context)
        self.checks_run += 1
        
        # Update context with outputs
        for key, value in result.outputs.items():
            self.context[key] = value
        
        # Merge services (don't overwrite, extend)
        if result.services:
            existing_services = self.context.get("services", [])
            # Convert to list of dicts for comparison
            existing_urls = {s.url if isinstance(s, Service) else s.get("url") for s in existing_services}
            
            for service in result.services:
                svc_url = service.url if isinstance(service, Service) else service.get("url")
                if svc_url not in existing_urls:
                    existing_services.append(service)
                else:
                    # Update existing service with new info
                    for i, existing in enumerate(existing_services):
                        existing_url = existing.url if isinstance(existing, Service) else existing.get("url")
                        if existing_url == svc_url:
                            if isinstance(service, Service) and isinstance(existing, Service):
                                # Merge metadata
                                existing.metadata.update(service.metadata)
                                existing.service_type = service.service_type or existing.service_type
                            break
            
            self.context["services"] = existing_services
        
        # Process findings
        for finding in result.findings:
            self.finding_counter += 1
            # Preserve stable IDs from lib/findings.build_finding(); only
            # assign a sequential fallback if the check left the ID empty.
            if not finding.id:
                finding.id = f"F-{self.finding_counter:03d}"
            self.findings.append(finding)
        
        # Track failures
        if not result.success:
            self.checks_failed += 1
    
    def stop(self):
        """Stop the runner."""
        self.is_running = False
    
    def pause(self):
        """Pause the runner."""
        self.is_paused = True
    
    def resume(self):
        """Resume the runner."""
        self.is_paused = False
    
    def get_check_tree(self) -> dict:
        """Get check dependency tree for visualization."""
        return {
            "checks": [check.to_dict() for check in self.checks],
            "context_keys": list(self.context.keys())
        }
    
    def get_diagnostics(self) -> dict:
        """Get detailed diagnostic information."""
        return {
            "context_keys": list(self.context.keys()),
            "services_count": len(self.context.get("services", [])),
            "findings_count": len(self.findings),
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "can_run": check.can_run(self.context),
                    "missing_conditions": check.get_missing_conditions(self.context),
                    "findings_produced": len(check.result.findings) if check.result else 0,
                    "errors": check.result.errors if check.result else []
                }
                for check in self.checks
            ]
        }
