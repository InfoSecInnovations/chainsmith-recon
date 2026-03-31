"""
Scout Agent (Check-Based v2)

Production-viable reconnaissance using the modular check framework.
Replaces LLM-driven tool selection with deterministic, chained checks.
"""

from typing import Optional, Callable, Awaitable
from datetime import datetime

from app.checks import CheckRunner, Service
from app.checks.entry import LabDnsEnumerationCheck, ServiceProbeCheck
from app.checks.web import (
    HeaderAnalysisCheck, RobotsTxtCheck, PathProbeCheck,
    OpenAPICheck, CorsCheck
)
from app.checks.ai import (
    ChatEndpointDiscoveryCheck, ChatbotCapabilityProbeCheck,
    PromptExtractionCheck, ErrorInfoLeakCheck, ModelEndpointCheck
)

from app.models import (
    Finding as ModelFinding, FindingSeverity, FindingStatus,
    AgentType, AgentEvent, EventType, EventImportance, ScopeDefinition
)
from app.guardian import Guardian


class ScoutAgent:
    """
    Scout agent using check-based discovery v2.
    
    Check execution order (determined by conditions):
    
    1. Entry Points (no conditions):
       - LabDnsEnumerationCheck → services, target_hosts
    
    2. Service Enrichment (needs: services):
       - ServiceProbeCheck → enriched services with types
    
    3. Web Checks (needs: services, runs on http/html/api types):
       - HeaderAnalysisCheck
       - RobotsTxtCheck
       - PathProbeCheck
       - OpenAPICheck
       - CorsCheck
    
    4. AI Discovery (needs: services):
       - ChatEndpointDiscoveryCheck → chat_endpoints
    
    5. AI Checks (needs: chat_endpoints):
       - ChatbotCapabilityProbeCheck
       - PromptExtractionCheck
       - ErrorInfoLeakCheck
       - ModelEndpointCheck
    """
    
    def __init__(
        self,
        scope: ScopeDefinition,
        guardian: Guardian,
        hallucination_ids: list[str] = None,  # Not used in check-based approach
        event_callback: Optional[Callable[[AgentEvent], Awaitable[None]]] = None,
        parallel: bool = False  # Sequential by default for educational clarity
    ):
        self.scope = scope
        self.guardian = guardian
        self.event_callback = event_callback
        self.findings: list[ModelFinding] = []
        self.is_running = False
        self.is_paused = False
        
        # Create runner with scope
        self.runner = CheckRunner(
            event_callback=event_callback,
            parallel=parallel,
            scope_domains=scope.in_scope_domains,
            excluded_domains=scope.out_of_scope_domains
        )
        
        # Register checks in logical order
        self._register_checks()
    
    def _register_checks(self):
        """Register all checks. Order doesn't matter - conditions control flow."""
        
        # === Entry Points ===
        self.runner.register_check(LabDnsEnumerationCheck())
        
        # === Service Enrichment ===
        self.runner.register_check(ServiceProbeCheck())
        
        # === Web Checks (run on all HTTP services) ===
        self.runner.register_check(HeaderAnalysisCheck())
        self.runner.register_check(RobotsTxtCheck())
        self.runner.register_check(PathProbeCheck())
        self.runner.register_check(OpenAPICheck())
        self.runner.register_check(CorsCheck())
        
        # === AI Discovery ===
        self.runner.register_check(ChatEndpointDiscoveryCheck())
        self.runner.register_check(ModelEndpointCheck())
        
        # === AI Checks (run after chat endpoints discovered) ===
        self.runner.register_check(ChatbotCapabilityProbeCheck())
        self.runner.register_check(PromptExtractionCheck())
        self.runner.register_check(ErrorInfoLeakCheck())
    
    async def run(self, directive: Optional[str] = None) -> list[ModelFinding]:
        """
        Run check-based discovery.
        
        Args:
            directive: Optional instruction (not currently used)
            
        Returns:
            List of findings in standard model format
        """
        self.is_running = True
        self.findings = []
        
        # Initial context
        initial_context = {
            "scope_domains": self.scope.in_scope_domains,
            "excluded_domains": self.scope.out_of_scope_domains,
        }
        
        # Run all checks
        check_findings = await self.runner.run(initial_context)
        
        # Convert to model findings
        for cf in check_findings:
            try:
                model_finding = ModelFinding(
                    id=cf.id,
                    finding_type=cf.check_name or "discovered",
                    title=cf.title,
                    description=cf.description,
                    severity=FindingSeverity(cf.severity),
                    status=FindingStatus.PENDING,
                    discovered_by=AgentType.SCOUT,
                    discovered_at=datetime.utcnow(),
                    target_url=cf.target_url,
                    evidence_summary=cf.evidence,
                    # Don't pass raw_evidence - it expects a RawEvidence object
                    # Store raw data in evidence_summary or skip it
                    raw_evidence=None
                )
                self.findings.append(model_finding)
            except Exception as e:
                # Log but continue with other findings
                print(f"Error converting finding {cf.id}: {e}")
                continue
        
        self.is_running = False
        return self.findings
    
    def stop(self):
        """Stop the agent."""
        self.is_running = False
        self.runner.stop()
    
    def pause(self):
        """Pause the agent."""
        self.is_paused = True
        self.runner.pause()
    
    def resume(self):
        """Resume the agent."""
        self.is_paused = False
        self.runner.resume()
    
    def get_check_tree(self) -> dict:
        """Get check dependency tree for visualization."""
        return self.runner.get_check_tree()
    
    def get_diagnostics(self) -> dict:
        """Get diagnostic information about the run."""
        return self.runner.get_diagnostics()
