"""
app/checks/chain.py - Check Chain Orchestrator

Resolves check dependencies and executes suites in proper order.

Suite execution order (based on data flow):
1. network - DNS, service discovery (produces: services)
2. web - HTTP analysis (requires: services)
3. ai - LLM/embedding discovery (requires: services, produces: chat_endpoints, etc.)
4. mcp - MCP server discovery (requires: services, produces: mcp_servers)
5. agent - Agent discovery (requires: services, produces: agent_endpoints)
6. rag - RAG discovery (requires: services, produces: rag_endpoints)
7. cag - CAG discovery (requires: services, cag depends on rag/ai context)

Within each suite, checks are ordered by their conditions:
- Entry checks (no conditions) run first
- Dependent checks run after their requirements are satisfied

Usage:
    from app.checks.chain import ChainOrchestrator
    
    orchestrator = ChainOrchestrator()
    orchestrator.add_checks(get_all_checks())
    
    # Get execution plan
    plan = orchestrator.get_execution_plan()
    
    # Run with proper ordering
    findings = await orchestrator.run(initial_context)
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional, Callable, Awaitable

from app.checks.base import BaseCheck, CheckResult, CheckStatus, Finding, Service


# Suite execution order (DAG based on typical data flow)
SUITE_ORDER = [
    "network",  # Discovers services
    "web",      # Analyzes HTTP services
    "ai",       # Discovers AI endpoints
    "mcp",      # MCP server discovery (can run parallel with agent/rag)
    "agent",    # Agent endpoint discovery
    "rag",      # RAG endpoint discovery
    "cag",      # CAG cache discovery (depends on ai/rag context)
]

# Suite dependencies (suite -> list of suites that must complete first)
SUITE_DEPENDENCIES = {
    "network": [],
    "web": ["network"],
    "ai": ["network", "web"],
    "mcp": ["network"],
    "agent": ["network", "ai"],
    "rag": ["network", "ai"],
    "cag": ["network", "ai", "rag"],
}


@dataclass
class CheckNode:
    """A check with its dependency metadata."""
    check: BaseCheck
    suite: str
    dependencies: set[str] = field(default_factory=set)  # Check names this depends on
    dependents: set[str] = field(default_factory=set)    # Checks that depend on this
    
    @property
    def name(self) -> str:
        return self.check.name
    
    @property
    def produces(self) -> list[str]:
        return self.check.produces
    
    @property
    def requires(self) -> list[str]:
        """Get output names this check requires."""
        return [c.output_name for c in self.check.conditions]


@dataclass
class ExecutionPhase:
    """A group of checks that can run together."""
    phase_number: int
    suite: str
    checks: list[BaseCheck]
    parallel: bool = False  # Can these run in parallel?
    
    def __str__(self):
        check_names = [c.name for c in self.checks]
        mode = "parallel" if self.parallel else "sequential"
        return f"Phase {self.phase_number} [{self.suite}] ({mode}): {check_names}"


class ChainOrchestrator:
    """
    Orchestrates check execution with proper dependency resolution.
    
    Features:
    - Suite-level ordering (network → web → ai → mcp/agent/rag → cag)
    - Check-level dependency resolution within suites
    - Parallel execution of independent checks (optional)
    - Progress tracking and events
    """
    
    def __init__(
        self,
        event_callback: Optional[Callable[[dict], Awaitable[None]]] = None,
        parallel_within_phase: bool = False,
        scope_domains: list[str] = None,
        excluded_domains: list[str] = None,
    ):
        self.event_callback = event_callback
        self.parallel_within_phase = parallel_within_phase
        self.scope_domains = scope_domains or []
        self.excluded_domains = excluded_domains or []
        
        self.nodes: dict[str, CheckNode] = {}
        self.suites: dict[str, list[CheckNode]] = defaultdict(list)
        self.context: dict[str, Any] = {}
        self.findings: list[Finding] = []
        self.finding_counter = 0
        
        # Execution state
        self.is_running = False
        self.is_paused = False
        self.current_phase: Optional[ExecutionPhase] = None
        
        # Stats
        self.checks_run = 0
        self.checks_skipped = 0
        self.checks_failed = 0
        self.phases_completed = 0
    
    def add_check(self, check: BaseCheck, suite: str = "unknown"):
        """Add a check to the orchestrator."""
        node = CheckNode(check=check, suite=suite)
        self.nodes[check.name] = node
        self.suites[suite].append(node)
        
        # Set scope validator
        check.set_scope_validator(self._is_in_scope)
    
    def add_checks(self, checks: list[BaseCheck], suite_resolver: Callable[[str], str] = None):
        """Add multiple checks with optional suite resolver."""
        for check in checks:
            suite = suite_resolver(check.name) if suite_resolver else self._infer_suite(check)
            self.add_check(check, suite)
        
        # Build dependency graph
        self._build_dependency_graph()
    
    def _infer_suite(self, check: BaseCheck) -> str:
        """Infer suite from check name or module."""
        name = check.name.lower()
        
        # Check name patterns
        suite_patterns = {
            "network": ["dns", "wildcard_dns", "geoip", "reverse_dns", "port_scan",
                        "tls_analysis", "service_probe", "http_method_enum",
                        "banner_grab"],
            "web": ["header", "robots", "path", "openapi", "cors",
                    "webdav", "vcs_exposure", "config_exposure", "directory_listing",
                    "default_creds", "debug_endpoints",
                    "cookie_security", "auth_detection", "waf_detection",
                    "sitemap", "redirect_chain", "error_page", "ssrf_indicator",
                    "favicon", "http2_detection", "hsts_preload", "sri_check",
                    "mass_assignment"],
            "ai": ["llm", "embedding", "model_info", "fingerprint", "error",
                    "tool_discovery", "prompt", "rate_limit", "filter", "context_window"],
            "mcp": ["mcp"],
            "agent": ["agent", "goal_injection"],
            "rag": ["rag", "indirect_injection"],
            "cag": ["cag", "cache"],
        }
        
        for suite, patterns in suite_patterns.items():
            if any(p in name for p in patterns):
                return suite
        
        return "unknown"
    
    def _build_dependency_graph(self):
        """Build check dependency graph based on produces/conditions."""
        # Map output names to producing checks
        output_producers: dict[str, list[str]] = defaultdict(list)
        
        for name, node in self.nodes.items():
            for output in node.produces:
                output_producers[output].append(name)
        
        # For each check, find what checks produce its requirements
        for name, node in self.nodes.items():
            for req in node.requires:
                producers = output_producers.get(req, [])
                for producer in producers:
                    if producer != name:
                        node.dependencies.add(producer)
                        self.nodes[producer].dependents.add(name)
    
    def get_execution_plan(self) -> list[ExecutionPhase]:
        """
        Generate an execution plan respecting dependencies.
        
        Returns list of phases, where each phase contains checks
        that can run after all previous phases complete.
        """
        phases = []
        phase_num = 0
        executed = set()
        
        # Process suites in order
        for suite in SUITE_ORDER:
            if suite not in self.suites:
                continue
            
            suite_nodes = self.suites[suite]
            suite_pending = [n for n in suite_nodes if n.name not in executed]
            
            while suite_pending:
                # Find checks whose dependencies are all satisfied
                ready = []
                still_pending = []
                
                for node in suite_pending:
                    # Check if all dependencies are executed
                    deps_satisfied = all(
                        dep in executed or dep not in self.nodes
                        for dep in node.dependencies
                    )
                    
                    # Also check suite-level dependencies
                    suite_deps = SUITE_DEPENDENCIES.get(suite, [])
                    suite_deps_satisfied = all(
                        all(n.name in executed for n in self.suites.get(dep_suite, []))
                        for dep_suite in suite_deps
                    )
                    
                    if deps_satisfied and suite_deps_satisfied:
                        ready.append(node)
                    else:
                        still_pending.append(node)
                
                if not ready:
                    # No progress possible - might have circular deps or missing deps
                    # Force remaining checks into a phase
                    ready = still_pending
                    still_pending = []
                
                if ready:
                    phase_num += 1
                    phase = ExecutionPhase(
                        phase_number=phase_num,
                        suite=suite,
                        checks=[n.check for n in ready],
                        parallel=self.parallel_within_phase and len(ready) > 1,
                    )
                    phases.append(phase)
                    
                    for node in ready:
                        executed.add(node.name)
                
                suite_pending = still_pending
        
        # Handle any unknown suite checks
        if "unknown" in self.suites:
            unknown_nodes = [n for n in self.suites["unknown"] if n.name not in executed]
            if unknown_nodes:
                phase_num += 1
                phases.append(ExecutionPhase(
                    phase_number=phase_num,
                    suite="unknown",
                    checks=[n.check for n in unknown_nodes],
                    parallel=False,
                ))
        
        return phases
    
    async def run(self, initial_context: dict[str, Any] = None) -> list[Finding]:
        """
        Execute all checks in dependency order.
        
        Args:
            initial_context: Starting context (target hosts, scope, etc.)
            
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
        self.phases_completed = 0
        
        # Reset all checks
        for node in self.nodes.values():
            node.check.status = CheckStatus.PENDING
            node.check.result = None
        
        # Initialize services list
        if "services" not in self.context:
            self.context["services"] = []
        
        # Get execution plan
        phases = self.get_execution_plan()
        
        await self._emit({
            "type": "run_started",
            "total_phases": len(phases),
            "total_checks": sum(len(p.checks) for p in phases),
        })
        
        for phase in phases:
            if not self.is_running:
                break
            
            # Handle pause
            while self.is_paused and self.is_running:
                await asyncio.sleep(0.1)
            
            self.current_phase = phase
            
            await self._emit({
                "type": "phase_started",
                "phase": phase.phase_number,
                "suite": phase.suite,
                "checks": [c.name for c in phase.checks],
            })
            
            if phase.parallel:
                await asyncio.gather(*[
                    self._run_check(check) for check in phase.checks
                ])
            else:
                for check in phase.checks:
                    if not self.is_running:
                        break
                    await self._run_check(check)
            
            self.phases_completed += 1
            
            await self._emit({
                "type": "phase_completed",
                "phase": phase.phase_number,
                "suite": phase.suite,
            })
        
        self.is_running = False
        self.current_phase = None
        
        await self._emit({
            "type": "run_completed",
            "findings_count": len(self.findings),
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
        })
        
        return self.findings
    
    async def _run_check(self, check: BaseCheck):
        """Run a single check and process results."""
        await self._emit({
            "type": "check_started",
            "check": check.name,
        })
        
        # Check if conditions are met
        if not check.can_run(self.context):
            check.status = CheckStatus.SKIPPED
            self.checks_skipped += 1
            await self._emit({
                "type": "check_skipped",
                "check": check.name,
                "reason": "conditions not met",
                "missing": check.get_missing_conditions(self.context),
            })
            return
        
        # Execute
        result = await check.execute(self.context)
        self.checks_run += 1
        
        # Update context with outputs
        for key, value in result.outputs.items():
            # Merge lists, replace scalars
            if key in self.context and isinstance(self.context[key], list) and isinstance(value, list):
                existing = {str(v) for v in self.context[key]}
                for item in value:
                    if str(item) not in existing:
                        self.context[key].append(item)
            else:
                self.context[key] = value
        
        # Merge services
        self._merge_services(result.services)
        
        # Process findings
        for finding in result.findings:
            self.finding_counter += 1
            if not finding.id:
                finding.id = f"F-{self.finding_counter:03d}"
            self.findings.append(finding)
        
        # Track failures
        if not result.success:
            self.checks_failed += 1
        
        await self._emit({
            "type": "check_completed",
            "check": check.name,
            "findings_count": len(result.findings),
            "outputs": list(result.outputs.keys()),
            "success": result.success,
        })
    
    def _merge_services(self, new_services: list[Service]):
        """Merge new services into context."""
        if not new_services:
            return
        
        existing = self.context.get("services", [])
        existing_urls = set()
        
        for svc in existing:
            url = svc.url if isinstance(svc, Service) else svc.get("url", "")
            existing_urls.add(url)
        
        for svc in new_services:
            url = svc.url if isinstance(svc, Service) else svc.get("url", "")
            if url not in existing_urls:
                existing.append(svc)
                existing_urls.add(url)
        
        self.context["services"] = existing
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within scope."""
        from urllib.parse import urlparse
        from app.lib.targets import host_matches_pattern
        
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            
            # Check exclusions
            for excluded in self.excluded_domains:
                if host_matches_pattern(host, excluded):
                    return False
            
            # If no scope, allow all
            if not self.scope_domains:
                return True
            
            # Check scope
            for scope in self.scope_domains:
                if host_matches_pattern(host, scope):
                    return True
            
            return False
        except Exception:
            return False
    
    async def _emit(self, event: dict):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)
    
    def stop(self):
        """Stop execution."""
        self.is_running = False
    
    def pause(self):
        """Pause execution."""
        self.is_paused = True
    
    def resume(self):
        """Resume execution."""
        self.is_paused = False
    
    def get_diagnostics(self) -> dict:
        """Get detailed diagnostic information."""
        return {
            "suites": {
                suite: [n.name for n in nodes]
                for suite, nodes in self.suites.items()
            },
            "context_keys": list(self.context.keys()),
            "services_count": len(self.context.get("services", [])),
            "findings_count": len(self.findings),
            "checks_run": self.checks_run,
            "checks_skipped": self.checks_skipped,
            "checks_failed": self.checks_failed,
            "phases_completed": self.phases_completed,
            "dependency_graph": {
                name: {
                    "suite": node.suite,
                    "dependencies": list(node.dependencies),
                    "dependents": list(node.dependents),
                    "produces": node.produces,
                    "requires": node.requires,
                }
                for name, node in self.nodes.items()
            },
        }
    
    def print_execution_plan(self):
        """Print human-readable execution plan."""
        phases = self.get_execution_plan()
        
        print("\n=== Execution Plan ===\n")
        
        for phase in phases:
            mode = "⚡ parallel" if phase.parallel else "→ sequential"
            print(f"Phase {phase.phase_number} [{phase.suite}] {mode}")
            
            for check in phase.checks:
                deps = []
                node = self.nodes.get(check.name)
                if node and node.dependencies:
                    deps = list(node.dependencies)
                
                produces = check.produces if check.produces else []
                
                dep_str = f" (deps: {deps})" if deps else ""
                prod_str = f" → {produces}" if produces else ""
                
                print(f"  • {check.name}{dep_str}{prod_str}")
            
            print()
