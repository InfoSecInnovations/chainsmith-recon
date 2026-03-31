"""
app/engine/scanner.py - Scan Execution Engine

Core scan orchestration:
- Check registration and execution
- Context propagation between checks
- Progress tracking
- Verification
"""

import asyncio
import random
import logging
from datetime import datetime
from typing import TYPE_CHECKING

import httpx

from app.checks import CheckRunner
from app.checks.network import DnsEnumerationCheck, PortScanCheck, ServiceProbeCheck
from app.checks.web import (
    HeaderAnalysisCheck, RobotsTxtCheck, PathProbeCheck,
    OpenAPICheck, CorsCheck
)
from app.checks.ai import (
    LLMEndpointCheck, EmbeddingEndpointCheck, ModelInfoCheck,
    AIFrameworkFingerprintCheck, AIErrorLeakageCheck,
    ToolDiscoveryCheck, PromptLeakageCheck,
    RateLimitCheck, ContentFilterCheck, ContextWindowCheck
)
from app.scenarios import get_scenario_manager
from app.proof_of_scope import traffic_logger, ScopeStatus

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger(__name__)


# ─── Check Registry ───────────────────────────────────────────

def get_all_checks():
    """
    Return instances of all available checks.
    
    This is the canonical list of checks in execution order.
    The check pipeline flows:
        dns_enumeration → target_hosts
        port_scan → services (from target_hosts)
        service_probe → enriched services
        web checks → findings (from services)
        ai checks → findings (from services/endpoints)
    """
    return [
        # Network checks - entry point
        DnsEnumerationCheck(),
        PortScanCheck(),
        ServiceProbeCheck(),
        # Web checks
        HeaderAnalysisCheck(),
        RobotsTxtCheck(),
        PathProbeCheck(),
        OpenAPICheck(),
        CorsCheck(),
        # AI checks
        LLMEndpointCheck(),
        EmbeddingEndpointCheck(),
        ModelInfoCheck(),
        AIFrameworkFingerprintCheck(),
        AIErrorLeakageCheck(),
        ToolDiscoveryCheck(),
        PromptLeakageCheck(),
        RateLimitCheck(),
        ContentFilterCheck(),
        ContextWindowCheck(),
    ]


def get_check_info(check) -> dict:
    """Extract info from a check instance."""
    return {
        "name": check.name,
        "description": getattr(check, 'description', ''),
        "reason": getattr(check, 'reason', ''),
        "references": getattr(check, 'references', []),
        "techniques": getattr(check, 'techniques', []),
        "simulated": bool(getattr(check, '_is_simulated', False)),
    }


# Pre-compute available checks for API responses
AVAILABLE_CHECKS = {c.name: get_check_info(c) for c in get_all_checks()}


# ─── Scan Execution ───────────────────────────────────────────

async def run_scan(state: "AppState"):
    """
    Run web reconnaissance checks with progress tracking.
    
    Args:
        state: The application state object to update during scan
    """
    try:
        logger.info(f"Starting scan against {state.target}")
        
        # Create runner
        runner = CheckRunner(
            scope_domains=[state.target],
            excluded_domains=state.exclude,
            parallel=state.settings["parallel"]
        )
        state.runner = runner
        
        # Get real checks as the baseline
        real_checks = get_all_checks()
        logger.info(f"get_all_checks() returned {len(real_checks)} checks: {[c.name for c in real_checks]}")
        
        # If scenario is active, build hybrid check list (simulations override real checks)
        mgr = get_scenario_manager()
        if mgr.is_active:
            simulations = mgr.get_simulations()
            sim_by_name = {s.name: s for s in simulations}
            
            logger.info(f"Scenario '{mgr.active.name}' active — {len(simulations)} simulated checks available")
            
            # Build hybrid list: use simulation if available, otherwise real check
            all_checks = []
            for check in real_checks:
                if check.name in sim_by_name:
                    logger.info(f"  {check.name}: using simulation")
                    all_checks.append(sim_by_name[check.name])
                else:
                    logger.info(f"  {check.name}: using real check")
                    all_checks.append(check)
        else:
            logger.info("No scenario active, using all real checks")
            all_checks = real_checks
        
        # Filter by techniques if specified
        if state.techniques:
            logger.info(f"Filtering by techniques: {state.techniques}")
            checks_to_run = [c for c in all_checks if c.name in state.techniques]
        else:
            checks_to_run = all_checks
        
        # Register checks
        logger.info(f"Registering {len(checks_to_run)} checks: {[c.name for c in checks_to_run]}")
        for check in checks_to_run:
            runner.register_check(check)
            state.check_statuses[check.name] = "pending"
        
        state.checks_total = len(runner.checks)
        logger.info(f"Registered {state.checks_total} checks: {[c.name for c in runner.checks]}")
        
        # Run checks with progress callback
        check_findings = await run_checks_with_progress(runner, state)
        
        logger.info(f"Checks complete. Found {len(check_findings)} findings.")
        
        # Convert to simple dicts
        for cf in check_findings:
            state.findings.append({
                "id": cf.id,
                "title": cf.title,
                "description": cf.description,
                "severity": cf.severity,
                "target_url": cf.target_url,
                "evidence": cf.evidence,
                "check_name": cf.check_name,
                "references": getattr(cf, 'references', []),
                "verified": False,
                "verification_status": "pending"
            })
        
        # Run verification phase if enabled
        verification_level = state.settings.get("verification_level", "none")
        if verification_level != "none" and len(state.findings) > 0:
            await run_verification(state, verification_level)
        else:
            # Mark all as verified if skipping verification
            for f in state.findings:
                f["verified"] = True
                f["verification_status"] = "skipped"
        
        state.status = "complete"
        state.phase = "complete"
        state.current_check = None
        logger.info(f"Scan complete. {len(state.findings)} findings.")
        
    except Exception as e:
        logger.exception(f"Scan error: {e}")
        state.status = "error"
        state.phase = "error"
        state.error_message = str(e)


async def run_checks_with_progress(runner: CheckRunner, state: "AppState"):
    """
    Run checks and update progress state.
    
    This is the core check execution loop. It:
    1. Starts with initial context (scope, base_domain)
    2. Runs checks whose conditions are satisfied
    3. Propagates outputs to context for downstream checks
    4. Tracks progress in state
    
    Args:
        runner: The CheckRunner with registered checks
        state: The application state to update
        
    Returns:
        List of all findings from all checks
    """
    initial_context = {
        "scope_domains": [state.target],
        "excluded_domains": state.exclude,
        "base_domain": state.target,  # DNS enumeration needs this
    }
    
    all_findings = []
    context = initial_context.copy()
    context["services"] = []
    
    iteration = 0
    max_iterations = 100
    
    # Reset all checks to pending
    for check in runner.checks:
        check.status = check.status.__class__.PENDING
        check.result = None
    
    # Log initial state
    logger.info("=" * 60)
    logger.info("Starting check loop")
    logger.info(f"Initial context keys: {list(context.keys())}")
    logger.info(f"Registered checks: {[c.name for c in runner.checks]}")
    for c in runner.checks:
        logger.info(f"  {c.name}: conditions={c.conditions}, can_run={c.can_run(context)}")
    logger.info("=" * 60)
    
    while iteration < max_iterations:
        iteration += 1
        
        # Log iteration state
        logger.info(f"=== Iteration {iteration} ===")
        logger.info(f"Context keys: {list(context.keys())}")
        logger.info(f"context['target_hosts'] = {context.get('target_hosts', 'NOT SET')!r}")
        logger.info(f"context['services'] count = {len(context.get('services', []))}")
        
        # Log each check's state
        for c in runner.checks:
            is_pending = c.status.value == "pending"
            can_run = c.can_run(context)
            missing = c.get_missing_conditions(context) if not can_run else []
            logger.info(f"  {c.name}: status={c.status.value}, pending={is_pending}, can_run={can_run}, missing={missing}")
        
        # Find runnable checks (pending + conditions satisfied)
        runnable = [
            c for c in runner.checks 
            if c.status.value == "pending" and c.can_run(context)
        ]
        
        logger.info(f"Runnable checks: {[c.name for c in runnable]}")
        
        if not runnable:
            logger.info("No runnable checks - breaking loop")
            break
        
        # Execute runnable checks
        for check in runnable:
            # Update state
            state.current_check = check.name
            state.check_statuses[check.name] = "running"
            
            state.check_log.append({
                "check": check.name,
                "event": "started",
                "timestamp": datetime.utcnow().isoformat()
            })
            
            logger.info(f"Running check: {check.name}")
            
            # Execute check
            try:
                result = await check.execute(context)
                logger.info(f"{check.name} completed. success={result.success}, errors={result.errors}")
                logger.info(f"{check.name} outputs: {list(result.outputs.keys())}")
                logger.info(f"{check.name} findings: {len(result.findings)}, services: {len(result.services)}")
            except Exception as e:
                logger.error(f"{check.name} raised exception: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                raise
            
            # Log traffic if enabled
            if state.proof_settings.traffic_logging:
                _log_check_traffic(check.name, context, result, state)
            
            # Update context with outputs
            for key, value in result.outputs.items():
                logger.info(f"Setting context['{key}'] = {value!r}")
                context[key] = value
            
            # Merge services
            if result.services:
                existing = context.get("services", [])
                
                def get_url(s):
                    return s.url if hasattr(s, 'url') else s.get('url', '')
                
                existing_urls = {get_url(s) for s in existing}
                for svc in result.services:
                    if get_url(svc) not in existing_urls:
                        existing.append(svc)
                context["services"] = existing
                logger.info(f"Services merged. Total: {len(context['services'])}")
            
            # Collect findings
            all_findings.extend(result.findings)
            
            # Update state
            state.checks_completed += 1
            state.check_statuses[check.name] = "completed"
            
            state.check_log.append({
                "check": check.name,
                "event": "completed",
                "findings_count": len(result.findings),
                "timestamp": datetime.utcnow().isoformat()
            })
            
            logger.info(f"After {check.name}, context['target_hosts'] = {context.get('target_hosts', 'NOT SET')!r}")
    
    logger.info(f"Loop finished after {iteration} iterations")
    logger.info(f"Total findings: {len(all_findings)}")
    
    # Assign finding IDs
    for i, f in enumerate(all_findings, 1):
        f.id = f"F-{i:03d}"
    
    return all_findings


def _log_check_traffic(check_name: str, context: dict, result, state: "AppState"):
    """Log traffic for a check execution."""
    services = context.get("services", [])
    for svc in services:
        svc_url = svc.url if hasattr(svc, 'url') else svc.get('url', '')
        if not svc_url:
            continue
            
        scope_status = ScopeStatus.IN_SCOPE
        if state.scope_checker:
            host = svc_url.split("://")[1].split("/")[0].split(":")[0] if "://" in svc_url else svc_url
            scope_status = state.scope_checker.check_host(host)
        
        traffic_logger.log_request(
            dst_host=svc_url,
            method="GET",
            path="/",
            check_name=check_name,
            scope_status=scope_status
        )


async def run_verification(state: "AppState", level: str):
    """
    Verify findings by re-requesting endpoints.
    
    Levels:
    - sample: Verify ~20% of findings
    - half: Verify 50% of findings  
    - all: Verify all findings
    """
    state.status = "verifying"
    state.phase = "verifying"
    
    findings = state.findings
    total = len(findings)
    
    # Determine how many to verify
    if level == "sample":
        count = max(1, int(total * 0.2))
    elif level == "half":
        count = max(1, int(total * 0.5))
    else:  # all
        count = total
    
    # Select findings to verify
    if count < total:
        to_verify = random.sample(findings, count)
    else:
        to_verify = findings
    
    state.verification_total = len(to_verify)
    state.verified_count = 0
    
    logger.info(f"Verifying {len(to_verify)} of {total} findings (level: {level})")
    
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        for finding in to_verify:
            try:
                target_url = finding.get("target_url")
                if not target_url:
                    finding["verified"] = True
                    finding["verification_status"] = "no_url"
                    state.verified_count += 1
                    continue
                
                # Re-request the endpoint
                response = await client.get(target_url)
                
                # Check if the finding is still valid
                if response.status_code < 500:
                    finding["verified"] = True
                    finding["verification_status"] = "verified"
                else:
                    finding["verified"] = False
                    finding["verification_status"] = "failed"
                
                state.verified_count += 1
                
            except Exception as e:
                logger.warning(f"Verification failed for {finding.get('id')}: {e}")
                finding["verified"] = False
                finding["verification_status"] = "error"
                state.verified_count += 1
    
    # Mark non-verified findings
    verified_ids = {f["id"] for f in to_verify}
    for finding in findings:
        if finding["id"] not in verified_ids:
            finding["verification_status"] = "not_checked"
    
    logger.info(f"Verification complete. {state.verified_count} findings verified.")
