"""
app/check_resolver.py - Check List Builder

Builds the list of checks to run, handling:
- Real checks (default)
- Scenario simulations (override real checks)
- Technique filtering (run only specific checks)

This is separate from execution — it just decides WHAT to run.
The CheckLauncher handles HOW to run them.

Usage:
    from app.check_resolver import resolve_checks
    
    checks = resolve_checks(
        techniques=["dns_enumeration", "port_scan"],  # Optional filter
        scenario_name="fakobanko"  # Optional scenario
    )
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def resolve_checks(
    techniques: Optional[list[str]] = None,
    scenario_name: Optional[str] = None,
    check_names: Optional[list[str]] = None,
    suites: Optional[list[str]] = None,
) -> list:
    """
    Build the list of checks to run.

    Args:
        techniques: If provided, only run checks with these names (legacy)
        scenario_name: If provided, load this scenario and use its simulations
        check_names: If provided, only run checks matching these names
        suites: If provided, only run checks belonging to these suites

    Returns:
        List of check instances ready to run
    """
    # Get all real checks
    real_checks = get_real_checks()
    logger.info(f"Real checks available: {len(real_checks)} — {[c.name for c in real_checks]}")

    # If scenario active, merge simulations with real checks
    if scenario_name:
        checks = apply_scenario(real_checks, scenario_name)
    else:
        checks = real_checks

    # Filter by techniques if specified (legacy)
    if techniques:
        checks = filter_by_techniques(checks, techniques)

    # Filter by explicit check names
    if check_names:
        checks = [c for c in checks if c.name in check_names]
        logger.info(f"Filtered to {len(checks)} checks by names: {check_names}")

    # Filter by suites
    if suites:
        checks = filter_by_suites(checks, suites)

    logger.info(f"Final check list: {len(checks)} — {[c.name for c in checks]}")
    return checks


def get_real_checks() -> list:
    """Get all real check instances."""
    from app.checks.network import (
        DnsEnumerationCheck, WildcardDnsCheck, DnsRecordCheck, GeoIpCheck,
        ReverseDnsCheck, PortScanCheck, TlsAnalysisCheck, ServiceProbeCheck,
        HttpMethodEnumCheck, BannerGrabCheck,
        WhoisLookupCheck, TracerouteCheck, IPv6DiscoveryCheck,
    )
    from app.checks.web import (
        HeaderAnalysisCheck, RobotsTxtCheck, PathProbeCheck,
        OpenAPICheck, CorsCheck,
        WebDAVCheck, VCSExposureCheck, ConfigExposureCheck,
        DirectoryListingCheck, DefaultCredsCheck, DebugEndpointCheck,
        CookieSecurityCheck, AuthDetectionCheck, WAFDetectionCheck,
        SitemapCheck, RedirectChainCheck, ErrorPageCheck, SSRFIndicatorCheck,
        FaviconCheck, HTTP2DetectionCheck, HSTSPreloadCheck,
        SRICheck, MassAssignmentCheck,
    )
    from app.checks.mcp import (
        MCPDiscoveryCheck, MCPToolEnumerationCheck,
        MCPAuthCheck, WebSocketTransportCheck,
        ToolChainAnalysisCheck, ShadowToolDetectionCheck,
        ToolSchemaLeakageCheck, MCPServerFingerprintCheck,
        TransportSecurityCheck, MCPNotificationInjectionCheck,
        MCPToolInvocationCheck, MCPResourceTraversalCheck,
        ResourceTemplateInjectionCheck, MCPPromptInjectionCheck,
        MCPSamplingAbuseCheck, MCPProtocolVersionCheck,
        ToolRateLimitCheck, UndeclaredCapabilityCheck,
    )
    from app.checks.ai import (
        LLMEndpointCheck, EmbeddingEndpointCheck, ModelInfoCheck,
        AIFrameworkFingerprintCheck, AIErrorLeakageCheck,
        ToolDiscoveryCheck, PromptLeakageCheck,
        RateLimitCheck, ContentFilterCheck, ContextWindowCheck,
        JailbreakTestingCheck, MultiTurnInjectionCheck,
        InputFormatInjectionCheck, ModelEnumerationCheck,
        TokenCostExhaustionCheck, SystemPromptInjectionCheck,
        OutputFormatManipulationCheck, APIParameterInjectionCheck,
    )
    
    # Instantiate all checks in dependency order
    checks = [
        # Network Phase 1 (no dependencies, can run in parallel)
        DnsEnumerationCheck(),
        WildcardDnsCheck(),
        DnsRecordCheck(),
        WhoisLookupCheck(),

        # Network Phase 2 (depends on dns_enumeration)
        GeoIpCheck(),
        ReverseDnsCheck(),
        IPv6DiscoveryCheck(),
        PortScanCheck(),

        # Network Phase 4 (depends on services/port_scan)
        TlsAnalysisCheck(),
        ServiceProbeCheck(),
        BannerGrabCheck(),

        # Network Phase 5 (depends on service_probe)
        HttpMethodEnumCheck(),
        TracerouteCheck(),
        
        # Web Phase 1 (depends on services)
        HeaderAnalysisCheck(),
        CookieSecurityCheck(),
        CorsCheck(),
        RobotsTxtCheck(),
        WAFDetectionCheck(),
        AuthDetectionCheck(),
        FaviconCheck(),
        HTTP2DetectionCheck(),

        # Web Phase 2 (depends on Phase 1)
        PathProbeCheck(),
        SitemapCheck(),
        ErrorPageCheck(),
        OpenAPICheck(),

        # Web critical findings (Phase 6a — depends on services, some use path_probe output)
        WebDAVCheck(),
        VCSExposureCheck(),
        ConfigExposureCheck(),
        DirectoryListingCheck(),
        DefaultCredsCheck(),
        DebugEndpointCheck(),

        # Web Phase 4 (depends on Phase 2-3)
        RedirectChainCheck(),
        SSRFIndicatorCheck(),
        MassAssignmentCheck(),
        HSTSPreloadCheck(),
        SRICheck(),
        
        # AI discovery (depends on services)
        LLMEndpointCheck(),
        EmbeddingEndpointCheck(),
        ModelInfoCheck(),
        AIFrameworkFingerprintCheck(),
        
        # AI Phase 2 (depends on chat_endpoints)
        AIErrorLeakageCheck(),
        ContentFilterCheck(),
        RateLimitCheck(),
        ContextWindowCheck(),
        ModelEnumerationCheck(),
        APIParameterInjectionCheck(),
        SystemPromptInjectionCheck(),

        # AI Phase 3 (depends on Phase 2 results)
        ToolDiscoveryCheck(),
        PromptLeakageCheck(),
        OutputFormatManipulationCheck(),

        # AI Phase 4 (uses filter/tool knowledge from Phase 2-3)
        JailbreakTestingCheck(),
        MultiTurnInjectionCheck(),
        InputFormatInjectionCheck(),
        TokenCostExhaustionCheck(),

        # MCP Phase 1 (depends on services — discovery)
        MCPDiscoveryCheck(),
        WebSocketTransportCheck(),

        # MCP Phase 2 (depends on mcp_servers)
        MCPToolEnumerationCheck(),
        MCPAuthCheck(),
        TransportSecurityCheck(),
        MCPServerFingerprintCheck(),
        UndeclaredCapabilityCheck(),
        MCPProtocolVersionCheck(),

        # MCP Phase 3 (depends on Phase 2 — tool data + server connections)
        ShadowToolDetectionCheck(),
        ToolSchemaLeakageCheck(),
        ToolChainAnalysisCheck(),
        MCPNotificationInjectionCheck(),
        MCPSamplingAbuseCheck(),
        ToolRateLimitCheck(),

        # MCP Phase 4 (active probing — requires tool invocation)
        MCPToolInvocationCheck(),
        MCPResourceTraversalCheck(),
        ResourceTemplateInjectionCheck(),

        # MCP Phase 5 (cross-suite — depends on MCP + AI suite)
        MCPPromptInjectionCheck(),
    ]
    
    logger.info(f"Loaded {len(checks)} real checks")
    return checks


def apply_scenario(real_checks: list, scenario_name: str) -> list:
    """
    Apply scenario simulations to check list.
    
    Simulations replace real checks with the same name.
    Real checks without a simulation are kept as-is.
    
    Args:
        real_checks: List of real check instances
        scenario_name: Name of scenario to load
    
    Returns:
        Hybrid list with simulations where available
    """
    from app.scenarios import get_scenario_manager, ScenarioLoadError
    
    mgr = get_scenario_manager()
    
    # Load scenario if not already active
    if not mgr.is_active or mgr.active.name != scenario_name:
        try:
            mgr.load(scenario_name)
            logger.info(f"Loaded scenario: {scenario_name}")
        except ScenarioLoadError as e:
            logger.warning(f"Could not load scenario '{scenario_name}': {e}")
            return real_checks
    
    # Get simulations
    simulations = mgr.get_simulations()
    sim_by_name = {s.name: s for s in simulations}
    
    logger.info(f"Scenario '{scenario_name}' has {len(simulations)} simulations: {list(sim_by_name.keys())}")
    
    # Build hybrid list
    result = []
    for check in real_checks:
        if check.name in sim_by_name:
            logger.info(f"  {check.name}: using SIMULATION")
            result.append(sim_by_name[check.name])
        else:
            logger.info(f"  {check.name}: using real check")
            result.append(check)
    
    return result


def filter_by_techniques(checks: list, techniques: list[str]) -> list:
    """
    Filter checks to only those in the techniques list.
    
    Args:
        checks: Full list of checks
        techniques: Names of checks to keep
    
    Returns:
        Filtered list
    """
    filtered = [c for c in checks if c.name in techniques]
    logger.info(f"Filtered to {len(filtered)} checks by techniques: {techniques}")
    return filtered


def filter_by_suites(checks: list, suites: list[str]) -> list:
    """
    Filter checks to only those belonging to the given suites.

    Suite is inferred from the check name since checks don't carry
    an explicit suite attribute.
    """
    filtered = [c for c in checks if infer_suite(c.name) in suites]
    logger.info(f"Filtered to {len(filtered)} checks by suites: {suites}")
    return filtered


def infer_suite(check_name: str) -> str:
    """Infer the suite name from a check name."""
    name_lower = check_name.lower()
    suite_patterns = {
        "network": ["dns", "wildcard_dns", "geoip", "reverse_dns", "port_scan",
                    "tls_analysis", "service_probe", "http_method_enum",
                    "banner_grab", "whois_lookup", "traceroute",
                    "ipv6_discovery"],
        "web": ["header", "robots", "path", "openapi", "cors",
                "webdav", "vcs_exposure", "config_exposure", "directory_listing",
                "default_creds", "debug_endpoints",
                "cookie_security", "auth_detection", "waf_detection",
                "sitemap", "redirect_chain", "error_page", "ssrf_indicator",
                "favicon", "http2_detection", "hsts_preload", "sri_check",
                "mass_assignment"],
        "ai": ["llm", "embedding", "model_info", "fingerprint", "error",
                "tool_discovery", "prompt", "rate_limit", "filter", "context",
                "jailbreak", "multi_turn", "input_format", "model_enum",
                "token_cost", "system_prompt_injection", "output_format",
                "api_parameter"],
        "mcp": ["mcp"],
        "agent": ["agent"],
        "rag": ["rag"],
        "cag": ["cag"],
    }
    for suite, patterns in suite_patterns.items():
        if any(p in name_lower for p in patterns):
            return suite
    return "other"


def get_check_by_name(name: str):
    """Get a single check instance by name."""
    checks = get_real_checks()
    for c in checks:
        if c.name == name:
            return c
    return None
