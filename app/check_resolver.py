"""
app/check_resolver.py - Check List Builder

Builds the list of checks to run, handling:
- Real checks (default) — community + custom
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

import importlib
import logging

logger = logging.getLogger(__name__)


def resolve_checks(
    techniques: list[str] | None = None,
    scenario_name: str | None = None,
    check_names: list[str] | None = None,
    suites: list[str] | None = None,
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
    from app.checks.agent import (
        AgentCallbackInjectionCheck,
        AgentContextOverflowCheck,
        AgentCrossInjectionCheck,
        AgentDiscoveryCheck,
        AgentFrameworkExploitsCheck,
        AgentFrameworkVersionCheck,
        AgentGoalInjectionCheck,
        AgentLoopDetectionCheck,
        AgentMemoryExtractionCheck,
        AgentMemoryPoisoningCheck,
        AgentMultiAgentDetectionCheck,
        AgentPrivilegeEscalationCheck,
        AgentReflectionAbuseCheck,
        AgentStateManipulationCheck,
        AgentStreamingInjectionCheck,
        AgentToolAbuseCheck,
        AgentTrustChainCheck,
    )
    from app.checks.ai import (
        AIErrorLeakageCheck,
        AIFrameworkFingerprintCheck,
        APIParameterInjectionCheck,
        ContentFilterCheck,
        ContextWindowCheck,
        EmbeddingEndpointCheck,
        InputFormatInjectionCheck,
        JailbreakTestingCheck,
        LLMEndpointCheck,
        ModelEnumerationCheck,
        ModelInfoCheck,
        MultiTurnInjectionCheck,
        OutputFormatManipulationCheck,
        PromptLeakageCheck,
        RateLimitCheck,
        SystemPromptInjectionCheck,
        TokenCostExhaustionCheck,
        ToolDiscoveryCheck,
    )
    from app.checks.cag import (
        CacheEvictionCheck,
        CacheKeyReverseCheck,
        CachePoisoningCheck,
        CacheQuotaCheck,
        CacheWarmingCheck,
        CAGCacheProbeCheck,
        CAGDiscoveryCheck,
        CrossUserLeakageCheck,
        DistributedCacheCheck,
        InjectionPersistenceCheck,
        MultiLayerCacheCheck,
        ProviderCachingCheck,
        SemanticThresholdCheck,
        SerializationCheck,
        SideChannelCheck,
        StaleContextCheck,
        TTLMappingCheck,
    )
    from app.checks.mcp import (
        MCPAuthCheck,
        MCPDiscoveryCheck,
        MCPNotificationInjectionCheck,
        MCPPromptInjectionCheck,
        MCPProtocolVersionCheck,
        MCPResourceTraversalCheck,
        MCPSamplingAbuseCheck,
        MCPServerFingerprintCheck,
        MCPToolEnumerationCheck,
        MCPToolInvocationCheck,
        ResourceTemplateInjectionCheck,
        ShadowToolDetectionCheck,
        ToolChainAnalysisCheck,
        ToolRateLimitCheck,
        ToolSchemaLeakageCheck,
        TransportSecurityCheck,
        UndeclaredCapabilityCheck,
        WebSocketTransportCheck,
    )
    from app.checks.network import (
        BannerGrabCheck,
        DnsEnumerationCheck,
        DnsRecordCheck,
        GeoIpCheck,
        HttpMethodEnumCheck,
        IPv6DiscoveryCheck,
        PortScanCheck,
        ReverseDnsCheck,
        ServiceProbeCheck,
        TlsAnalysisCheck,
        TracerouteCheck,
        WhoisLookupCheck,
        WildcardDnsCheck,
    )
    from app.checks.rag import (
        RAGAdversarialEmbeddingCheck,
        RAGAuthBypassCheck,
        RAGCachePoisoningCheck,
        RAGChunkBoundaryCheck,
        RAGCollectionEnumerationCheck,
        RAGCorpusPoisoningCheck,
        RAGCrossCollectionCheck,
        RAGDiscoveryCheck,
        RAGDocumentExfiltrationCheck,
        RAGEmbeddingFingerprintCheck,
        RAGFusionRerankerCheck,
        RAGIndirectInjectionCheck,
        RAGMetadataInjectionCheck,
        RAGMultimodalInjectionCheck,
        RAGRetrievalManipulationCheck,
        RAGSourceAttributionCheck,
        RAGVectorStoreAccessCheck,
    )
    from app.checks.web import (
        AuthDetectionCheck,
        ConfigExposureCheck,
        CookieSecurityCheck,
        CorsCheck,
        DebugEndpointCheck,
        DefaultCredsCheck,
        DirectoryListingCheck,
        ErrorPageCheck,
        FaviconCheck,
        HeaderAnalysisCheck,
        HSTSPreloadCheck,
        HTTP2DetectionCheck,
        MassAssignmentCheck,
        OpenAPICheck,
        PathProbeCheck,
        RedirectChainCheck,
        RobotsTxtCheck,
        SitemapCheck,
        SRICheck,
        SSRFIndicatorCheck,
        VCSExposureCheck,
        WAFDetectionCheck,
        WebDAVCheck,
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
        # Web critical observations (Phase 6a — depends on services, some use path_probe output)
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
        # Agent Phase 1 (depends on services — discovery)
        AgentDiscoveryCheck(),
        # Agent Phase 2 (depends on agent_endpoints)
        AgentMultiAgentDetectionCheck(),
        AgentFrameworkVersionCheck(),
        AgentMemoryExtractionCheck(),
        # Agent Phase 3 (depends on Phase 2 — active probing)
        AgentGoalInjectionCheck(),
        AgentToolAbuseCheck(),
        AgentPrivilegeEscalationCheck(),
        AgentLoopDetectionCheck(),
        AgentCallbackInjectionCheck(),
        AgentStreamingInjectionCheck(),
        # Agent Phase 4 (depends on Phase 2-3 — framework-specific)
        AgentFrameworkExploitsCheck(),
        AgentMemoryPoisoningCheck(),
        AgentContextOverflowCheck(),
        AgentReflectionAbuseCheck(),
        AgentStateManipulationCheck(),
        # Agent Phase 5 (depends on multi-agent detection)
        AgentTrustChainCheck(),
        AgentCrossInjectionCheck(),
        # RAG Phase 1 (depends on services — discovery)
        RAGDiscoveryCheck(),
        # RAG Phase 2 (depends on rag_endpoints / vector_stores)
        RAGVectorStoreAccessCheck(),
        RAGAuthBypassCheck(),
        RAGCollectionEnumerationCheck(),
        RAGEmbeddingFingerprintCheck(),
        # RAG Phase 3 (depends on Phase 1-2 — read-only probing)
        RAGIndirectInjectionCheck(),
        RAGDocumentExfiltrationCheck(),
        RAGRetrievalManipulationCheck(),
        RAGSourceAttributionCheck(),
        RAGCachePoisoningCheck(),
        # RAG Phase 4 (depends on Phase 2-3 — write/intrusive)
        RAGCorpusPoisoningCheck(),
        RAGMetadataInjectionCheck(),
        RAGChunkBoundaryCheck(),
        RAGMultimodalInjectionCheck(),
        # RAG Phase 5 (depends on Phase 3-4 — advanced)
        RAGFusionRerankerCheck(),
        RAGCrossCollectionCheck(),
        RAGAdversarialEmbeddingCheck(),
        # CAG Phase 1 (depends on services — discovery)
        CAGDiscoveryCheck(),
        CAGCacheProbeCheck(),
        # CAG Phase 2 (depends on cag_endpoints — infrastructure analysis)
        CacheEvictionCheck(),
        CacheWarmingCheck(),
        TTLMappingCheck(),
        MultiLayerCacheCheck(),
        CacheQuotaCheck(),
        ProviderCachingCheck(),
        # CAG Phase 3 (depends on Phase 1-2 — deep probing)
        CrossUserLeakageCheck(),
        CacheKeyReverseCheck(),
        SemanticThresholdCheck(),
        SideChannelCheck(),
        StaleContextCheck(),
        # CAG Phase 4 (active exploitation — intrusive)
        CachePoisoningCheck(),
        InjectionPersistenceCheck(),
        # CAG Phase 5 (advanced — infrastructure-dependent)
        SerializationCheck(),
        DistributedCacheCheck(),
    ]

    logger.info(f"Loaded {len(checks)} community checks")

    # Custom checks (dynamic discovery from custom/)
    custom = _get_custom_checks()
    if custom:
        checks.extend(custom)
        logger.info(f"Loaded {len(custom)} custom checks")

    logger.info(f"Total checks available: {len(checks)}")
    return checks


def _get_custom_checks() -> list:
    """Discover and load custom checks from app/checks/custom/.

    Reads the CUSTOM_CHECK_REGISTRY from custom/__init__.py,
    imports each module, instantiates each class, and validates
    that it extends BaseCheck with well-formed metadata.

    Returns only checks that instantiate successfully.
    """
    from app.checks.base import BaseCheck
    from app.checks.custom import CUSTOM_CHECK_REGISTRY

    checks = []
    for module_name, class_name in CUSTOM_CHECK_REGISTRY:
        try:
            mod = importlib.import_module(f"app.checks.custom.{module_name}")
            cls = getattr(mod, class_name)
            if not issubclass(cls, BaseCheck):
                logger.warning(
                    f"Custom check {class_name} in {module_name} does not extend BaseCheck — skipped"
                )
                continue
            instance = cls()
            checks.append(instance)
            logger.info(f"  Custom check loaded: {instance.name}")
        except Exception as e:
            logger.warning(f"Failed to load custom check {module_name}.{class_name}: {e}")
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
    from app.scenarios import ScenarioLoadError, get_scenario_manager

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

    logger.info(
        f"Scenario '{scenario_name}' has {len(simulations)} simulations: {list(sim_by_name.keys())}"
    )

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
        # Prefix-based suites first (avoid false matches with AI patterns)
        "mcp": ["mcp"],
        "agent": ["agent"],
        "rag": ["rag"],
        "cag": ["cag"],
        "network": [
            "dns",
            "wildcard_dns",
            "geoip",
            "reverse_dns",
            "port_scan",
            "tls_analysis",
            "service_probe",
            "http_method_enum",
            "banner_grab",
            "whois_lookup",
            "traceroute",
            "ipv6_discovery",
        ],
        "web": [
            "header",
            "robots",
            "path",
            "openapi",
            "cors",
            "webdav",
            "vcs_exposure",
            "config_exposure",
            "directory_listing",
            "default_creds",
            "debug_endpoints",
            "cookie_security",
            "auth_detection",
            "waf_detection",
            "sitemap",
            "redirect_chain",
            "error_page",
            "ssrf_indicator",
            "favicon",
            "http2_detection",
            "hsts_preload",
            "sri_check",
            "mass_assignment",
        ],
        "ai": [
            "llm",
            "embedding",
            "model_info",
            "fingerprint",
            "error",
            "tool_discovery",
            "prompt",
            "rate_limit",
            "filter",
            "context",
            "jailbreak",
            "multi_turn",
            "input_format",
            "model_enum",
            "token_cost",
            "system_prompt_injection",
            "output_format",
            "api_parameter",
        ],
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
