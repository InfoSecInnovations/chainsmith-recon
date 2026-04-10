"""
app/engine/chains.py - Attack Chain Detection

Two-pass chain analysis:
1. Rule-based pattern matching against known attack patterns
2. LLM-based discovery of novel chains
"""

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from app.lib.llm import (
    LLMErrorType,
    LLMResponse,
    get_llm_client,
)

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger(__name__)

# Maximum auto-retries for retryable LLM errors
LLM_MAX_RETRIES = 2
# Backoff delays in seconds (attempt 2 → 2s, attempt 3 → 4s)
LLM_RETRY_DELAYS = [2, 4]


@dataclass
class ChainAnalysisResult:
    """Structured result from LLM chain analysis."""

    chains: list[dict] = field(default_factory=list)
    llm_status: str = "success"  # success, failed, partial, not_configured
    llm_response: LLMResponse | None = None
    attempts: int = 0
    sanitized_prompt_used: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_analysis_dict(self) -> dict:
        """Build the llm_analysis dict for state / API response."""
        resp = self.llm_response
        return {
            "status": self.llm_status,
            "error_type": (resp.error_type.value if resp else LLMErrorType.NONE.value),
            "error_message": (resp.error if resp and not resp.success else None),
            "provider": (resp.provider if resp else None),
            "model": (resp.model if resp else None),
            "retryable": (resp.retryable if resp and not resp.success else False),
            "auto_mitigated": self.sanitized_prompt_used and self.llm_status == "success",
            "attempts": self.attempts,
            "timestamp": self.timestamp,
            "sanitized_prompt_used": self.sanitized_prompt_used,
            "token_usage": (resp.usage if resp and resp.usage else None),
        }


def _load_sanitized_terms() -> dict[str, str]:
    """Load content-filter term replacements from data file."""
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "sanitized_terms.json"
    )
    try:
        with open(data_path) as f:
            data = json.load(f)
        return data.get("replacements", {})
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Could not load sanitized terms: {e}")
        return {}


def _sanitize_prompt(prompt: str) -> str:
    """Replace security-specific terms with sanitized alternatives."""
    terms = _load_sanitized_terms()
    sanitized = prompt
    # Sort by length descending so longer matches replace first
    for original, replacement in sorted(terms.items(), key=lambda x: -len(x[0])):
        # Case-insensitive replacement preserving first-char case
        import re

        def _repl(m, _replacement=replacement):
            matched = m.group(0)
            if matched[0].isupper():
                return _replacement[0].upper() + _replacement[1:]
            return _replacement

        sanitized = re.sub(re.escape(original), _repl, sanitized, flags=re.IGNORECASE)
    return sanitized


# ─── Attack Chain Patterns ────────────────────────────────────

CHAIN_PATTERNS = [
    {
        "name": "api_documentation_recon",
        "title": "API Documentation Intelligence Gathering",
        "description": "Exposed API documentation combined with endpoint discovery reveals full attack surface",
        "severity": "medium",
        "required_observations": [
            {"check_name": "openapi_discovery"},
            {"check_name": "path_probe", "title_contains": "openapi"},
        ],
        "exploitation_steps": [
            "Access the exposed OpenAPI/Swagger documentation",
            "Enumerate all available endpoints and their parameters",
            "Identify authentication requirements for each endpoint",
            "Map out data models and potential injection points",
            "Use documentation to craft targeted API attacks",
        ],
    },
    {
        "name": "technology_stack_fingerprint",
        "title": "Technology Stack Identification",
        "description": "Version disclosure enables targeted vulnerability research",
        "severity": "medium",
        "required_observations": [
            {"check_name": "service_probe", "title_contains": "Technology"},
            {"check_name": "service_probe", "title_contains": "Server"},
        ],
        "exploitation_steps": [
            "Note the disclosed technology versions (e.g., vLLM/0.4.1)",
            "Search CVE databases for known vulnerabilities",
            "Check for default credentials or configurations",
            "Research technology-specific attack techniques",
            "Prepare targeted exploits based on version information",
        ],
    },
    {
        "name": "security_header_weakness",
        "title": "Client-Side Attack Surface",
        "description": "Missing security headers enable client-side attacks",
        "severity": "low",
        "required_observations": [
            {"check_name": "header_analysis", "title_contains": "Missing security headers"}
        ],
        "exploitation_steps": [
            "Note missing headers (CSP, X-Frame-Options, etc.)",
            "Test for XSS vulnerabilities without CSP protection",
            "Attempt clickjacking attacks without frame protection",
            "Check for MIME-sniffing vulnerabilities",
            "Craft client-side attack payloads",
        ],
    },
    {
        "name": "protected_admin_interface",
        "title": "Protected Administrative Interface",
        "description": "Admin interface exists but is protected - potential authorization bypass target",
        "severity": "medium",
        "required_observations": [
            {
                "check_name": "path_probe",
                "title_contains": "Protected path",
                "title_contains_2": "admin",
            }
        ],
        "exploitation_steps": [
            "Note the protected admin path location",
            "Test for authorization bypass techniques",
            "Check for parameter manipulation to access admin functions",
            "Look for alternative paths to admin functionality",
            "Test for IDOR vulnerabilities in admin endpoints",
        ],
    },
    {
        "name": "debug_endpoint_exposure",
        "title": "Debug Endpoint Information Leakage",
        "description": "Debug endpoints may leak sensitive configuration or allow manipulation",
        "severity": "high",
        "required_observations": [
            {"check_name": "openapi_discovery", "evidence_contains": "debug"}
        ],
        "exploitation_steps": [
            "Access discovered debug endpoints",
            "Extract configuration information",
            "Look for sensitive data in debug output",
            "Test for debug functionality that modifies state",
            "Check for ability to enable verbose error messages",
        ],
    },
    {
        "name": "multi_service_attack_surface",
        "title": "Multi-Service Architecture Reconnaissance",
        "description": "Multiple services discovered increases attack surface complexity",
        "severity": "medium",
        "required_observations": [{"check_name": "dns_enumeration", "count_gte": 2}],
        "exploitation_steps": [
            "Map relationships between discovered services",
            "Identify internal communication patterns",
            "Look for services with weaker security postures",
            "Test for SSRF between services",
            "Check for trust relationships that can be exploited",
        ],
    },
    {
        "name": "ai_service_prompt_injection",
        "title": "AI/ML Service Prompt Injection Surface",
        "description": "Chat/AI endpoints combined with API documentation suggest prompt injection opportunities",
        "severity": "high",
        "required_observations": [
            {"check_name": "llm_endpoint_discovery"},
            {"check_name": "openapi_discovery"},
        ],
        "exploitation_steps": [
            "Identify chat/completion endpoints from API documentation",
            "Test for prompt injection vulnerabilities",
            "Attempt to extract system prompts",
            "Try to bypass content filters",
            "Test for indirect prompt injection via other data sources",
        ],
    },
    {
        "name": "ai_model_reconnaissance",
        "title": "AI Model Information Disclosure",
        "description": "Model information endpoints reveal architecture details for targeted attacks",
        "severity": "medium",
        "required_observations": [
            {"check_name": "model_info_check"},
            {"check_name": "ai_framework_fingerprint"},
        ],
        "exploitation_steps": [
            "Extract model version and architecture details",
            "Research known vulnerabilities for identified framework",
            "Identify model-specific attack techniques",
            "Use model info to craft targeted prompts",
            "Check for model configuration weaknesses",
        ],
    },
    {
        "name": "ai_error_exploitation",
        "title": "AI Service Error-Based Reconnaissance",
        "description": "Error messages from AI service reveal internal structure and tools",
        "severity": "high",
        "required_observations": [
            {"check_name": "ai_error_leakage", "title_contains": "tool"},
        ],
        "exploitation_steps": [
            "Analyze leaked tool names from error messages",
            "Map internal API structure from path disclosures",
            "Use stack traces to identify code paths",
            "Craft inputs that trigger informative errors",
            "Target discovered tools for abuse",
        ],
    },
    {
        "name": "embedding_data_extraction",
        "title": "Embedding Endpoint Data Exposure",
        "description": "Embedding endpoints may enable training data extraction or inference attacks",
        "severity": "medium",
        "required_observations": [{"check_name": "embedding_endpoint_discovery"}],
        "exploitation_steps": [
            "Test embedding endpoint for membership inference",
            "Attempt to extract training data patterns",
            "Check for embedding inversion possibilities",
            "Test rate limits on embedding generation",
            "Look for sensitive data in embedding responses",
        ],
    },
    # ─── RAG Chains ──────────────────────────────────────────────
    {
        "name": "rag_pipeline_compromise",
        "title": "RAG Pipeline Prompt Injection",
        "description": "Discovered RAG pipeline is vulnerable to indirect prompt injection, enabling attacker-controlled context to influence all responses",
        "severity": "high",
        "required_observations": [
            {"check_name": "rag_discovery"},
            {"check_name": "rag_indirect_injection"},
        ],
        "exploitation_steps": [
            "Confirm RAG pipeline endpoints from discovery observations",
            "Craft documents containing indirect prompt injection payloads",
            "Submit crafted queries that trigger retrieval of poisoned context",
            "Verify injection payloads execute within the LLM response",
            "Escalate to data exfiltration or user manipulation via injected instructions",
        ],
    },
    {
        "name": "rag_data_theft",
        "title": "RAG Document Exfiltration",
        "description": "RAG endpoint leaks sensitive document content through crafted retrieval queries",
        "severity": "high",
        "required_observations": [
            {"check_name": "rag_discovery"},
            {"check_name": "rag_document_exfiltration"},
        ],
        "exploitation_steps": [
            "Identify RAG pipeline endpoints and query interface",
            "Craft queries designed to maximize retrieval of sensitive documents",
            "Use iterative probing to extract full document contents chunk by chunk",
            "Correlate extracted content to identify confidential data categories",
            "Assess scope of exposed data across the knowledge base",
        ],
    },
    {
        "name": "rag_corpus_poisoning_pipeline",
        "title": "RAG Corpus Poisoning with Persistent Injection",
        "description": "Writable ingestion endpoint combined with injection vulnerability enables persistent attacker-controlled responses for all users",
        "severity": "critical",
        "required_observations": [
            {"check_name": "rag_corpus_poisoning"},
            {"check_name": "rag_indirect_injection"},
        ],
        "exploitation_steps": [
            "Identify writable document ingestion endpoints",
            "Craft documents embedding persistent prompt injection payloads",
            "Ingest poisoned documents into the RAG corpus",
            "Verify poisoned documents are retrieved for targeted query topics",
            "Confirm injected instructions persist and affect all users querying those topics",
        ],
    },
    {
        "name": "rag_vector_store_direct_access",
        "title": "Vector Store Unauthenticated Access",
        "description": "Direct unauthenticated access to the vector store backend bypasses all RAG pipeline controls",
        "severity": "high",
        "required_observations": [
            {"check_name": "rag_vector_store_access"},
            {"check_name": "rag_auth_bypass"},
        ],
        "exploitation_steps": [
            "Access vector store API endpoints directly using discovered bypass",
            "Enumerate all stored collections and their metadata",
            "Query vectors directly to extract raw document embeddings",
            "Attempt to modify or delete vectors to corrupt the knowledge base",
            "Exfiltrate document content by reconstructing from stored chunks",
        ],
    },
    {
        "name": "rag_cross_collection_leak",
        "title": "RAG Cross-Collection Data Leakage",
        "description": "Enumerated collections combined with broken isolation enables lateral access across knowledge bases",
        "severity": "high",
        "required_observations": [
            {"check_name": "rag_collection_enumeration"},
            {"check_name": "rag_cross_collection"},
        ],
        "exploitation_steps": [
            "Enumerate all available vector store collections",
            "Identify collections belonging to different tenants or security contexts",
            "Craft queries that trigger cross-collection retrieval",
            "Extract data from collections the current user should not access",
            "Map the full scope of data accessible through broken isolation",
        ],
    },
    {
        "name": "rag_metadata_trust_manipulation",
        "title": "RAG Metadata Injection with Source Spoofing",
        "description": "Injected metadata poisons source citations, enabling phishing or trust manipulation via fabricated references",
        "severity": "medium",
        "required_observations": [
            {"check_name": "rag_metadata_injection"},
            {"check_name": "rag_source_attribution"},
        ],
        "exploitation_steps": [
            "Identify metadata fields that flow into RAG source citations",
            "Craft injection payloads targeting document metadata (titles, URLs, authors)",
            "Verify fabricated source attributions appear in LLM responses",
            "Use spoofed citations to direct users to attacker-controlled resources",
            "Escalate to phishing by embedding malicious URLs in trusted citation format",
        ],
    },
    # ─── CAG Chains ──────────────────────────────────────────────
    {
        "name": "cag_cross_user_data_exposure",
        "title": "CAG Cross-User Data Leakage",
        "description": "Cache serves one user's context to another — direct data leakage across trust boundaries",
        "severity": "critical",
        "required_observations": [
            {"check_name": "cag_discovery"},
            {"check_name": "cag_cross_user_leakage"},
        ],
        "exploitation_steps": [
            "Identify CAG endpoints and caching infrastructure",
            "Submit queries designed to populate the cache with identifiable content",
            "Switch authentication context and query for the same or similar topics",
            "Verify that cached responses from other users are returned",
            "Systematically extract other users' cached conversations and context",
        ],
    },
    {
        "name": "cag_persistent_poisoning",
        "title": "CAG Cache Poisoning Attack",
        "description": "Leaky cache combined with confirmed poisoning enables attacker-injected content served to other users",
        "severity": "critical",
        "required_observations": [
            {"check_name": "cag_cache_probe"},
            {"check_name": "cag_cache_poisoning"},
        ],
        "exploitation_steps": [
            "Probe cache behavior to identify cacheable query patterns",
            "Craft responses containing malicious instructions or misinformation",
            "Submit queries that cause the poisoned response to be cached",
            "Verify poisoned content is served to subsequent users making similar queries",
            "Estimate blast radius based on cache key granularity and TTL",
        ],
    },
    {
        "name": "cag_warming_injection_persistence",
        "title": "CAG Cache Warming with Persistent Injection",
        "description": "Cache warming accepts arbitrary content and injected prompt responses persist across users",
        "severity": "high",
        "required_observations": [
            {"check_name": "cag_cache_warming"},
            {"check_name": "cag_injection_persistence"},
        ],
        "exploitation_steps": [
            "Access cache warming endpoints to pre-populate cache entries",
            "Inject prompt injection payloads via the warming interface",
            "Verify injected content is stored in the cache layer",
            "Confirm that warmed malicious entries are served to other users",
            "Establish persistence by re-warming entries before TTL expiry",
        ],
    },
    {
        "name": "cag_timing_surveillance",
        "title": "CAG Timing Side-Channel Query Surveillance",
        "description": "Timing differences combined with known similarity threshold reveal what other users are querying",
        "severity": "medium",
        "required_observations": [
            {"check_name": "cag_side_channel"},
            {"check_name": "cag_semantic_threshold"},
        ],
        "exploitation_steps": [
            "Measure response timing differences for cache hits vs misses",
            "Map the semantic similarity threshold for cache key matching",
            "Generate candidate queries across topics of interest",
            "Identify which topics produce cache hits (indicating prior user queries)",
            "Build a profile of user query patterns from timing analysis",
        ],
    },
    {
        "name": "cag_stale_privilege_persistence",
        "title": "CAG Stale Context Privilege Persistence",
        "description": "Cached context outlives authorization changes; mapped TTL reveals the exploitation window",
        "severity": "high",
        "required_observations": [
            {"check_name": "cag_stale_context"},
            {"check_name": "cag_ttl_mapping"},
        ],
        "exploitation_steps": [
            "Map cache TTL values and expiry behavior for different entry types",
            "Identify contexts where authorization should have been revoked",
            "Verify that cached context still grants access after permission changes",
            "Calculate the exploitation window based on TTL duration",
            "Demonstrate access to resources using stale cached authorization",
        ],
    },
    # ─── MCP Chains ──────────────────────────────────────────────
    {
        "name": "mcp_unauthenticated_tool_execution",
        "title": "MCP Unauthenticated Tool Execution",
        "description": "Enumerated tools with no authentication enables direct unauthenticated tool invocation",
        "severity": "critical",
        "required_observations": [
            {"check_name": "mcp_tool_enumeration"},
            {"check_name": "mcp_auth_check"},
            {"check_name": "mcp_tool_invocation"},
        ],
        "exploitation_steps": [
            "Enumerate all tools exposed by the MCP server",
            "Confirm authentication is not enforced on tool invocation endpoints",
            "Invoke high-risk tools directly without credentials",
            "Test for data access, file operations, or code execution capabilities",
            "Assess the full scope of unauthenticated tool capabilities",
        ],
    },
    {
        "name": "mcp_shadow_tool_exploitation",
        "title": "MCP Shadow Tool Prompt Injection",
        "description": "Hidden shadow tools that override legitimate ones are exploitable via prompt injection in tool results",
        "severity": "high",
        "required_observations": [
            {"check_name": "mcp_shadow_tool_detection"},
            {"check_name": "mcp_prompt_injection"},
        ],
        "exploitation_steps": [
            "Identify shadow tools that override or masquerade as legitimate tools",
            "Analyze how shadow tool descriptions influence LLM tool selection",
            "Craft prompt injection payloads that flow through MCP tool results",
            "Verify the LLM executes attacker-controlled instructions from tool output",
            "Chain shadow tool redirection with prompt injection for persistent control",
        ],
    },
    {
        "name": "mcp_dangerous_tool_chain",
        "title": "MCP Dangerous Tool Chain Confirmed",
        "description": "Dangerous capability combinations identified and confirmed invocable",
        "severity": "high",
        "required_observations": [
            {"check_name": "mcp_tool_chain_analysis"},
            {"check_name": "mcp_tool_invocation"},
        ],
        "exploitation_steps": [
            "Review dangerous tool combinations identified by chain analysis",
            "Confirm tools in the dangerous chain are individually invocable",
            "Execute the tool chain sequentially to demonstrate combined impact",
            "Test for data exfiltration, privilege escalation, or code execution paths",
            "Document the end-to-end attack path through chained tool invocations",
        ],
    },
    {
        "name": "mcp_schema_informed_attack",
        "title": "MCP Schema-Informed Tool Exploitation",
        "description": "Leaked schemas reveal parameter structure, enabling precisely crafted tool invocations",
        "severity": "medium",
        "required_observations": [
            {"check_name": "mcp_schema_leakage"},
            {"check_name": "mcp_tool_invocation"},
        ],
        "exploitation_steps": [
            "Extract detailed parameter schemas from MCP tool definitions",
            "Identify sensitive or undocumented parameters in leaked schemas",
            "Craft tool invocations using discovered parameter structures",
            "Test for hidden admin parameters or debug flags in tool calls",
            "Use schema knowledge to bypass input validation or access controls",
        ],
    },
    {
        "name": "mcp_resource_traversal_chain",
        "title": "MCP Resource Traversal with Template Injection",
        "description": "Path traversal on resources combined with template injection enables server-side file access or SSRF",
        "severity": "high",
        "required_observations": [
            {"check_name": "mcp_resource_traversal"},
            {"check_name": "mcp_template_injection"},
        ],
        "exploitation_steps": [
            "Identify MCP resource URIs vulnerable to path traversal",
            "Test template parameters for injection of arbitrary values",
            "Combine traversal with template injection to access internal files",
            "Attempt SSRF by injecting internal URLs into resource templates",
            "Escalate to configuration file access or internal service discovery",
        ],
    },
    # ─── Agent Chains ────────────────────────────────────────────
    {
        "name": "agent_hijacking",
        "title": "Agent Goal Hijacking",
        "description": "Discovered agent endpoints are vulnerable to goal override, redirecting autonomous agent behavior",
        "severity": "high",
        "required_observations": [
            {"check_name": "agent_discovery"},
            {"check_name": "agent_goal_injection"},
        ],
        "exploitation_steps": [
            "Identify agent orchestration endpoints and interaction model",
            "Craft goal injection payloads that override the agent's objective",
            "Submit hijacked goals through the agent's input interface",
            "Verify the agent pursues the attacker-specified goal autonomously",
            "Escalate by directing the agent to exfiltrate data or modify systems",
        ],
    },
    {
        "name": "agent_persistent_memory_compromise",
        "title": "Agent Persistent Memory Compromise",
        "description": "Extracted agent memory reveals context for poisoning, enabling persistent attacker instructions",
        "severity": "critical",
        "required_observations": [
            {"check_name": "agent_memory_extraction"},
            {"check_name": "agent_memory_poisoning"},
        ],
        "exploitation_steps": [
            "Extract existing agent memory to understand stored context and format",
            "Analyze memory structure to identify injection points",
            "Craft poisoned memory entries containing persistent attacker instructions",
            "Inject poisoned entries into agent memory via discovered mechanism",
            "Verify poisoned instructions persist across sessions and influence all future interactions",
        ],
    },
    {
        "name": "agent_privilege_escalation_via_tools",
        "title": "Agent Privilege Escalation via Tool Abuse",
        "description": "Conversational tool invocation combined with privilege claims enables escalated operations",
        "severity": "high",
        "required_observations": [
            {"check_name": "agent_tool_abuse"},
            {"check_name": "agent_privilege_escalation"},
        ],
        "exploitation_steps": [
            "Identify tools accessible through conversational manipulation",
            "Test privilege escalation by claiming elevated roles in conversation",
            "Invoke restricted tools using the escalated privilege context",
            "Verify the agent executes privileged operations on behalf of the attacker",
            "Map the full scope of operations accessible through combined escalation",
        ],
    },
    {
        "name": "multi_agent_lateral_injection",
        "title": "Multi-Agent Lateral Injection Chain",
        "description": "Multi-agent topology discovered; output from one agent poisons another through trusted channels",
        "severity": "critical",
        "required_observations": [
            {"check_name": "agent_multi_agent_detection"},
            {"check_name": "agent_cross_injection"},
            {"check_name": "agent_trust_chain"},
        ],
        "exploitation_steps": [
            "Map multi-agent system topology and inter-agent communication paths",
            "Identify trust relationships between agents in the hierarchy",
            "Inject malicious output into a lower-privilege agent",
            "Verify poisoned output propagates to higher-privilege agents via trust chain",
            "Achieve escalated actions through the trusted agent that processes poisoned input",
        ],
    },
    {
        "name": "agent_guardrail_bypass",
        "title": "Agent Guardrail Bypass via Context Overflow",
        "description": "Triggerable loops combined with context overflow pushes safety instructions out of the context window",
        "severity": "high",
        "required_observations": [
            {"check_name": "agent_loop_detection"},
            {"check_name": "agent_context_overflow"},
        ],
        "exploitation_steps": [
            "Identify agent loop triggers that generate excessive context",
            "Craft inputs that force the agent into repetitive processing loops",
            "Monitor context window consumption as loop iterations accumulate",
            "Verify that safety guardrails are evicted from context after overflow",
            "Submit restricted requests after guardrail context has been pushed out",
        ],
    },
    {
        "name": "agent_framework_exploitation",
        "title": "Agent Framework Targeted Exploitation",
        "description": "Specific framework version identified with confirmed exploitable known vulnerabilities",
        "severity": "high",
        "required_observations": [
            {"check_name": "agent_framework_version"},
            {"check_name": "agent_framework_exploits"},
        ],
        "exploitation_steps": [
            "Identify the exact agent framework and version from fingerprinting",
            "Cross-reference version against known CVEs and security advisories",
            "Confirm exploitability of discovered vulnerabilities on the target",
            "Develop or adapt exploits for the identified framework version",
            "Execute framework-level attacks to bypass agent security controls",
        ],
    },
    # ─── Cross-Category Chains ───────────────────────────────────
    {
        "name": "full_llm_compromise_pipeline",
        "title": "Full LLM Compromise Pipeline",
        "description": "System prompt extracted and tools discovered enables fully informed attacks against the LLM service",
        "severity": "critical",
        "required_observations": [
            {"check_name": "llm_endpoint_discovery"},
            {"check_name": "prompt_leakage"},
            {"check_name": "tool_discovery"},
        ],
        "exploitation_steps": [
            "Access discovered LLM chat/completion endpoints",
            "Extract the system prompt to understand constraints and instructions",
            "Enumerate available tools and their capabilities",
            "Craft attacks informed by system prompt boundaries and tool access",
            "Chain prompt manipulation with tool invocation for maximum impact",
        ],
    },
    {
        "name": "unauthenticated_rag_exfiltration",
        "title": "Unauthenticated RAG Data Exfiltration",
        "description": "No authentication on AI endpoints combined with RAG pipeline enables unauthenticated document theft",
        "severity": "critical",
        "required_observations": [
            {"check_name": "auth_bypass"},
            {"check_name": "rag_discovery"},
            {"check_name": "rag_document_exfiltration"},
        ],
        "exploitation_steps": [
            "Confirm AI endpoints are accessible without authentication",
            "Identify RAG pipeline endpoints behind the unauthenticated service",
            "Submit crafted queries to extract sensitive document content",
            "Iterate extraction across all accessible knowledge base topics",
            "Exfiltrate complete document corpus without any credentials",
        ],
    },
    {
        "name": "content_filter_bypass_pipeline",
        "title": "Content Filter Bypass Pipeline",
        "description": "Filters characterized, jailbreaks confirmed, and streaming bypasses content filtering",
        "severity": "high",
        "required_observations": [
            {"check_name": "content_filter_check"},
            {"check_name": "jailbreak_testing"},
            {"check_name": "streaming_analysis"},
        ],
        "exploitation_steps": [
            "Map content filter rules and blocked categories from detection results",
            "Apply confirmed jailbreak techniques to bypass filter logic",
            "Test if streaming mode skips or weakens content filtering",
            "Combine jailbreak prompts with streaming to maximize bypass success",
            "Generate restricted content through the combined bypass chain",
        ],
    },
    {
        "name": "cross_origin_ai_abuse",
        "title": "Cross-Origin AI Service Abuse",
        "description": "Permissive CORS on AI endpoints allows any website to make cross-origin requests to the LLM",
        "severity": "high",
        "required_observations": [
            {"check_name": "cors_check"},
            {"check_name": "llm_endpoint_discovery"},
        ],
        "exploitation_steps": [
            "Confirm permissive CORS configuration on AI service endpoints",
            "Craft a malicious webpage that makes cross-origin requests to the LLM",
            "Test if authenticated user sessions are forwarded with CORS requests",
            "Demonstrate cross-origin prompt injection or data exfiltration",
            "Assess impact on users who visit attacker-controlled pages while authenticated",
        ],
    },
    {
        "name": "ssrf_via_agent_callback",
        "title": "SSRF via Agent Callback Injection",
        "description": "URL-accepting parameters combined with agent callback injection enables server-side request forgery",
        "severity": "high",
        "required_observations": [
            {"check_name": "ssrf_indicator"},
            {"check_name": "agent_callback_injection"},
        ],
        "exploitation_steps": [
            "Identify parameters that accept URLs from SSRF indicator observations",
            "Craft callback injection payloads targeting internal network resources",
            "Submit payloads through the agent's callback/webhook interface",
            "Verify the agent makes server-side requests to attacker-specified URLs",
            "Enumerate internal services and extract data through SSRF responses",
        ],
    },
    {
        "name": "infrastructure_informed_ai_attack",
        "title": "Infrastructure-Informed AI Attack",
        "description": "Leaked config files reveal API keys and settings that inform targeted attacks against the identified AI framework",
        "severity": "medium",
        "required_observations": [
            {"check_name": "config_exposure"},
            {"check_name": "ai_framework_fingerprint"},
        ],
        "exploitation_steps": [
            "Extract API keys, secrets, and configuration from exposed config files",
            "Identify the AI framework and version from fingerprinting results",
            "Use discovered API keys to access backend AI services directly",
            "Apply framework-specific attack techniques informed by configuration",
            "Test for elevated access using exposed credentials and known framework weaknesses",
        ],
    },
    {
        "name": "financial_denial_of_service",
        "title": "Financial Denial of Service via Token Exhaustion",
        "description": "Rate limit bypass combined with expensive completions enables uncapped cost generation",
        "severity": "high",
        "required_observations": [
            {"check_name": "rate_limit_check"},
            {"check_name": "token_cost_exhaustion"},
        ],
        "exploitation_steps": [
            "Identify rate limiting mechanisms and any discovered bypass techniques",
            "Confirm that expensive completions can be triggered without token limits",
            "Bypass rate limits to submit high-volume expensive completion requests",
            "Estimate cost impact based on token pricing and achievable request volume",
            "Demonstrate sustained cost generation through combined bypass and exhaustion",
        ],
    },
    {
        "name": "openapi_mass_assignment",
        "title": "API Schema-Informed Mass Assignment",
        "description": "Full API schema reveals data models; mass assignment confirms writable fields that should be protected",
        "severity": "high",
        "required_observations": [
            {"check_name": "openapi_discovery"},
            {"check_name": "mass_assignment"},
        ],
        "exploitation_steps": [
            "Extract complete data models from exposed OpenAPI/Swagger documentation",
            "Identify privileged fields (roles, permissions, pricing) from schema definitions",
            "Confirm mass assignment vulnerabilities allow writing to protected fields",
            "Craft requests that set privileged field values using discovered schemas",
            "Escalate access by modifying role or permission fields via mass assignment",
        ],
    },
    {
        "name": "credential_compromise_chain",
        "title": "Credential Compromise via Default Credentials",
        "description": "Authentication mechanism identified and default credentials confirmed working",
        "severity": "high",
        "required_observations": [
            {"check_name": "auth_detection"},
            {"check_name": "default_creds"},
        ],
        "exploitation_steps": [
            "Identify the authentication mechanism in use (Basic, Bearer, OAuth, form)",
            "Confirm default credentials provide valid access to the application",
            "Enumerate accessible functionality under the default account",
            "Check if default account has administrative or elevated privileges",
            "Use authenticated access to reach protected functionality and data",
        ],
    },
    {
        "name": "mcp_agent_hybrid_attack",
        "title": "MCP-to-Agent Injection Pipeline",
        "description": "MCP tools feed into agent context; prompt injection via tool results hijacks agent behavior",
        "severity": "critical",
        "required_observations": [
            {"check_name": "mcp_discovery"},
            {"check_name": "agent_discovery"},
            {"check_name": "mcp_prompt_injection"},
        ],
        "exploitation_steps": [
            "Identify MCP server endpoints and connected agent orchestration",
            "Map how MCP tool results flow into the agent's context window",
            "Craft prompt injection payloads within MCP tool result content",
            "Verify injected instructions from tool results influence agent behavior",
            "Chain MCP tool injection with agent goal manipulation for persistent control",
        ],
    },
]


# ─── Chain Analysis ───────────────────────────────────────────


async def _update_chain_status_in_db(scan_id: str | None, **fields) -> None:
    """Persist chain status fields to the Scan DB record (best-effort)."""
    if not scan_id:
        return
    try:
        from app.db.repositories import ScanRepository

        await ScanRepository().update_scan_status(scan_id, **fields)
    except Exception:
        logger.warning("Failed to persist chain status to DB", exc_info=True)


async def _load_observations_for_chains(scan_id: str | None) -> list[dict]:
    """Load observations from the database for chain analysis."""
    if not scan_id:
        return []
    try:
        from app.db.repositories import ObservationRepository

        return await ObservationRepository().get_observations(scan_id)
    except Exception:
        logger.warning("Failed to load observations from DB for chain analysis", exc_info=True)
        return []


async def _persist_chains(scan_id: str | None, chains: list[dict]) -> None:
    """Persist chains to the database (best-effort)."""
    if not scan_id or not chains:
        return
    try:
        from app.db.repositories import ChainRepository

        await ChainRepository().bulk_create(scan_id, chains)
    except Exception:
        logger.warning("Failed to persist chains to DB", exc_info=True)


async def run_chain_analysis(state: "AppState", llm_only: bool = False):
    """
    Run two-pass chain analysis: rule-based then LLM.

    Reads observations from DB, accumulates chains locally, persists
    chains and status to DB. Updates state.chain_status as a concurrency guard.

    Args:
        llm_only: If True, skip rule-based pass and re-run LLM only
                  (used by the /api/chains/retry endpoint).
    """
    scan_id = getattr(state, "_last_scan_id", None)
    chains: list[dict] = []
    chain_error: str | None = None
    chain_llm_analysis: dict | None = None

    try:
        logger.info("Starting chain analysis...")

        # Load observations from DB
        observations = await _load_observations_for_chains(scan_id)

        if not llm_only:
            # Pass 1: Rule-based pattern matching
            rule_chains = detect_rule_based_chains(observations)
            logger.info(f"Rule-based analysis found {len(rule_chains)} chains")
            chains.extend(rule_chains)
        else:
            # For retry, load existing rule-based chains from DB
            try:
                from app.db.repositories import ChainRepository

                existing = await ChainRepository().get_chains(scan_id) if scan_id else []
                rule_chains = [c for c in existing if c.get("source") == "rule-based"]
                chains.extend(rule_chains)
            except Exception:
                logger.warning("Failed to load existing chains for retry", exc_info=True)
                rule_chains = []

        # Pass 2: LLM-based analysis
        result = await detect_llm_chains(state, observations, len(chains))
        chain_llm_analysis = result.to_analysis_dict()

        logger.info(
            f"LLM analysis returned {len(result.chains)} chains (status: {result.llm_status})"
        )

        for chain in result.chains:
            # Check if this overlaps with a rule-based chain
            overlapping = find_overlapping_chain(chain, chains)
            if overlapping:
                overlapping["source"] = "both"
                overlapping["llm_reasoning"] = chain.get("llm_reasoning")
                if chain.get("exploitation_steps"):
                    overlapping["exploitation_steps"].extend(chain["exploitation_steps"])
            else:
                chains.append(chain)

        # Set top-level status based on LLM outcome
        if result.llm_status == "success":
            state.chain_status = "complete"
        elif result.llm_status == "not_configured":
            state.chain_status = "complete"  # rule-only is fine
        elif chains:
            state.chain_status = "partial"  # have rule chains but LLM failed
        else:
            state.chain_status = "error"
            chain_error = (
                result.llm_response.error if result.llm_response else "LLM analysis failed"
            )

        logger.info(f"Chain analysis complete. {len(chains)} total chains.")

        # Guided Mode: proactive chain_identified message
        if chains:
            await _emit_chain_identified_proactive(state, len(chains))

        # Persist chains and status to DB
        await _persist_chains(scan_id, chains)
        await _update_chain_status_in_db(
            scan_id,
            chain_status=state.chain_status,
            chain_error=chain_error,
            chain_llm_analysis=chain_llm_analysis,
        )

    except Exception as e:
        logger.exception(f"Chain analysis error: {e}")
        state.chain_status = "error"
        await _update_chain_status_in_db(scan_id, chain_status="error", chain_error=str(e))


def detect_rule_based_chains(observations: list[dict]) -> list[dict]:
    """Detect chains using predefined patterns."""
    chains = []
    chain_counter = 0

    for pattern in CHAIN_PATTERNS:
        matching_observations = match_pattern(pattern, observations)

        if matching_observations:
            chain_counter += 1
            chains.append(
                {
                    "id": f"C-{chain_counter:03d}",
                    "title": pattern["title"],
                    "description": pattern["description"],
                    "severity": pattern["severity"],
                    "observation_ids": [f["id"] for f in matching_observations],
                    "exploitation_steps": pattern["exploitation_steps"],
                    "source": "rule-based",
                    "pattern_name": pattern["name"],
                    "llm_reasoning": None,
                }
            )

    return chains


def match_pattern(pattern: dict, observations: list[dict]) -> list[dict]:
    """Check if observations match a pattern's requirements."""
    matched_observations = []

    for req in pattern["required_observations"]:
        matching = []

        for observation in observations:
            # Check check_name match
            if req.get("check_name") and observation.get("check_name") != req["check_name"]:
                continue

            # Check title_contains
            if req.get("title_contains"):
                if req["title_contains"].lower() not in observation.get("title", "").lower():
                    continue

            # Check title_contains_2 (secondary filter)
            if req.get("title_contains_2"):
                if req["title_contains_2"].lower() not in observation.get("title", "").lower():
                    continue

            # Check evidence_contains
            if req.get("evidence_contains"):
                if req["evidence_contains"].lower() not in observation.get("evidence", "").lower():
                    continue

            # Check count_gte (minimum count of observations)
            if req.get("count_gte"):
                count = len([f for f in observations if f.get("check_name") == req["check_name"]])
                if count < req["count_gte"]:
                    continue

            matching.append(observation)

        if not matching:
            return []  # Pattern not fully matched

        matched_observations.extend(matching)

    # Deduplicate
    seen_ids = set()
    unique_observations = []
    for f in matched_observations:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            unique_observations.append(f)

    return unique_observations


def _build_chain_prompt(state: "AppState", observations_summary: list[dict]) -> str:
    """Build the chain analysis prompt."""
    return f"""You are a penetration testing expert analyzing reconnaissance observations for attack chain opportunities.

Target: {state.target}

Observations discovered:
{format_observations_for_llm(observations_summary)}

Analyze these observations and identify potential ATTACK CHAINS - combinations of observations that together enable a more severe attack than any single observation alone.

For each chain you identify, provide:
1. A descriptive title
2. Which observation IDs are involved
3. The combined severity (low/medium/high/critical)
4. Brief step-by-step exploitation instructions (keep each step to one short sentence)
5. A concise reasoning for why these observations combine into a chain (2-3 sentences max)

Be concise. Limit to the top 5 most impactful chains.

IMPORTANT: Respond with ONLY valid JSON, no other text. Use this exact format:
{{
    "chains": [
        {{
            "title": "Chain title",
            "observation_ids": ["O-001", "O-002"],
            "severity": "high",
            "exploitation_steps": ["Step 1", "Step 2"],
            "reasoning": "Why these observations combine..."
        }}
    ]
}}

Only include chains that represent genuine combined attack opportunities. If no additional chains beyond obvious single-observation attacks exist, return {{"chains": []}}."""


async def detect_llm_chains(
    state: "AppState",
    observations: list[dict],
    existing_chain_count: int = 0,
) -> ChainAnalysisResult:
    """
    Use LLM to discover additional attack chains.

    Returns a ChainAnalysisResult with chains, status, and error context.
    Includes auto-retry for retryable errors and content filter mitigation.
    """
    llm_client = get_llm_client()
    if not llm_client.is_available():
        logger.info("LLM not configured - skipping AI chain analysis")
        resp = await llm_client.chat("")  # gets NOT_CONFIGURED response
        return ChainAnalysisResult(
            llm_status="not_configured",
            llm_response=resp,
            attempts=0,
        )

    # Prepare observations summary
    observations_summary = []
    for f in observations:
        observations_summary.append(
            {
                "id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
                "check": f.get("check_name"),
                "target": f.get("target_url"),
                "evidence": f.get("evidence", "")[:200],
            }
        )

    prompt = _build_chain_prompt(state, observations_summary)
    sanitized_prompt_used = False
    attempts = 0
    last_response: LLMResponse | None = None

    # --- Attempt loop (original prompt, then retries, then sanitized) ---
    for attempt in range(1, LLM_MAX_RETRIES + 2):  # up to 3 attempts
        attempts = attempt

        if attempt > 1:
            delay = LLM_RETRY_DELAYS[min(attempt - 2, len(LLM_RETRY_DELAYS) - 1)]
            logger.info(
                f"LLM chain analysis retry {attempt}/{LLM_MAX_RETRIES + 1} after {delay}s backoff"
            )
            # Retry status is transient — logged only
            logger.debug(f"LLM chain analysis: retrying (attempt {attempt})")
            await asyncio.sleep(delay)

        response = await llm_client.chat(prompt, max_tokens=4096)
        last_response = response

        if response.success:
            # Try to parse the response
            llm_chains = parse_llm_response(response.content)
            if llm_chains is None:
                # JSON parse failure — not retryable in the same way
                response.error_type = LLMErrorType.PARSE_ERROR
                response.error = "LLM returned non-JSON response"
                response.success = False
                response.retryable = False
                last_response = response
                break  # parse errors won't improve with retry

            # Success — build chain objects
            chains = _build_chain_objects(llm_chains, existing_chain_count)
            logger.info(
                f"LLM chain analysis found {len(chains)} chains "
                f"(provider: {llm_client.provider_name}, "
                f"attempts: {attempts})"
            )
            return ChainAnalysisResult(
                chains=chains,
                llm_status="success",
                llm_response=response,
                attempts=attempts,
                sanitized_prompt_used=sanitized_prompt_used,
            )

        # --- Failure handling ---
        logger.warning(
            f"LLM chain analysis attempt {attempt} failed: "
            f"{response.error_type.value} — {response.error}"
        )

        # Content filter → try sanitized prompt once (don't count as retry)
        if response.error_type == LLMErrorType.CONTENT_FILTER and not sanitized_prompt_used:
            logger.info("Content filter rejection — retrying with sanitized prompt")
            prompt = _sanitize_prompt(prompt)
            sanitized_prompt_used = True
            continue  # don't consume a retry slot

        # Retryable error → continue loop
        if response.retryable and attempt <= LLM_MAX_RETRIES:
            continue

        # Non-retryable or exhausted retries — stop
        break

    # All attempts failed
    logger.warning(
        f"LLM chain analysis failed after {attempts} attempt(s): "
        f"{last_response.error_type.value if last_response else 'unknown'}"
    )
    return ChainAnalysisResult(
        llm_status="failed",
        llm_response=last_response,
        attempts=attempts,
        sanitized_prompt_used=sanitized_prompt_used,
    )


def _build_chain_objects(llm_chains: list[dict], existing_chain_count: int = 0) -> list[dict]:
    """Convert parsed LLM chain dicts into our internal chain format."""
    chains = []
    chain_counter = existing_chain_count + 1
    for lc in llm_chains:
        chains.append(
            {
                "id": f"C-{chain_counter:03d}",
                "title": lc.get("title", "LLM-discovered chain"),
                "description": lc.get("reasoning", ""),
                "severity": lc.get("severity", "medium"),
                "observation_ids": lc.get("observation_ids", []),
                "exploitation_steps": lc.get("exploitation_steps", []),
                "source": "llm",
                "pattern_name": None,
                "llm_reasoning": lc.get("reasoning"),
            }
        )
        chain_counter += 1
    return chains


def format_observations_for_llm(observations: list[dict]) -> str:
    """Format observations for LLM prompt."""
    lines = []
    for f in observations:
        lines.append(f"- {f['id']}: [{f['severity'].upper()}] {f['title']}")
        lines.append(f"  Check: {f['check']}, Target: {f['target']}")
        if f["evidence"]:
            lines.append(f"  Evidence: {f['evidence'][:100]}...")
        lines.append("")
    return "\n".join(lines)


def parse_llm_response(content: str) -> list[dict] | None:
    """
    Parse LLM JSON response, handling potential formatting issues.

    Returns list of chain dicts on success, or None if parsing fails entirely.
    """
    if not content or not content.strip():
        logger.warning("Empty LLM response")
        return None

    # Try direct parse
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data.get("chains", [])
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    fence_match = re.search(r"```(?:json)?\s*\n(.*?)```", content, re.DOTALL)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1))
            if isinstance(data, dict):
                return data.get("chains", [])
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

    # Try to find JSON object in response
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(content[start:end])
            if isinstance(data, dict):
                return data.get("chains", [])
    except json.JSONDecodeError:
        pass

    # Try to find JSON array in response
    try:
        start = content.find("[")
        end = content.rfind("]") + 1
        if start >= 0 and end > start:
            data = json.loads(content[start:end])
            if isinstance(data, list):
                return data
    except json.JSONDecodeError:
        pass

    logger.warning("Could not parse LLM response as JSON: %s", content[:200])
    return None


def find_overlapping_chain(new_chain: dict, existing_chains: list[dict]) -> dict | None:
    """Find if a chain overlaps significantly with existing chains."""
    new_ids = set(new_chain.get("observation_ids", []))

    for existing in existing_chains:
        existing_ids = set(existing.get("observation_ids", []))

        # Check for >50% overlap
        overlap = len(new_ids & existing_ids)
        if overlap > 0 and overlap >= len(new_ids) * 0.5:
            return existing

    return None


# ─── Guided Mode: proactive chain_identified ──────────────────


async def _emit_chain_identified_proactive(state, chain_count: int) -> None:
    """Push a proactive chain_identified message if Guided Mode is active."""
    try:
        from app.engine.chat import sse_manager
        from app.engine.guided import maybe_emit_proactive
        from app.models import ComponentType

        text = f"New attack chain{'s' if chain_count > 1 else ''} detected linking observations."
        if chain_count > 1:
            text = f"{chain_count} attack chains detected linking observations."

        await maybe_emit_proactive(
            sse_manager=sse_manager,
            session_id=state.session_id,
            agent=ComponentType.CHAINSMITH,
            trigger="chain_identified",
            text=text,
            actions=[
                {
                    "label": "Show chains",
                    "injected_message": "Explain the attack chains from this scan",
                }
            ],
        )
    except Exception:
        logger.debug("Guided mode proactive chain_identified failed (non-fatal)", exc_info=True)
