"""
Fakobanko Configuration and Findings System

Manages randomized observations, certain findings, and session state.
Supports both standard lab mode and range mode.
"""

import hashlib
import json
import os
import random
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

# ─── Environment Configuration ─────────────────────────────────

VERBOSE_ERRORS = os.getenv("FAKOBANKO_VERBOSE_ERRORS", "true").lower() == "true"
RANDOMIZE_FINDINGS = os.getenv("FAKOBANKO_RANDOMIZE_FINDINGS", "true").lower() == "true"
RATE_LIMIT_ENABLED = os.getenv("FAKOBANKO_RATE_LIMIT", "false").lower() == "true"
WAF_ENABLED = os.getenv("FAKOBANKO_WAF_ENABLED", "false").lower() == "true"
HONEYPOT_ENABLED = os.getenv("FAKOBANKO_HONEYPOT", "false").lower() == "true"
RANGE_MODE = os.getenv("FAKOBANKO_RANGE_MODE", "false").lower() == "true"

# Session state file for coordinating observations across containers
SESSION_STATE_PATH = Path(os.getenv("FAKOBANKO_SESSION_STATE", "/data/fakobanko_session.json"))

# Range configuration paths
RANGE_CONFIG_DIR = Path(os.getenv("FAKOBANKO_RANGE_CONFIG", "/app/range"))


# ─── Session Models ────────────────────────────────────────────


class SessionState(BaseModel):
    """Tracks which observations are active for this session."""

    session_id: str
    active_observations: list[str]
    active_hallucinations: list[str]
    created_at: str
    # Range mode fields (optional)
    range_mode: bool = False
    active_services: list[str] = []
    selected_chains: list[dict] = []


# ─── Standard Lab Findings ─────────────────────────────────────

# Certain observations - always present in standard mode
CERTAIN_OBSERVATIONS = [
    "header_vllm_version",  # X-Powered-By: vLLM/0.4.1
    "robots_model_admin",  # robots.txt discloses /internal/model-admin
    "chatbot_tool_leak",  # Error messages expose tool names
    "debug_mode_enabled",  # Verbose error stack traces
    "mcp_endpoint_exposed",  # MCP discovery endpoint exposed
    "cors_misconfigured",  # Wildcard CORS headers
    "missing_security_headers",  # No CSP, X-Frame-Options, etc.
    "version_disclosure",  # Server version in headers
]

# Random observations pool - 8-15 selected per session in standard mode
RANDOM_OBSERVATIONS_POOL = [
    # Original findings
    "jwt_shared_secret",
    "embedding_endpoint_exposed",
    "model_card_disclosure",
    "api_version_mismatch",
    "rate_limit_bypass",
    "stack_trace_disclosure",
    "internal_announcement_tool",
    "customer_lookup_tool",
    "fetch_document_tool",
    "session_leak",
    "model_temperature_exposed",
    "cache_timing_leak",
    "tool_schema_disclosure",
    "openapi_exposed",
    "internal_endpoints_documented",
    "auth_schemes_revealed",
    "dynamic_tool_loading",
    "resource_list_exposed",
    "tool_chain_exposed",
    "agent_config_leak",
    "no_session_isolation",
    "memory_endpoint_exposed",
    # Web suite findings
    "vcs_exposure",
    "config_exposure",
    "directory_listing",
    "debug_endpoints",
    "cookie_security_missing",
    "waf_detected",
    "sitemap_exposed",
    "redirect_chain_open",
    "error_page_info_leak",
    "ssrf_indicator_found",
    "favicon_default",
    "http2_enabled",
    "hsts_preload_missing",
    "sri_missing",
    "mass_assignment_writable",
    "default_creds_found",
    "auth_detection_basic",
    "webdav_enabled",
    # AI suite findings
    "jailbreak_susceptible",
    "multiturn_injectable",
    "input_format_exploitable",
    "model_enum_possible",
    "token_cost_unbounded",
    "system_inject_possible",
    "output_format_manipulable",
    "param_inject_possible",
    "streaming_unfiltered",
    "auth_bypass_ai",
    "model_fingerprint_exposed",
    "history_leak_detected",
    "function_abuse_possible",
    "guardrail_inconsistent",
    "training_data_extractable",
    "adversarial_input_accepted",
    "cache_detect_possible",
    # MCP suite findings
    "websocket_transport_open",
    "tool_chain_analysis_dangerous",
    "shadow_tool_detected",
    "schema_leakage_mcp",
    "server_fingerprint_mcp",
    "transport_security_weak",
    "notification_injection_mcp",
    "resource_traversal_mcp",
    "template_injection_mcp",
    "prompt_injection_mcp",
    "sampling_abuse_mcp",
    "protocol_version_old",
    "rate_limit_mcp_missing",
    "undeclared_capabilities_mcp",
    # Agent suite findings
    "multi_agent_detected",
    "memory_extraction_agent",
    "privilege_escalation_agent",
    "loop_detection_agent",
    "callback_injection_agent",
    "streaming_injection_agent",
    "framework_exploits_agent",
    "memory_poisoning_agent",
    "context_overflow_agent",
    "reflection_abuse_agent",
    "state_manipulation_agent",
    "trust_chain_agent",
    "cross_injection_agent",
    # RAG suite findings
    "vector_store_access_open",
    "auth_bypass_rag",
    "collection_enumeration_rag",
    "embedding_fingerprint_rag",
    "document_exfiltration_rag",
    "retrieval_manipulation_rag",
    "source_attribution_rag",
    "cache_poisoning_rag",
    "corpus_poisoning_rag",
    "metadata_injection_rag",
    "chunk_boundary_rag",
    "multimodal_injection_rag",
    "fusion_reranker_rag",
    "cross_collection_rag",
    "adversarial_embedding_rag",
    # CAG suite findings
    "cache_eviction_cag",
    "cache_warming_cag",
    "ttl_mapping_cag",
    "multi_layer_cache_cag",
    "cache_quota_cag",
    "provider_caching_cag",
    "cross_user_leakage_cag",
    "cache_key_reverse_cag",
    "semantic_threshold_cag",
    "side_channel_cag",
    "stale_context_cag",
    "cache_poisoning_cag",
    "injection_persistence_cag",
    "serialization_cag",
    "distributed_cache_cag",
    # Network suite findings
    "tls_weak",
    "ports_extra_open",
    "banner_grab_info",
    "ipv6_found",
    "whois_info",
    "traceroute_info",
    "geoip_info",
    "http_method_extra",
]


# ─── Range Mode Configuration ──────────────────────────────────


def load_range_config(filename: str) -> dict:
    """Load JSON config from range directory."""
    config_path = RANGE_CONFIG_DIR / filename
    if not config_path.exists():
        return {}
    with open(config_path) as f:
        return json.load(f)


def create_range_session() -> SessionState:
    """Create a new range mode session with chain-based randomization."""
    chain_config = load_range_config("chain_packages.json")
    services_config = load_range_config("services.json")

    if not chain_config or not services_config:
        # Fallback to standard mode if range configs missing
        return create_standard_session()

    packages = chain_config.get("chain_packages", [])
    rules = chain_config.get("selection_rules", {})
    random_pool = chain_config.get("random_findings_pool", [])

    # Select chain packages
    min_chains = rules.get("min_chains", 2)
    max_chains = rules.get("max_chains", 4)
    num_to_select = random.randint(min_chains, min(max_chains, len(packages)))
    selected_packages = random.sample(packages, k=num_to_select)

    # Determine required services
    required_services = set()
    for pkg in selected_packages:
        required_services.update(pkg.get("required_services", []))

    # Always include always_on services
    services = services_config.get("services", {})
    always_on = [svc_id for svc_id, svc in services.items() if svc.get("always_on", False)]
    active_services = sorted(set(always_on) | required_services)

    # Collect findings from chains
    required_findings = []
    for pkg in selected_packages:
        required_findings.extend(pkg.get("required_findings", []))
    required_findings = list(set(required_findings))

    # Add extra random findings
    min_extra = rules.get("extra_findings_min", 2)
    max_extra = rules.get("extra_findings_max", 5)
    available = [f for f in random_pool if f not in required_findings]
    num_extra = random.randint(min_extra, min(max_extra, len(available)))
    extra_findings = random.sample(available, k=num_extra) if available else []

    all_findings = required_findings + extra_findings

    # Select hallucinations
    num_hallucinations = random.randint(2, 5)
    hallucination_ids = [f"H{i:02d}" for i in range(1, 21)]
    active_hallucinations = random.sample(hallucination_ids, k=num_hallucinations)

    session = SessionState(
        session_id=hashlib.sha256(os.urandom(32)).hexdigest()[:16],
        active_observations=all_findings,
        active_hallucinations=active_hallucinations,
        created_at=datetime.utcnow().isoformat(),
        range_mode=True,
        active_services=active_services,
        selected_chains=[
            {"id": pkg["id"], "name": pkg["chain_name"], "severity": pkg["severity"]}
            for pkg in selected_packages
        ],
    )

    return session


def create_standard_session() -> SessionState:
    """Create a standard lab mode session."""
    session_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    # Select random findings
    num_random = random.randint(8, 15) if RANDOMIZE_FINDINGS else 0
    active_random = random.sample(RANDOM_OBSERVATIONS_POOL, k=num_random)

    # Select random hallucinations
    num_hallucinations = random.randint(2, 5)
    hallucination_ids = [f"H{i:02d}" for i in range(1, 21)]
    active_hallucinations = random.sample(hallucination_ids, k=num_hallucinations)

    session = SessionState(
        session_id=session_id,
        active_observations=CERTAIN_OBSERVATIONS + active_random,
        active_hallucinations=active_hallucinations,
        created_at=datetime.utcnow().isoformat(),
        range_mode=False,
        active_services=["www", "chat", "api"],
    )

    return session


# ─── Session Management ────────────────────────────────────────

_session_cache: SessionState | None = None


def get_or_create_session() -> SessionState:
    """Get existing session or create new one."""
    global _session_cache

    if _session_cache is not None:
        return _session_cache

    if SESSION_STATE_PATH.exists():
        try:
            data = json.loads(SESSION_STATE_PATH.read_text())
            _session_cache = SessionState(**data)
            return _session_cache
        except (json.JSONDecodeError, ValueError):
            pass

    # Create new session based on mode
    if RANGE_MODE:
        session = create_range_session()
    else:
        session = create_standard_session()

    # Persist
    SESSION_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SESSION_STATE_PATH.write_text(session.model_dump_json(indent=2))

    _session_cache = session
    return session


def reset_session() -> SessionState:
    """Clear session and create new one with fresh randomization."""
    global _session_cache
    _session_cache = None

    if SESSION_STATE_PATH.exists():
        SESSION_STATE_PATH.unlink()

    return get_or_create_session()


def is_observation_active(finding_id: str) -> bool:
    """Check if a specific finding is active in current session."""
    session = get_or_create_session()
    return finding_id in session.active_observations


def get_active_observations() -> list[str]:
    """Get list of all active findings for current session."""
    session = get_or_create_session()
    return session.active_observations


def get_active_hallucinations() -> list[str]:
    """Get list of hallucination IDs active for current session."""
    session = get_or_create_session()
    return session.active_hallucinations


def get_active_services() -> list[str]:
    """Get list of active service names."""
    session = get_or_create_session()
    return session.active_services


def get_selected_chains() -> list[dict]:
    """Get list of selected chain packages (range mode only)."""
    session = get_or_create_session()
    return session.selected_chains


def is_range_mode() -> bool:
    """Check if running in range mode."""
    return RANGE_MODE


def get_session_id() -> str:
    """Get current session ID."""
    session = get_or_create_session()
    return session.session_id
