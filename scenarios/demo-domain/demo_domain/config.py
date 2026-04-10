"""
Demo-Domain Configuration and Findings System

Manages randomized findings, certain findings, and session state.
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

VERBOSE_ERRORS = os.getenv("DEMO_DOMAIN_VERBOSE_ERRORS", "true").lower() == "true"

LLM_PROFILE = os.getenv("LLM_PROFILE", "openai")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Session state file for coordinating findings across containers
SESSION_STATE_PATH = Path(os.getenv("DEMO_DOMAIN_SESSION_STATE", "/data/demo_session.json"))


# ─── Session Models ────────────────────────────────────────────


class SessionState(BaseModel):
    """Tracks which findings are active for this session."""

    session_id: str
    active_findings: list[str]
    active_hallucinations: list[str]
    created_at: str
    # Range mode fields (optional)
    range_mode: bool = False
    active_services: list[str] = []
    selected_chains: list[dict] = []


# ─── Standard Lab Findings ─────────────────────────────────────

# Certain findings - always present in standard mode
CERTAIN_FINDINGS = [
    "version_disclosure",
    "missing_security_headers",
    "robots_sensitive_paths",
    "verbose_errors",
    "cors_wildcard",
]

# Random findings pool - 5-10 selected per session in standard mode
RANDOM_FINDINGS_POOL = [
    "unauthed_docs",
    "tool_schema_exposed",
    "no_rate_limit",
    "mcp_endpoint_exposed",
    "dynamic_tool_loading",
    "resource_list_exposed",
    "agent_config_leak",
    "no_session_isolation",
    "memory_endpoint_exposed",
    "cookie_security_missing",
    "config_exposure",
    "debug_endpoints",
    "directory_listing",
    "auth_detection_basic",
    "jailbreak_susceptible",
    "multiturn_injectable",
    "guardrail_inconsistent",
    "history_leak_detected",
    "tls_weak",
    "http_method_extra",
    "rag_endpoint_exposed",
    "rag_indirect_injection",
    "rag_document_exfil",
    "rag_collection_enum",
    "rag_source_attribution",
    "rag_corpus_poisoning",
    "cache_endpoint_exposed",
    "cache_cross_user_leak",
    "cache_poisoning",
    "cache_stale_context",
    "cache_probe_timing",
    "agent_goal_injection",
    "agent_memory_extraction",
    "agent_tool_abuse",
    "agent_privilege_escalation",
]


# ─── Session Creation ──────────────────────────────────────────


def create_standard_session() -> SessionState:
    """Create a standard lab mode session."""
    session_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    # Select 5-10 random findings from pool
    num_random = random.randint(5, 10)
    active_random = random.sample(RANDOM_FINDINGS_POOL, k=num_random)

    # Select random hallucinations
    num_hallucinations = random.randint(2, 5)
    hallucination_ids = [f"H{i:02d}" for i in range(1, 21)]
    active_hallucinations = random.sample(hallucination_ids, k=num_hallucinations)

    session = SessionState(
        session_id=session_id,
        active_findings=CERTAIN_FINDINGS + active_random,
        active_hallucinations=active_hallucinations,
        created_at=datetime.utcnow().isoformat(),
        range_mode=False,
        active_services=["www", "chat", "api", "agent", "rag", "cache", "docs"],
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


def is_finding_active(finding_id: str) -> bool:
    """Check if a specific finding is active in current session."""
    session = get_or_create_session()
    return finding_id in session.active_findings


def get_active_findings() -> list[str]:
    """Get list of all active findings for current session."""
    session = get_or_create_session()
    return session.active_findings
