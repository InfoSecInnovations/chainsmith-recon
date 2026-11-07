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

# Session state file for coordinating findings across containers. Compose sets
# SESSION_STATE_PATH (the mounted ./data/session.json that range/start-range.sh
# writes); this module used to read only DEMO_DOMAIN_SESSION_STATE, so every
# container fell back to its own unshared /data/demo_session.json and rolled
# its own session.
SESSION_STATE_PATH = Path(
    os.getenv("DEMO_DOMAIN_SESSION_STATE")
    or os.getenv("SESSION_STATE_PATH")
    or "/data/demo_session.json"
)


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

# Every id below is a gate a demo-domain service checks with
# `is_observation_active(...)` (tests/scanning/test_range_observation_ids.py).
# Missing security headers and wildcard CORS are planted unconditionally, so
# they are not listed.

# Certain observations - always present in standard mode
CERTAIN_OBSERVATIONS = [
    "version_disclosure",
    "robots_sensitive_paths",
    "verbose_errors",
]

# Random observations pool - 5-10 selected per session in standard mode
RANDOM_OBSERVATIONS_POOL = [
    "unauthed_docs",
    "unauthed_user_endpoint",
    "api_key_in_error",
    "tool_schema_exposed",
    "mcp_tools_exposed",
    "mcp_resources_exposed",
    "mcp_backend_leakage",
    "cross_session_memory",
    "agent_tool_abuse",
    "cookie_security_missing",
    "config_exposure",
    "debug_endpoints",
    "directory_listing",
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
]

RANDOM_COUNT_MIN = 5
RANDOM_COUNT_MAX = 10


# ─── Session Creation ──────────────────────────────────────────


def resolve_active_observations(
    session_id: str, selected_chains: list[dict] | None = None
) -> list[str]:
    """The observations a session plants, seeded by its id.

    Certain ones, a sample of the pool, then each selected chain's
    `required_findings`. Seeded rather than the global `random`, so every
    container derives the same list from the same session file (the fakobanko
    services do the same, in app/scenario_services/common/config.py).
    """
    rng = random.Random(session_id)
    high = min(RANDOM_COUNT_MAX, len(RANDOM_OBSERVATIONS_POOL))
    sample = rng.sample(RANDOM_OBSERVATIONS_POOL, k=rng.randint(min(RANDOM_COUNT_MIN, high), high))
    chained = [f for chain in selected_chains or [] for f in chain.get("required_findings", [])]
    return list(dict.fromkeys(CERTAIN_OBSERVATIONS + sample + chained))


def resolve_active_hallucinations(session_id: str) -> list[str]:
    rng = random.Random(f"{session_id}:hallucinations")
    hallucination_ids = [f"H{i:02d}" for i in range(1, 21)]
    return rng.sample(hallucination_ids, k=rng.randint(2, 5))


def session_from_file_data(data: dict) -> SessionState:
    """A session from a session file, deriving the lists it leaves out.

    range/start-range.sh writes the session id, chains and services only.
    A file that does carry the lists is taken as written.
    """
    session_id = (
        data.get("session_id")
        or hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]
    )
    chains = data.get("selected_chains") or []
    return SessionState(
        session_id=session_id,
        active_observations=(
            data["active_observations"]
            if "active_observations" in data
            else resolve_active_observations(session_id, chains)
        ),
        active_hallucinations=(
            data["active_hallucinations"]
            if "active_hallucinations" in data
            else resolve_active_hallucinations(session_id)
        ),
        created_at=data.get("created_at") or datetime.utcnow().isoformat(),
        range_mode=bool(data.get("range_mode", bool(chains))),
        active_services=data.get("active_services") or [],
        selected_chains=chains,
    )


def create_standard_session() -> SessionState:
    """Create a standard lab mode session."""
    session_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    session = SessionState(
        session_id=session_id,
        active_observations=resolve_active_observations(session_id),
        active_hallucinations=resolve_active_hallucinations(session_id),
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
            if isinstance(data, dict):
                # Not SessionState(**data): the file start-range writes has no
                # observation lists, which failed validation, and the fallback
                # below then overwrote the file and its selected chains.
                _session_cache = session_from_file_data(data)
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


def is_observation_active(finding_id: str) -> bool:
    """Check if a specific finding is active in current session."""
    session = get_or_create_session()
    return finding_id in session.active_observations


def get_active_observations() -> list[str]:
    """Get list of all active findings for current session."""
    session = get_or_create_session()
    return session.active_observations
