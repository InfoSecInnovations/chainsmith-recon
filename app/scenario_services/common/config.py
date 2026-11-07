"""
app/scenario_services/common/config.py

Shared configuration system for scenario services.

This module provides:
- Session management with randomized observations
- Observation activation checks (is_observation_active)
- Environment-based configuration
- Scenario-aware configuration loading

Configuration sources (in order of precedence):
1. Environment variables (SCENARIO_*, SERVICE_*)
2. Scenario manifest (scenario.json, path from SCENARIO_CONFIG_PATH)
3. Session state file (persisted randomization, path from SESSION_STATE_PATH)

Usage in services:
    from app.scenario_services.common.config import (
        is_observation_active,
        get_or_create_session,
        get_config,
    )

    if is_observation_active("cors_misconfigured"):
        response.headers["Access-Control-Allow-Origin"] = "*"
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import random
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════


def _env_bool(key: str, default: bool = False) -> bool:
    """Parse boolean from environment variable."""
    val = os.getenv(key, "").lower()
    if val in ("true", "1", "yes", "on"):
        return True
    if val in ("false", "0", "no", "off"):
        return False
    return default


# Core paths
SCENARIO_CONFIG_PATH = Path(os.getenv("SCENARIO_CONFIG_PATH", "/app/scenarios/scenario.json"))
SESSION_STATE_PATH = Path(os.getenv("SESSION_STATE_PATH", "/app/data/session.json"))

# Service identity
SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown")
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "8080"))

# Behavior flags
VERBOSE_ERRORS = _env_bool("VERBOSE_ERRORS", True)
RANDOMIZE_OBSERVATIONS = _env_bool("RANDOMIZE_OBSERVATIONS", True)
RATE_LIMIT_ENABLED = _env_bool("RATE_LIMIT_ENABLED", False)
WAF_ENABLED = _env_bool("WAF_ENABLED", False)
HONEYPOT_ENABLED = _env_bool("HONEYPOT_ENABLED", False)
RANGE_MODE = _env_bool("RANGE_MODE", False)

# Branding (scenario can override)
BRAND_NAME = os.getenv("BRAND_NAME", "")
BRAND_DOMAIN = os.getenv("BRAND_DOMAIN", "")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ObservationsConfig:
    """Configuration for observations randomization."""

    certain: list[str] = field(default_factory=list)
    random_pool: list[str] = field(default_factory=list)
    random_min: int = 2
    random_max: int = 5


@dataclass
class ScenarioConfig:
    """Parsed scenario.json configuration."""

    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    brand_name: str = ""
    brand_domain: str = ""
    observations: ObservationsConfig = field(default_factory=ObservationsConfig)
    # Raw data for extensions
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> ScenarioConfig:
        """Parse scenario.json into ScenarioConfig."""
        observations_raw = data.get("observations", {})

        # Handle both flat list and structured observations config
        if isinstance(observations_raw, list):
            # Legacy: observations is just a list of certain observations
            observations = ObservationsConfig(certain=observations_raw)
        else:
            random_count = observations_raw.get("random_count", {})
            observations = ObservationsConfig(
                certain=observations_raw.get("certain", []),
                random_pool=observations_raw.get("random_pool", []),
                random_min=random_count.get("min", 2),
                random_max=random_count.get("max", 5),
            )

        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            brand_name=data.get("brand_name", data.get("name", "")),
            brand_domain=data.get("brand_domain", ""),
            observations=observations,
            raw=data,
        )


_scenario_config: ScenarioConfig | None = None
_scenario_config_lock = threading.Lock()


def _load_scenario_config() -> ScenarioConfig:
    """Load scenario configuration from SCENARIO_CONFIG_PATH."""
    if not SCENARIO_CONFIG_PATH.exists():
        return ScenarioConfig()

    try:
        with open(SCENARIO_CONFIG_PATH) as f:
            data = json.load(f)
        return ScenarioConfig.from_dict(data)
    except (json.JSONDecodeError, OSError) as e:
        # Log but don't fail - return empty config
        logger.warning("Failed to load scenario config: %s", e)
        return ScenarioConfig()


def get_scenario_config() -> ScenarioConfig:
    """Get cached scenario configuration."""
    global _scenario_config

    if _scenario_config is not None:
        return _scenario_config

    with _scenario_config_lock:
        if _scenario_config is None:
            _scenario_config = _load_scenario_config()
        return _scenario_config


def get_config(key: str, default: Any = None) -> Any:
    """
    Get configuration value with fallback chain:
    1. Environment variable (uppercase, with SCENARIO_ prefix)
    2. Scenario config raw data
    3. Default value
    """
    # Try environment first
    env_key = f"SCENARIO_{key.upper()}"
    if env_val := os.getenv(env_key):
        return env_val

    # Try scenario config
    config = get_scenario_config()
    if key in config.raw:
        return config.raw[key]

    return default


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class SessionState:
    """
    Tracks which observations are active for this session.
    Persisted to SESSION_STATE_PATH so all containers share the same state.
    """

    session_id: str
    active_observations: list[str]
    active_hallucinations: list[str] = field(default_factory=list)
    created_at: str = ""
    # Range mode fields
    range_mode: bool = False
    active_services: list[str] = field(default_factory=list)
    selected_chains: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "active_observations": self.active_observations,
            "active_hallucinations": self.active_hallucinations,
            "created_at": self.created_at,
            "range_mode": self.range_mode,
            "active_services": self.active_services,
            "selected_chains": self.selected_chains,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SessionState:
        return cls(
            session_id=data.get("session_id", ""),
            active_observations=data.get("active_observations", []),
            active_hallucinations=data.get("active_hallucinations", []),
            created_at=data.get("created_at", ""),
            range_mode=data.get("range_mode", False),
            active_services=data.get("active_services", []),
            selected_chains=data.get("selected_chains", []),
        )


_session_cache: SessionState | None = None
_session_lock = threading.Lock()


def _generate_session_id() -> str:
    """Generate a random session ID."""
    return hashlib.sha256(os.urandom(32)).hexdigest()[:16]


def resolve_active_observations(
    config: ScenarioConfig,
    session_id: str,
    selected_chains: list[dict] | None = None,
    *,
    randomize: bool | None = None,
) -> list[str]:
    """The observations a session plants, derived from its id (lab backport 1b).

    In order:
    1. the scenario's `certain` observations;
    2. a sample from `random_pool`, sized within `random_count`;
    3. every selected chain package's `required_findings`, so a chain the range
       picked can actually be completed.

    Then an order-stable dedupe.

    The RNG is seeded with the session id, never the global `random`. Every
    container derives the same list from the same session file without a lock,
    and a session id reproduces its range. `range/start-range.sh` writes only
    the id, the chains and the services, and leaves this list to Python.
    """
    if randomize is None:
        randomize = RANDOMIZE_OBSERVATIONS
    rng = random.Random(session_id)
    observations = list(config.observations.certain)

    pool = list(config.observations.random_pool)
    if pool and randomize:
        high = min(config.observations.random_max, len(pool))
        low = min(config.observations.random_min, high)
        count = rng.randint(low, high) if high > 0 else 0
        if count > 0:
            observations.extend(rng.sample(pool, k=count))

    for chain in selected_chains or []:
        observations.extend(chain.get("required_findings", []) or [])

    return list(dict.fromkeys(observations))


def resolve_active_hallucinations(session_id: str) -> list[str]:
    """Hallucination ids for a session, seeded by its id like the observations."""
    rng = random.Random(f"{session_id}:hallucinations")
    hallucination_ids = [f"H{i:02d}" for i in range(1, 21)]
    return rng.sample(hallucination_ids, k=rng.randint(2, 5))


def _create_session() -> SessionState:
    """Create a new session with randomized observations."""
    config = get_scenario_config()
    session_id = _generate_session_id()

    session = SessionState(
        session_id=session_id,
        active_observations=resolve_active_observations(config, session_id),
        active_hallucinations=resolve_active_hallucinations(session_id),
        created_at=datetime.now(UTC).isoformat(),
        range_mode=RANGE_MODE,
        active_services=[SERVICE_NAME] if SERVICE_NAME else [],
    )

    return session


def session_from_file_data(data: dict, config: ScenarioConfig | None = None) -> SessionState:
    """Build a session from a session file's contents, deriving what it leaves out.

    `range/start-range.sh` writes `session_id`, `selected_chains` and
    `active_services`, and no `active_observations` (lab backport 1a). That
    list, and the hallucinations, are derived here from the session id. A file
    that does carry the keys is taken as written, even if a list is empty.

    A legacy file's `extra_findings` (what start-range used to write, and what
    no service ever read) is folded in, so an old session still plants those.
    """
    session = SessionState.from_dict(data)
    if not session.session_id:
        # Derived from the file, not random, so every container still agrees.
        digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        session.session_id = digest[:16]
    if "active_observations" not in data:
        config = config or get_scenario_config()
        derived = resolve_active_observations(config, session.session_id, session.selected_chains)
        derived.extend(data.get("extra_findings", []) or [])
        session.active_observations = list(dict.fromkeys(derived))
    if "active_hallucinations" not in data:
        session.active_hallucinations = resolve_active_hallucinations(session.session_id)
    return session


def _load_session() -> SessionState | None:
    """Load session from state file if it exists."""
    if not SESSION_STATE_PATH.exists():
        return None

    try:
        with open(SESSION_STATE_PATH) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    return session_from_file_data(data)


def _save_session(session: SessionState) -> None:
    """Persist session state to file atomically (temp file + rename)."""
    import tempfile

    SESSION_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write to temp file, then rename for atomic update
    fd, tmp_path = tempfile.mkstemp(dir=SESSION_STATE_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(session.to_dict(), f, indent=2)
        # Atomic rename (on POSIX; on Windows, replaces if exists)
        os.replace(tmp_path, SESSION_STATE_PATH)
    except BaseException:
        # Clean up temp file on failure
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def get_or_create_session() -> SessionState:
    """
    Get existing session or create new one.

    Thread-safe and file-based for cross-container consistency.
    First container to call this creates the session; others read it.
    """
    global _session_cache

    # Fast path: already cached in this process
    if _session_cache is not None:
        return _session_cache

    with _session_lock:
        # Double-check after acquiring lock
        if _session_cache is not None:
            return _session_cache

        # Try loading from file (another container may have created it)
        session = _load_session()

        if session is None:
            # We're first - create and persist
            session = _create_session()
            _save_session(session)

        _session_cache = session
        return session


def reset_session() -> SessionState:
    """
    Clear session and create new one with fresh randomization.
    Called by range reset scripts.
    """
    global _session_cache

    with _session_lock:
        _session_cache = None

        if SESSION_STATE_PATH.exists():
            SESSION_STATE_PATH.unlink()

        session = _create_session()
        _save_session(session)
        _session_cache = session

        return session


def reload_session() -> SessionState:
    """
    Force reload session from file.
    Useful when another container has reset the session.
    """
    global _session_cache

    with _session_lock:
        _session_cache = None
        return get_or_create_session()


# ═══════════════════════════════════════════════════════════════════════════════
# OBSERVATION CHECKS
# ═══════════════════════════════════════════════════════════════════════════════


def is_observation_active(observation_id: str) -> bool:
    """
    Check if a specific observation is active in current session.

    This is the primary API for services to check whether to expose
    a vulnerability or security misconfiguration.

    Usage:
        if is_observation_active("cors_misconfigured"):
            response.headers["Access-Control-Allow-Origin"] = "*"
    """
    session = get_or_create_session()
    return observation_id in session.active_observations


def get_active_observations() -> list[str]:
    """Get list of all active observation IDs for current session."""
    session = get_or_create_session()
    return list(session.active_observations)


def get_active_hallucinations() -> list[str]:
    """Get list of hallucination IDs active for current session."""
    session = get_or_create_session()
    return list(session.active_hallucinations)


def get_session_id() -> str:
    """Get current session ID."""
    session = get_or_create_session()
    return session.session_id


def is_range_mode() -> bool:
    """Check if running in range mode."""
    return RANGE_MODE


# ═══════════════════════════════════════════════════════════════════════════════
# BRAND HELPERS
# ═══════════════════════════════════════════════════════════════════════════════


def get_brand_name() -> str:
    """Get the scenario's brand name for display."""
    if BRAND_NAME:
        return BRAND_NAME
    config = get_scenario_config()
    return config.brand_name or config.name or "Demo"


def get_brand_domain() -> str:
    """Get the scenario's domain for URLs."""
    if BRAND_DOMAIN:
        return BRAND_DOMAIN
    config = get_scenario_config()
    return config.brand_domain or "localhost"
