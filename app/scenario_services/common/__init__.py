"""
app/scenario_services/common - Shared utilities for scenario services.

This package provides:
- config: Session management, observation checks, environment configuration
- (future) middleware: Common FastAPI middleware
- (future) responses: Standard response helpers
"""

from app.scenario_services.common.config import (
    HONEYPOT_ENABLED,
    RANDOMIZE_OBSERVATIONS,
    RANGE_MODE,
    RATE_LIMIT_ENABLED,
    SERVICE_NAME,
    SERVICE_PORT,
    # Environment flags
    VERBOSE_ERRORS,
    WAF_ENABLED,
    ScenarioConfig,
    SessionState,
    get_active_observations,
    get_active_hallucinations,
    get_brand_domain,
    # Brand helpers
    get_brand_name,
    # Configuration
    get_config,
    # Session management
    get_or_create_session,
    get_scenario_config,
    get_session_id,
    # Observation checks
    is_observation_active,
    is_range_mode,
    reload_session,
    reset_session,
)

__all__ = [
    # Session
    "get_or_create_session",
    "reset_session",
    "reload_session",
    "SessionState",
    # Observations
    "is_observation_active",
    "get_active_observations",
    "get_active_hallucinations",
    "get_session_id",
    "is_range_mode",
    # Config
    "get_config",
    "get_scenario_config",
    "ScenarioConfig",
    # Flags
    "VERBOSE_ERRORS",
    "RANDOMIZE_OBSERVATIONS",
    "RATE_LIMIT_ENABLED",
    "WAF_ENABLED",
    "HONEYPOT_ENABLED",
    "RANGE_MODE",
    "SERVICE_NAME",
    "SERVICE_PORT",
    # Brand
    "get_brand_name",
    "get_brand_domain",
]
