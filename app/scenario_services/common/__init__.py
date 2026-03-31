"""
app/scenario_services/common - Shared utilities for scenario services.

This package provides:
- config: Session management, finding checks, environment configuration
- (future) middleware: Common FastAPI middleware
- (future) responses: Standard response helpers
"""

from app.scenario_services.common.config import (
    # Session management
    get_or_create_session,
    reset_session,
    reload_session,
    SessionState,
    # Finding checks
    is_finding_active,
    get_active_findings,
    get_active_hallucinations,
    get_session_id,
    is_range_mode,
    # Configuration
    get_config,
    get_scenario_config,
    ScenarioConfig,
    # Environment flags
    VERBOSE_ERRORS,
    RANDOMIZE_FINDINGS,
    RATE_LIMIT_ENABLED,
    WAF_ENABLED,
    HONEYPOT_ENABLED,
    RANGE_MODE,
    SERVICE_NAME,
    SERVICE_PORT,
    # Brand helpers
    get_brand_name,
    get_brand_domain,
)

__all__ = [
    # Session
    "get_or_create_session",
    "reset_session",
    "reload_session",
    "SessionState",
    # Findings
    "is_finding_active",
    "get_active_findings",
    "get_active_hallucinations",
    "get_session_id",
    "is_range_mode",
    # Config
    "get_config",
    "get_scenario_config",
    "ScenarioConfig",
    # Flags
    "VERBOSE_ERRORS",
    "RANDOMIZE_FINDINGS",
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
