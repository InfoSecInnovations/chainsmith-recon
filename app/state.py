"""
app/state.py - Global Application State

Centralized state management for the Chainsmith scan engine.
"""

import uuid

from app.checks import CheckRunner
from app.proof_of_scope import ProofOfScopeSettings, ScopeChecker, reset_proof_of_scope


class AppState:
    """
    Global application state for scan tracking.

    Holds target info, findings, progress, settings, and proof-of-scope config.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all state to initial values."""
        self.session_id = uuid.uuid4().hex[:8]
        self.target: str | None = None
        self.exclude: list[str] = []
        self.techniques: list[str] = []
        self.findings: list[dict] = []
        self.status: str = "idle"
        self.phase: str = "idle"  # idle, scanning, verifying, done
        self.error_message: str | None = None
        self.runner: CheckRunner | None = None

        # Progress tracking
        self.checks_total: int = 0
        self.checks_completed: int = 0
        self.current_check: str | None = None
        self.check_statuses: dict[str, str] = {}  # name -> status
        self.check_log: list[dict] = []  # History of check executions

        # Verification tracking
        self.verified_count: int = 0
        self.verification_total: int = 0

        # Chain analysis
        self.chains: list[dict] = []
        self.chain_status: str = "idle"  # idle, analyzing, complete, partial, error
        self.chain_error: str | None = None
        self.chain_llm_analysis: dict | None = None  # structured LLM analysis detail

        # Settings
        self.settings = {
            "parallel": False,
            "rate_limit": 10.0,
            "default_techniques": [],
            "verification_level": "none",  # none, sample, half, all
        }

        # Engagement link
        self.engagement_id: str | None = None

        # Scan advisor recommendations (Phase 20)
        self.advisor_recommendations: list[dict] = []

        # Adjudication tracking (Phase 21)
        self.adjudication_status: str = "idle"  # idle, adjudicating, complete, error
        self.adjudication_results: list[dict] = []
        self.adjudication_error: str | None = None

        # Proof of scope settings
        self.proof_settings = ProofOfScopeSettings()
        self.scope_checker: ScopeChecker | None = None

        # Reset proof of scope logs
        reset_proof_of_scope()


# Global state instance
state = AppState()
