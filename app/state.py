"""
app/state.py - Global Application State

Centralized state management for the Chainsmith scan engine.
"""

import uuid
from typing import Optional
from dataclasses import dataclass, field

from app.checks import CheckRunner
from app.proof_of_scope import (
    ProofOfScopeSettings, ScopeChecker, reset_proof_of_scope
)


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
        self.target: Optional[str] = None
        self.exclude: list[str] = []
        self.techniques: list[str] = []
        self.findings: list[dict] = []
        self.status: str = "idle"
        self.phase: str = "idle"  # idle, scanning, verifying, done
        self.error_message: Optional[str] = None
        self.runner: Optional[CheckRunner] = None
        
        # Progress tracking
        self.checks_total: int = 0
        self.checks_completed: int = 0
        self.current_check: Optional[str] = None
        self.check_statuses: dict[str, str] = {}  # name -> status
        self.check_log: list[dict] = []  # History of check executions
        
        # Verification tracking
        self.verified_count: int = 0
        self.verification_total: int = 0
        
        # Chain analysis
        self.chains: list[dict] = []
        self.chain_status: str = "idle"  # idle, analyzing, complete, error
        self.chain_error: Optional[str] = None
        
        # Settings
        self.settings = {
            "parallel": False,
            "rate_limit": 10.0,
            "default_techniques": [],
            "verification_level": "none"  # none, sample, half, all
        }
        
        # Engagement link
        self.engagement_id: Optional[str] = None

        # Proof of scope settings
        self.proof_settings = ProofOfScopeSettings()
        self.scope_checker: Optional[ScopeChecker] = None
        
        # Reset proof of scope logs
        reset_proof_of_scope()


# Global state instance
state = AppState()
