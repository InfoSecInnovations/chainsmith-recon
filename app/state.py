"""
app/state.py - Global Application State

Centralized state management for the Chainsmith scan engine.
"""

import asyncio
import uuid

from app.check_launcher import CheckLauncher
from app.guardian import Guardian
from app.proof_of_scope import ProofOfScopeSettings, reset_proof_of_scope


class AppState:
    """
    Global application state for scan progress tracking.

    Holds target info, progress counters, settings, and proof-of-scope config.
    Result data (observations, chains, adjudication) lives in the database,
    keyed by active_scan_id.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all state to initial values."""
        self.session_id = uuid.uuid4().hex[:8]
        self.active_scan_id: str | None = None  # Phase 31: points routes to current scan in DB
        self._last_scan_id: str | None = None  # Internal: used by post-scan phases
        self.target: str | None = None
        self.exclude: list[str] = []
        self.techniques: list[str] = []
        self.status: str = "idle"
        self.phase: str = "idle"  # idle, scanning, done

        # Cooperative pause/stop controls. pause_event set = running, cleared = paused.
        # stop_requested is checked between checks; the runner breaks when true.
        self.pause_event: asyncio.Event = asyncio.Event()
        self.pause_event.set()
        self.stop_requested: bool = False
        self.error_message: str | None = None
        self.runner: CheckLauncher | None = None

        # Progress tracking
        self.checks_total: int = 0
        self.checks_completed: int = 0
        self.current_check: str | None = None
        self.check_statuses: dict[str, str] = {}  # name -> status
        self.skip_reasons: dict[str, str] = {}  # name -> why skipped

        # Chain / adjudication concurrency guards (result data is in DB)
        self.chain_status: str = "idle"  # idle, analyzing, complete, partial, error
        self.adjudication_status: str = "idle"  # idle, adjudicating, complete, error
        self.triage_status: str = "idle"  # idle, triaging, complete, error
        self.chainsmith_status: str = "idle"  # idle, validating, complete, error

        # Settings
        self.settings = {
            "parallel": False,
            "rate_limit": 10.0,
            "default_techniques": [],
        }

        # Engagement link
        self.engagement_id: str | None = None

        # Proof of scope settings
        self.proof_settings = ProofOfScopeSettings()

        # Guardian — single authority for scope enforcement
        self.guardian: Guardian | None = None

        # Reset proof of scope logs
        reset_proof_of_scope()


# Global state instance
state = AppState()
