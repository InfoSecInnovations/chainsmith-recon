"""
app/state.py - Operator-Scope Application State

Phase B of the concurrent-scans overhaul shrinks AppState to just the
operator's scope prep — the fields that describe *who* is operating and
*what scope* they're allowed to probe. Per-scan runtime state
(progress, status, pause/stop, guardian, runner) has moved to
`app.scan_session.ScanSession`, managed by `app.scan_registry`.

Only these operator-scope fields remain here:
- session_id: the operator's chat/session identifier
- target, exclude, techniques: scope prep used when a scan is launched
- settings: default scan settings
- proof_settings: compliance / scan window / traffic logging
"""

import uuid

from app.proof_of_scope import ProofOfScopeSettings, reset_proof_of_scope


class AppState:
    """
    Operator-scope state.

    Result data (observations, chains, adjudication) lives in the database.
    Per-scan runtime state lives on ScanSession in the registry. This class
    holds only the operator's scope prep — the context from which scans get
    launched.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset operator scope to initial values."""
        self.session_id = uuid.uuid4().hex[:8]
        self.target: str | None = None
        self.exclude: list[str] = []
        self.techniques: list[str] = []

        # Default settings used when launching a scan.
        self.settings = {
            "parallel": False,
            "rate_limit": 10.0,
            "default_techniques": [],
        }

        # Proof of scope / compliance prep.
        self.proof_settings = ProofOfScopeSettings()

        # Reset proof of scope logs.
        reset_proof_of_scope()


# Global operator-scope instance.
state = AppState()
