"""
app/scan_context.py - Session resolution helper

Routes and engine modules that used to read `state.active_scan_id` /
`state._last_scan_id` now resolve a ScanSession through this helper.

Phase B back-compat: when no scan_id is passed, return the most-recently
started non-terminal session; if none is live, return the most recently
started session of any status (so post-scan status polls continue to work
while a completed session lingers in the registry's TTL window).
"""

from __future__ import annotations

from app.scan_registry import get_registry
from app.scan_session import ScanSession


def resolve_session(scan_id: str | None = None) -> ScanSession | None:
    """
    Resolve a ScanSession by id, or fall back to the 'current' scan.

    Explicit id wins. When id is None, prefer a running/paused session,
    otherwise return the most recently started session regardless of
    status (post-scan phases — chains, adjudication, triage — run against
    a session that's already marked complete).
    """
    reg = get_registry()
    if scan_id:
        return reg.get(scan_id)
    current = reg.current()
    if current is not None:
        return current
    return reg.most_recent()


def current_scan_id() -> str | None:
    """Convenience: scan id of the active-or-most-recent session."""
    session = resolve_session()
    return session.id if session is not None else None
