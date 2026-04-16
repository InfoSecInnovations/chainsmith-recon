"""
app/scan_registry.py - Process-Scoped Scan Registry

Introduced in Phase A of the concurrent-scans overhaul. ScanRegistry is a
dict of live (and recently-terminal) ScanSession objects keyed by scan id.

Phase A wires the registry in alongside AppState — scans are registered
but routes still read state. Phase B flips route reads. Phase C enforces
the max_concurrent_scans cap. Until then the registry is observational.

Singleton access: get_registry(). Kept singleton for pragmatic reasons
(§11.2 of the design doc); dependency-inject later if testing requires.
"""

from __future__ import annotations

import time

from app.scan_session import TERMINAL_STATUSES, ScanSession


class ScanRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, ScanSession] = {}

    # ── lifecycle ────────────────────────────────────────────────

    def register(self, session: ScanSession) -> None:
        """Add a newly-started session."""
        self._sessions[session.id] = session

    def get(self, scan_id: str) -> ScanSession | None:
        return self._sessions.get(scan_id)

    def remove(self, scan_id: str) -> ScanSession | None:
        return self._sessions.pop(scan_id, None)

    # ── queries ──────────────────────────────────────────────────

    def list(self, *, status: str | None = None) -> list[ScanSession]:
        """Return sessions, optionally filtered by exact status."""
        if status is None:
            return list(self._sessions.values())
        return [s for s in self._sessions.values() if s.status == status]

    def active(self) -> list[ScanSession]:
        """Non-terminal sessions (running or paused)."""
        return [s for s in self._sessions.values() if not s.is_terminal]

    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if not s.is_terminal)

    def current(self) -> ScanSession | None:
        """
        Most-recently-started non-terminal session.

        Back-compat escape hatch for single-scan routes during Phase A/B —
        those routes keep reading a "current" scan. Returns None if no
        active scan exists; callers should fall back to the most recent
        terminal session only if they care about scan-complete polls.
        """
        candidates = [s for s in self._sessions.values() if not s.is_terminal]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.started_at)

    def most_recent(self) -> ScanSession | None:
        """Most-recently-started session regardless of status."""
        if not self._sessions:
            return None
        return max(self._sessions.values(), key=lambda s: s.started_at)

    # ── reaping ──────────────────────────────────────────────────

    def reap_completed(self, ttl_seconds: int, *, now: float | None = None) -> int:
        """
        Drop terminal sessions whose completed_at is older than ttl_seconds.

        Returns the number of sessions reaped. Safe to call repeatedly.
        """
        cutoff = (now if now is not None else time.time()) - ttl_seconds
        to_drop = [
            sid
            for sid, s in self._sessions.items()
            if s.status in TERMINAL_STATUSES
            and s.completed_at is not None
            and s.completed_at < cutoff
        ]
        for sid in to_drop:
            del self._sessions[sid]
        return len(to_drop)

    # ── test helpers ─────────────────────────────────────────────

    def _reset(self) -> None:
        """Test-only: drop all sessions."""
        self._sessions.clear()


_registry: ScanRegistry | None = None


def get_registry() -> ScanRegistry:
    global _registry
    if _registry is None:
        _registry = ScanRegistry()
    return _registry
