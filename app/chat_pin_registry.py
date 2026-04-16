"""
app/chat_pin_registry.py - In-memory chat session → scan pin map

Phase F of the concurrent-scans overhaul. Tracks which scan (if any) each
browser-side chat session is currently watching, so proactive SSE events
(e.g. scan_complete) can fan out to just the chat sessions that actually
care instead of broadcasting to every open drawer.

Pins are ephemeral: process-scoped, not persisted. On restart, clients
re-register via POST /api/v1/chat/sessions/{id}/pin on first interaction.
That's fine — the pin is a selector convenience, not source of truth.
"""

from __future__ import annotations


class ChatSessionPinRegistry:
    def __init__(self) -> None:
        self._pins: dict[str, str] = {}

    def set_pin(self, chat_session_id: str, scan_id: str | None) -> None:
        """Pin a chat session to a scan. Passing None clears the pin."""
        if scan_id is None:
            self._pins.pop(chat_session_id, None)
        else:
            self._pins[chat_session_id] = scan_id

    def clear_pin(self, chat_session_id: str) -> None:
        self._pins.pop(chat_session_id, None)

    def get_pin(self, chat_session_id: str) -> str | None:
        return self._pins.get(chat_session_id)

    def sessions_for_scan(self, scan_id: str) -> list[str]:
        """Return chat session ids currently pinned to the given scan."""
        return [sid for sid, pinned in self._pins.items() if pinned == scan_id]

    def all_pinned_sessions(self) -> list[str]:
        """Return every chat session with a pin (any scan)."""
        return list(self._pins.keys())

    def _reset(self) -> None:
        """Test-only."""
        self._pins.clear()


_registry: ChatSessionPinRegistry | None = None


def get_pin_registry() -> ChatSessionPinRegistry:
    global _registry
    if _registry is None:
        _registry = ChatSessionPinRegistry()
    return _registry
