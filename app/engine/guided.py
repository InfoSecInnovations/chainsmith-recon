"""
app/engine/guided.py - Guided Mode Proactive Message Infrastructure

Provides the shared `maybe_emit_proactive()` pattern used by all agents
to push proactive messages when Guided Mode is active.

Phase 36.
"""

from __future__ import annotations

import logging

from app.models import ComponentType

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Proactive message helpers
# ═══════════════════════════════════════════════════════════════════════════════


def make_proactive_message(
    agent: ComponentType,
    trigger: str,
    text: str,
    actions: list[dict] | None = None,
    dismissable: bool = True,
) -> dict:
    """Build a structured proactive message payload for SSE."""
    return {
        "agent": str(agent),
        "trigger": trigger,
        "text": text,
        "actions": actions or [],
        "dismissable": dismissable,
    }


async def maybe_emit_proactive(
    sse_manager,
    session_id: str,
    agent: ComponentType,
    trigger: str,
    text: str,
    actions: list[dict] | None = None,
    dismissable: bool = True,
) -> bool:
    """Emit a proactive message only if Guided Mode is active.

    This is the shared pattern used across all agents. Callers do not
    need to check guided mode themselves — this function handles it.

    Args:
        sse_manager: The SSEManager instance.
        session_id: Target session.
        agent: Which agent is speaking.
        trigger: Trigger key (e.g. "scan_complete", "high_severity_found").
        text: The proactive message body.
        actions: Optional action buttons with label + injected_message.
        dismissable: Whether the operator can dismiss the message.

    Returns:
        True if the message was emitted, False if guided mode is off.
    """
    from app.preferences import is_guided_mode

    if not is_guided_mode():
        return False

    payload = make_proactive_message(
        agent=agent,
        trigger=trigger,
        text=text,
        actions=actions,
        dismissable=dismissable,
    )

    await sse_manager.send(session_id, "proactive_message", payload)
    logger.debug("Proactive message emitted: %s/%s", agent, trigger)
    return True
