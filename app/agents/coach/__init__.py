"""Coach agent component.

Pure re-export of the entry class so `from app.agents.coach import CoachAgent`
resolves to the same object the agent factory builds (identity-preserving, §3.1).
"""

from app.agents.coach.agent import CoachAgent

__all__ = ["CoachAgent"]
