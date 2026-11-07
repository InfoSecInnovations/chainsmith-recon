"""Adjudicator agent component.

Pure re-export of the entry class so `from app.agents.adjudicator import
AdjudicatorAgent` resolves to the same object the agent factory builds
(identity-preserving, §3.1).
"""

from app.agents.adjudicator.agent import AdjudicatorAgent

__all__ = ["AdjudicatorAgent"]
