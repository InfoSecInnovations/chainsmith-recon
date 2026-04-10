"""
Recon Agent Swarm

Four-agent architecture for AI-powered reconnaissance.

Imports are guarded so that individual agents can be imported directly
(e.g., `from app.agents.adjudicator import AdjudicatorAgent`) without
requiring all agent dependencies (openai, etc.) to be installed.
"""

__all__ = [
    "VerifierAgent",
    "ChainsmithAgent",
    "AdjudicatorAgent",
    "TriageAgent",
    "ResearcherAgent",
    "CoachAgent",
]


def __getattr__(name: str):
    """Lazy import of agent classes."""
    if name == "VerifierAgent":
        from app.agents.verifier import VerifierAgent

        return VerifierAgent
    if name == "ChainsmithAgent":
        from app.agents.chainsmith import ChainsmithAgent

        return ChainsmithAgent
    if name == "AdjudicatorAgent":
        from app.agents.adjudicator import AdjudicatorAgent

        return AdjudicatorAgent
    if name == "TriageAgent":
        from app.agents.triage import TriageAgent

        return TriageAgent
    if name == "ResearcherAgent":
        from app.agents.researcher import ResearcherAgent

        return ResearcherAgent
    if name == "CoachAgent":
        from app.agents.coach import CoachAgent

        return CoachAgent
    raise AttributeError(f"module 'app.agents' has no attribute {name!r}")
