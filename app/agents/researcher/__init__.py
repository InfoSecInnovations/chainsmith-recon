"""Researcher agent component.

Pure re-export of the entry class so `from app.agents.researcher import
ResearcherAgent` resolves to the same object the agent factory builds
(identity-preserving, §3.1).

The module-level tool implementations (`_lookup_cve`, `_lookup_exploit_db`,
`_fetch_vendor_advisory`, `_enrich_version_info`) and the declarative
`RESEARCHER_TOOLS` live in `agent.py`; white-box callers import them from
`app.agents.researcher.agent` directly.
"""

from app.agents.researcher.agent import ResearcherAgent

__all__ = ["ResearcherAgent"]
