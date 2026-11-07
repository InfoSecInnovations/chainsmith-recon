"""Triage agent component.

Pure re-export of the entry class so `from app.agents.triage import TriageAgent`
resolves to the same object the agent factory builds (identity-preserving, §3.1).

The module-level KB helpers (`load_remediation_kb`, `_match_kb_entries`) and the
`_clean_json` utility live in `agent.py`; white-box callers (the triage engine,
co-located tests) import them from `app.agents.triage.agent` directly.
"""

from app.agents.triage.agent import TriageAgent

__all__ = ["TriageAgent"]
