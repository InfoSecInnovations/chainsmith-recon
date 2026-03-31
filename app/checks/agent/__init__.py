"""
app/checks/agent - Agent Suite

AI agent reconnaissance checks.
Audits autonomous agent systems for goal hijacking, memory poisoning,
tool abuse, and unsafe multi-step execution patterns.

Implemented checks:
  agent_discovery          - Detect agent orchestration endpoints and frameworks
  agent_goal_injection     - Test for goal hijacking vulnerabilities

Supported frameworks (MVP):
  - LangChain / LangServe / LangGraph

Backlog frameworks:
  - AutoGen
  - CrewAI
  - AgentGPT
  - Semantic Kernel
  - Haystack Agents
  - SuperAGI / BabyAGI / MetaGPT

Backlog checks:
  agent_memory_probe       - Probe persistent memory for extractable content
  agent_memory_poisoning   - Attempt to poison agent memory store
  agent_tool_abuse         - Trigger unintended tool use via crafted tasks
  agent_loop_detection     - Identify runaway/infinite execution risks
  agent_reflection_abuse   - Exploit self-reflection to bypass constraints
  agent_context_overflow   - Test context window limits during multi-step tasks
  agent_callback_injection - Inject payloads via callback/webhook channels
  agent_privilege_escalation - Chain tool calls to escalate permissions

Chain patterns:
  agent_goal_hijack        - Input injection -> goal substitution -> tool execution
  agent_memory_exfil       - Memory read -> sensitive data extraction
  agent_tool_chain_abuse   - Chained tool calls -> unintended side effects
  agent_reflection_bypass  - Reflection loop -> constraint removal -> jailbreak
  agent_callback_pivot     - Callback injection -> external data exfiltration

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://atlas.mitre.org/
  https://python.langchain.com/docs/langserve
"""

from app.checks.base import BaseCheck
from app.checks.agent.discovery import AgentDiscoveryCheck
from app.checks.agent.goal_injection import AgentGoalInjectionCheck

__all__ = [
    "AgentDiscoveryCheck",
    "AgentGoalInjectionCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented Agent checks."""
    return [
        AgentDiscoveryCheck,
        AgentGoalInjectionCheck,
    ]
