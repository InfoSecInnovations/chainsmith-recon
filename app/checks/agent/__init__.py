"""
app/checks/agent - Agent Suite

AI agent reconnaissance checks.
Audits autonomous agent systems for goal hijacking, memory poisoning,
tool abuse, and unsafe multi-step execution patterns.

Implemented checks:
  agent_discovery                - Detect agent orchestration endpoints and frameworks
  agent_goal_injection           - Test for goal hijacking vulnerabilities (+ adaptive payloads)
  agent_multi_agent_detection    - Detect multi-agent system architectures
  agent_framework_version        - Fingerprint framework versions for known CVEs
  agent_memory_extraction        - Probe memory endpoints for extractable content
  agent_tool_abuse               - Test unintended tool invocation via conversation
  agent_privilege_escalation     - Test privilege escalation via conversational claims
  agent_loop_detection           - Detect agent runaway / infinite loop vulnerabilities
  agent_callback_injection       - Test callback/webhook injection and SSRF
  agent_streaming_injection      - Test injection on streaming endpoints
  agent_framework_exploits       - Test framework-specific CVEs and weaknesses
  agent_memory_poisoning         - Test persistent memory poisoning
  agent_context_overflow         - Test guardrails after context window overflow
  agent_reflection_abuse         - Test reflection/self-critique manipulation
  agent_state_manipulation       - Test direct state manipulation via API
  agent_trust_chain              - Exploit trust chain hierarchies
  agent_cross_injection          - Test cross-agent injection via output poisoning

Supported frameworks:
  - LangChain / LangServe / LangGraph
  - AutoGen
  - CrewAI

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://atlas.mitre.org/
  https://python.langchain.com/docs/langserve
"""

from app.checks.agent.callback_injection import AgentCallbackInjectionCheck
from app.checks.agent.context_overflow import AgentContextOverflowCheck
from app.checks.agent.cross_injection import AgentCrossInjectionCheck
from app.checks.agent.discovery import AgentDiscoveryCheck
from app.checks.agent.framework_exploits import AgentFrameworkExploitsCheck
from app.checks.agent.framework_version import AgentFrameworkVersionCheck
from app.checks.agent.goal_injection import AgentGoalInjectionCheck
from app.checks.agent.loop_detection import AgentLoopDetectionCheck
from app.checks.agent.memory_extraction import AgentMemoryExtractionCheck
from app.checks.agent.memory_poisoning import AgentMemoryPoisoningCheck
from app.checks.agent.multi_agent_detection import AgentMultiAgentDetectionCheck
from app.checks.agent.privilege_escalation import AgentPrivilegeEscalationCheck
from app.checks.agent.reflection_abuse import AgentReflectionAbuseCheck
from app.checks.agent.state_manipulation import AgentStateManipulationCheck
from app.checks.agent.streaming_injection import AgentStreamingInjectionCheck
from app.checks.agent.tool_abuse import AgentToolAbuseCheck
from app.checks.agent.trust_chain import AgentTrustChainCheck
from app.checks.base import BaseCheck

__all__ = [
    "AgentDiscoveryCheck",
    "AgentGoalInjectionCheck",
    "AgentMultiAgentDetectionCheck",
    "AgentFrameworkVersionCheck",
    "AgentMemoryExtractionCheck",
    "AgentToolAbuseCheck",
    "AgentPrivilegeEscalationCheck",
    "AgentLoopDetectionCheck",
    "AgentCallbackInjectionCheck",
    "AgentStreamingInjectionCheck",
    "AgentFrameworkExploitsCheck",
    "AgentMemoryPoisoningCheck",
    "AgentContextOverflowCheck",
    "AgentReflectionAbuseCheck",
    "AgentStateManipulationCheck",
    "AgentTrustChainCheck",
    "AgentCrossInjectionCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented Agent checks."""
    return [
        AgentDiscoveryCheck,
        AgentGoalInjectionCheck,
        AgentMultiAgentDetectionCheck,
        AgentFrameworkVersionCheck,
        AgentMemoryExtractionCheck,
        AgentToolAbuseCheck,
        AgentPrivilegeEscalationCheck,
        AgentLoopDetectionCheck,
        AgentCallbackInjectionCheck,
        AgentStreamingInjectionCheck,
        AgentFrameworkExploitsCheck,
        AgentMemoryPoisoningCheck,
        AgentContextOverflowCheck,
        AgentReflectionAbuseCheck,
        AgentStateManipulationCheck,
        AgentTrustChainCheck,
        AgentCrossInjectionCheck,
    ]
