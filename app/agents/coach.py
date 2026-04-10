"""
Coach Agent

Always-available conversational agent that explains anything happening inside
Chainsmith. No tools — pure LLM conversation grounded in session context.

Coach explains results and security concepts, references specific findings by
ID, and directs operators to the right component for their need (e.g.,
"ask ScanAdvisor for scan suggestions").

Session-scoped memory: maintains a capped history of prior Q&A exchanges
within the current session. Clears when chat is cleared.
"""

import logging
from collections import deque
from collections.abc import Awaitable, Callable

from app.lib.llm import LLMClient
from app.models import (
    AgentEvent,
    AttackChain,
    ComponentType,
    EventImportance,
    EventType,
    Observation,
)

logger = logging.getLogger(__name__)

COACH_SYSTEM_PROMPT = """\
You are Coach, a conversational assistant inside Chainsmith — a security \
reconnaissance and assessment platform.

YOUR ROLE:
- Explain what the operator is seeing: findings, chains, agent behavior, \
security concepts
- Reference specific findings by ID when relevant (e.g., "F-003 shows...")
- Use plain language — no jargon for jargon's sake
- Adjust depth to the question: one-liner for "what does CORS mean?", \
detailed walkthrough for "explain this chain's impact"
- Never speculate about findings you can't see in the session context

WHAT YOU KNOW ABOUT:
- Observations (findings): security issues discovered during scans
- Attack chains: linked findings that form multi-step attack paths
- Verifier: fact-checks observations, catches hallucinations
- Adjudicator: debates whether severity ratings are accurate (operator-triggered)
- ScanAdvisor: recommends additional checks and identifies coverage gaps
- CheckProofAdvisor: generates reproduction commands for verified findings
- Researcher: enriches findings with CVE details, exploit info, advisories
- Triage: prioritizes remediation actions
- Guardian: enforces scope boundaries

DIRECTING OPERATORS:
When the operator's question is better handled by another component, tell them:
- "For scan suggestions and coverage gaps, try asking ScanAdvisor."
- "To reproduce this finding, ask CheckProofAdvisor for proof guidance."
- "To challenge the severity rating, trigger Adjudicator."
- "For remediation priorities, ask Triage."
- "To validate your check graph, manage custom checks, or check upstream \
changes, ask the Steward (say 'validate checks' or 'check graph health')."
- "To enrich this finding with CVE details, run Researcher."

CONSTRAINTS:
- You have NO tools. You cannot probe, fetch, or modify anything.
- You explain — you do not tutor or proactively suggest what to investigate.
- You only know what's in the session context provided to you.
- Never fabricate finding IDs, CVE numbers, or data not in your context."""


class CoachAgent:
    """Conversational explainer agent — no tools, LLM-powered.

    Maintains session-scoped memory (capped deque of prior exchanges)
    that clears when the chat is cleared.
    """

    def __init__(
        self,
        client: LLMClient,
        memory_cap: int = 10,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
    ):
        self.client = client
        self.memory_cap = memory_cap
        self.event_callback = event_callback
        # Session-scoped conversation memory (capped)
        self._memory: deque[dict[str, str]] = deque(maxlen=memory_cap)

    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)

    async def ask(
        self,
        question: str,
        observations: list[Observation] | None = None,
        chains: list[AttackChain] | None = None,
        recent_events: list[dict] | None = None,
        scope_summary: str | None = None,
    ) -> str:
        """Answer an operator question grounded in session context.

        Args:
            question: The operator's question.
            observations: Current finding summaries for context.
            chains: Current chain summaries for context.
            recent_events: Recent event feed entries.
            scope_summary: Current scope definition summary.

        Returns:
            The Coach's response text.
        """
        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_START,
                agent=ComponentType.COACH,
                importance=EventImportance.LOW,
                message="Coach processing question...",
            )
        )

        if not self.client.is_available():
            await self.emit(
                AgentEvent(
                    event_type=EventType.AGENT_COMPLETE,
                    agent=ComponentType.COACH,
                    importance=EventImportance.LOW,
                    message="Coach unavailable — no LLM provider configured",
                )
            )
            return (
                "Coach requires an LLM provider. Start Chainsmith with a provider "
                "configured (--provider openai/anthropic/litellm) to enable Coach."
            )

        context_block = self._build_context(observations, chains, recent_events, scope_summary)

        # Build messages with memory
        messages = []
        if context_block:
            messages.append({"role": "system", "content": context_block})

        # Include prior exchanges from memory
        for exchange in self._memory:
            messages.append({"role": "user", "content": exchange["question"]})
            messages.append({"role": "assistant", "content": exchange["answer"]})

        messages.append({"role": "user", "content": question})

        prompt = "\n".join(
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}" for m in messages
        )

        response = await self.client.chat(
            prompt=prompt,
            system=COACH_SYSTEM_PROMPT,
            temperature=0.3,
            max_tokens=2000,
        )

        if not response.success:
            logger.warning("Coach LLM call failed: %s", response.error)
            await self.emit(
                AgentEvent(
                    event_type=EventType.AGENT_COMPLETE,
                    agent=ComponentType.COACH,
                    importance=EventImportance.LOW,
                    message="Coach LLM call failed",
                )
            )
            return "I'm having trouble responding right now. Please try again."

        answer = response.content.strip()

        # Store in memory
        self._memory.append({"question": question, "answer": answer})

        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_COMPLETE,
                agent=ComponentType.COACH,
                importance=EventImportance.LOW,
                message="Coach response complete",
            )
        )

        return answer

    def clear_memory(self):
        """Clear session-scoped conversation memory.

        Called when the operator clears the chat.
        """
        self._memory.clear()

    def _build_context(
        self,
        observations: list[Observation] | None,
        chains: list[AttackChain] | None,
        recent_events: list[dict] | None,
        scope_summary: str | None,
    ) -> str:
        """Build a curated session context block for the Coach."""
        parts = []

        if scope_summary:
            parts.append(f"CURRENT SCOPE:\n{scope_summary}")

        if observations:
            obs_lines = []
            for o in observations:
                line = f"  [{o.id}] {o.title} | {o.severity.value} | status={o.status.value}"
                if o.verification_notes:
                    line += f" | notes: {o.verification_notes[:100]}"
                if o.evidence_quality:
                    line += f" | evidence: {o.evidence_quality.value}"
                obs_lines.append(line)
            parts.append("OBSERVATIONS:\n" + "\n".join(obs_lines))

        if chains:
            chain_lines = []
            for c in chains:
                chain_lines.append(
                    f"  [{c.id}] {c.title} | combined={c.combined_severity.value} | "
                    f"steps: {', '.join(c.attack_steps[:3])}"
                    + (" ..." if len(c.attack_steps) > 3 else "")
                )
            parts.append("ATTACK CHAINS:\n" + "\n".join(chain_lines))

        if recent_events:
            event_lines = []
            for e in recent_events[-20:]:  # Last 20 events
                event_lines.append(f"  [{e.get('event_type', '?')}] {e.get('message', '')[:80]}")
            parts.append("RECENT EVENTS:\n" + "\n".join(event_lines))

        if not parts:
            return "SESSION CONTEXT: No scan data available yet."

        return "SESSION CONTEXT:\n\n" + "\n\n".join(parts)
