"""
app/engine/chat.py - Chat SSE Manager & Agent Event Bridge

Manages per-user SSE connections, agent message queues, and the bridge
that routes AgentEvent emissions into the chat stream.

Phase 35a: Text chat with SSE (MVP).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from app.db.repositories import ChatRepository
from app.models import AgentEvent, ComponentType, RouteDecision

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Chat response models
# ═══════════════════════════════════════════════════════════════════════════════


def make_chat_response(
    agent: ComponentType,
    text: str,
    references: list[dict] | None = None,
    actions: list[dict] | None = None,
    route_method: str | None = None,
    msg_id: str | None = None,
) -> dict:
    """Build a structured chat response dict."""
    return {
        "id": msg_id or f"msg-{uuid.uuid4().hex[:8]}",
        "agent": str(agent),
        "text": text,
        "timestamp": datetime.now(UTC).isoformat(),
        "routed_via": route_method,
        "references": references or [],
        "actions": actions or [],
    }


def make_system_message(text: str, msg_id: str | None = None) -> dict:
    """Build a system message (errors, redirects, info)."""
    return {
        "id": msg_id or f"sys-{uuid.uuid4().hex[:8]}",
        "agent": None,
        "text": text,
        "timestamp": datetime.now(UTC).isoformat(),
        "routed_via": None,
        "references": [],
        "actions": [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SSE Manager — per-user connection tracking and broadcast
# ═══════════════════════════════════════════════════════════════════════════════


class SSEManager:
    """Manages Server-Sent Event connections, one stream per user.

    Each connected user has an asyncio.Queue. The SSE endpoint reads
    from the queue and streams events to the browser.
    """

    def __init__(self) -> None:
        # session_id -> list of queues (one per tab/connection)
        self._connections: dict[str, list[asyncio.Queue]] = defaultdict(list)
        # agent_type -> queue of pending messages (one-at-a-time processing)
        self._agent_queues: dict[str, asyncio.Queue] = {}
        self._agent_busy: dict[str, bool] = {}

    def connect(self, session_id: str) -> asyncio.Queue:
        """Register a new SSE connection. Returns the queue to read from."""
        queue: asyncio.Queue = asyncio.Queue()
        self._connections[session_id].append(queue)
        logger.info(
            "SSE connection opened for session %s (total: %d)",
            session_id,
            len(self._connections[session_id]),
        )
        return queue

    def disconnect(self, session_id: str, queue: asyncio.Queue) -> None:
        """Unregister an SSE connection."""
        conns = self._connections.get(session_id, [])
        if queue in conns:
            conns.remove(queue)
        if not conns:
            self._connections.pop(session_id, None)
        logger.info("SSE connection closed for session %s", session_id)

    async def send(self, session_id: str, event_type: str, data: dict) -> None:
        """Push an event to all connections for a session."""
        conns = self._connections.get(session_id, [])
        payload = {"event": event_type, "data": data}
        for queue in conns:
            await queue.put(payload)

    async def broadcast_all(self, event_type: str, data: dict) -> None:
        """Push an event to ALL connected sessions."""
        payload = {"event": event_type, "data": data}
        for conns in self._connections.values():
            for queue in conns:
                await queue.put(payload)

    def has_connections(self, session_id: str) -> bool:
        """Check if a session has active SSE connections."""
        return bool(self._connections.get(session_id))

    # ─── Agent queue management ────────────────────────────────────

    def is_agent_busy(self, agent_type: str) -> bool:
        """Check if an agent is currently processing a message."""
        return self._agent_busy.get(agent_type, False)

    def set_agent_busy(self, agent_type: str, busy: bool) -> None:
        """Mark an agent as busy/idle."""
        self._agent_busy[agent_type] = busy


# ═══════════════════════════════════════════════════════════════════════════════
# Agent Event Bridge — connects agent callbacks to SSE stream
# ═══════════════════════════════════════════════════════════════════════════════


def create_chat_event_bridge(
    sse_manager: SSEManager,
    session_id: str,
):
    """Create an event callback that bridges agent events to SSE.

    Returns a callback function compatible with the agent event_callback
    signature: async (AgentEvent) -> None.
    """

    async def bridge(event: AgentEvent) -> None:
        await sse_manager.send(
            session_id,
            event_type="agent_event",
            data={
                "event_type": str(event.event_type),
                "agent": str(event.agent),
                "importance": str(event.importance),
                "message": event.message,
                "details": event.details,
                "observation_id": event.observation_id,
                "chain_id": event.chain_id,
                "timestamp": event.timestamp.isoformat(),
            },
        )

    return bridge


# ═══════════════════════════════════════════════════════════════════════════════
# Chat Dispatcher — routes messages through Prompt Router to agents
# ═══════════════════════════════════════════════════════════════════════════════


class ChatDispatcher:
    """Orchestrates chat message flow: route → agent → response → SSE.

    Handles agent queuing (one message at a time per agent) and
    persistence of both operator and agent messages.

    Unified chat API: if `target_agent` is specified, routes directly to
    that agent bypassing PromptRouter. Otherwise classifies via the router.
    """

    def __init__(self, sse_manager: SSEManager, chat_repo: ChatRepository) -> None:
        self.sse = sse_manager
        self.repo = chat_repo
        self._router = None  # lazy — set via set_router()
        self._coach = None  # lazy — created on first Coach request

    def set_router(self, router) -> None:
        """Inject the PromptRouter (avoids circular import)."""
        self._router = router

    def clear_coach_memory(self) -> None:
        """Clear Coach session memory. Called when chat is cleared."""
        if self._coach is not None:
            self._coach.clear_memory()

    def _get_coach(self):
        """Lazy-init the Coach agent."""
        if self._coach is None:
            from app.agents.coach import CoachAgent
            from app.lib.llm import get_llm_client

            client = get_llm_client()
            self._coach = CoachAgent(client=client)
        return self._coach

    async def handle_operator_message(
        self,
        session_id: str,
        text: str,
        ui_context: dict[str, str] | None = None,
        engagement_id: str | None = None,
        target_agent: str | None = None,
        scan_id: str | None = None,
    ) -> dict:
        """Process an operator chat message end-to-end.

        1. Persist operator message
        2. Route via PromptRouter (or direct agent if specified)
        3. Dispatch to target agent (or return clarification)
        4. Persist agent response
        5. Push response to SSE stream
        """
        # 1. Persist operator message
        op_msg_id = f"msg-{uuid.uuid4().hex[:8]}"
        await self.repo.save_message(
            msg_id=op_msg_id,
            session_id=session_id,
            direction="operator",
            text=text,
            engagement_id=engagement_id,
            ui_context=ui_context,
        )

        # 2. Route — direct agent or PromptRouter
        if target_agent:
            # Direct agent targeting — bypass PromptRouter
            component_map = {a.value: a for a in ComponentType}
            agent = component_map.get(target_agent)
            if agent is None:
                error_msg = make_system_message(
                    f"Unknown agent '{target_agent}'. Available: {', '.join(component_map.keys())}"
                )
                await self._persist_and_send(session_id, engagement_id, error_msg, None)
                return error_msg
            decision = RouteDecision(target=agent, method="direct", confidence=1.0)
        else:
            if self._router is None:
                error_msg = make_system_message(
                    "Chat system is not fully initialized. The prompt router is unavailable."
                )
                await self.sse.send(session_id, "chat_response", error_msg)
                return error_msg

            try:
                decision = await self._router.route(text, ui_context)
            except Exception as exc:
                logger.exception("Prompt router error")
                error_msg = make_system_message(f"Could not classify your message: {exc}")
                await self._persist_and_send(session_id, engagement_id, error_msg, None)
                return error_msg

        # 3. Handle clarification needed
        if decision.needs_clarification:
            clarify_msg = make_system_message(
                decision.clarification_prompt or "Could you clarify what you'd like to do?"
            )
            await self._persist_and_send(session_id, engagement_id, clarify_msg, decision.method)
            return clarify_msg

        # 4. Handle redirect notification
        if decision.redirect_message:
            await self.sse.send(
                session_id,
                "redirect",
                {
                    "from_agent": None,
                    "to_agent": str(decision.target),
                    "reason": decision.redirect_message,
                },
            )

        # 5. Check agent busy → queue indicator
        agent_name = str(decision.target)
        if self.sse.is_agent_busy(agent_name):
            await self.sse.send(
                session_id,
                "typing",
                {"agent": agent_name, "status": "queued"},
            )

        # 6. Send typing indicator
        await self.sse.send(
            session_id,
            "typing",
            {"agent": agent_name, "status": "thinking"},
        )

        # 7. Dispatch to agent
        response = await self._dispatch_to_agent(decision, text, session_id, ui_context)

        # 8. Persist and push agent response
        await self._persist_and_send(
            session_id, engagement_id, response, decision.method, agent_name
        )

        return response

    async def _dispatch_to_agent(
        self,
        decision: RouteDecision,
        text: str,
        session_id: str,
        ui_context: dict[str, str] | None,
    ) -> dict:
        """Dispatch a message to the target agent and return the response.

        This is the integration point where agents are called. For MVP,
        agents that don't have a chat-compatible interface get a
        placeholder response explaining what the agent does.
        """

        agent_type = decision.target
        bridge = create_chat_event_bridge(self.sse, session_id)

        self.sse.set_agent_busy(str(agent_type), True)
        try:
            if agent_type == ComponentType.CHAINSMITH:
                return await self._handle_chainsmith(text, bridge)
            elif agent_type == ComponentType.TRIAGE:
                return await self._handle_triage(text, session_id, bridge)
            elif agent_type == ComponentType.ADJUDICATOR:
                return await self._handle_adjudicator(text, session_id, bridge)
            elif agent_type == ComponentType.VERIFIER:
                return await self._handle_verifier(text, session_id, bridge)
            elif agent_type == ComponentType.COACH:
                return await self._handle_coach(text, session_id, bridge)
            elif agent_type == ComponentType.CHECK_PROOF_ADVISOR:
                return await self._handle_check_proof_advisor(text, session_id, bridge)
            elif agent_type == ComponentType.RESEARCHER:
                return await self._handle_researcher(text, session_id, bridge)
            else:
                return make_chat_response(
                    agent=agent_type,
                    text=f"The {agent_type} agent received your message but doesn't "
                    f"have a chat interface yet. This will be available in a future update.",
                    route_method=decision.method,
                )
        except Exception as exc:
            logger.exception("Agent dispatch error for %s", agent_type)
            return make_system_message(
                f"The {agent_type} agent encountered an error: {exc}. "
                "Try again or interact with it directly from its page."
            )
        finally:
            self.sse.set_agent_busy(str(agent_type), False)

    async def _handle_chainsmith(self, text: str, bridge) -> dict:
        """Route to ChainsmithAgent for check/chain stewardship."""
        from app.agents.chainsmith import ChainsmithAgent

        agent = ChainsmithAgent(event_callback=bridge)
        response = await agent.handle_message(text)
        return make_chat_response(
            agent=ComponentType.CHAINSMITH,
            text=response,
            route_method="keyword",
        )

    async def _handle_triage(self, text: str, session_id: str, bridge) -> dict:
        """Summarize triage plan or answer triage questions."""
        from app.db.repositories import TriageRepository
        from app.state import state

        scan_id = state.active_scan_id or state._last_scan_id
        if not scan_id:
            return make_chat_response(
                agent=ComponentType.TRIAGE,
                text="No scan data available yet. Run a scan first, then I can "
                "help prioritize remediation.",
                route_method="keyword",
            )

        repo = TriageRepository()
        plan = await repo.get_plan(scan_id)
        if not plan:
            return make_chat_response(
                agent=ComponentType.TRIAGE,
                text="No triage plan has been generated for the current scan. "
                "Trigger triage from the scan page first.",
                route_method="keyword",
            )

        # Summarize the plan in chat
        actions = await repo.get_actions(plan["id"])
        quick = [a for a in actions if a.get("effort_estimate") == "low"]
        summary_lines = [plan.get("summary", "Triage plan available.")]
        if quick:
            summary_lines.append(f"\n{len(quick)} quick win(s). Top: {quick[0]['action']}")
        summary_lines.append(
            "\nWould you like me to write a detailed analysis to the reports directory?"
        )
        return make_chat_response(
            agent=ComponentType.TRIAGE,
            text="\n".join(summary_lines),
            route_method="keyword",
            actions=[
                {
                    "label": "Write full analysis to reports",
                    "action": "triage_detailed_report",
                    "params": {"scan_id": scan_id},
                }
            ],
        )

    async def _handle_adjudicator(self, text: str, session_id: str, bridge) -> dict:
        """Summarize adjudication results or answer questions."""
        from app.db.repositories import AdjudicationRepository
        from app.state import state

        scan_id = state.active_scan_id or state._last_scan_id
        if not scan_id:
            return make_chat_response(
                agent=ComponentType.ADJUDICATOR,
                text="No scan data available yet. Run a scan first.",
                route_method="keyword",
            )

        repo = AdjudicationRepository()
        results = await repo.get_results(scan_id)
        if not results:
            return make_chat_response(
                agent=ComponentType.ADJUDICATOR,
                text="No adjudication results for the current scan. "
                "Trigger adjudication from the scan page.",
                route_method="keyword",
            )

        adjusted = [r for r in results if r["original_severity"] != r["adjudicated_severity"]]
        summary = (
            f"Adjudication complete: {len(results)} observations reviewed, "
            f"{len(adjusted)} severity adjustment(s)."
        )
        if adjusted:
            top = adjusted[0]
            summary += (
                f" Example: {top['observation_id']} changed from "
                f"{top['original_severity']} to {top['adjudicated_severity']}."
            )
        return make_chat_response(
            agent=ComponentType.ADJUDICATOR,
            text=summary,
            route_method="keyword",
            references=[
                {"type": "observation", "id": r["observation_id"], "label": r["observation_id"]}
                for r in adjusted[:5]
            ],
        )

    async def _handle_verifier(self, text: str, session_id: str, bridge) -> dict:
        """Summarize verification status."""
        from app.db.repositories import ObservationRepository
        from app.state import state

        scan_id = state.active_scan_id or state._last_scan_id
        if not scan_id:
            return make_chat_response(
                agent=ComponentType.VERIFIER,
                text="No scan data available. Run a scan first.",
                route_method="keyword",
            )

        repo = ObservationRepository()
        obs = await repo.get_observations(scan_id)
        verified = [o for o in obs if o.get("verification_status") == "verified"]
        rejected = [o for o in obs if o.get("verification_status") == "rejected"]

        return make_chat_response(
            agent=ComponentType.VERIFIER,
            text=(
                f"{len(obs)} observations total: {len(verified)} verified, "
                f"{len(rejected)} rejected, "
                f"{len(obs) - len(verified) - len(rejected)} pending."
            ),
            route_method="keyword",
        )

    async def _handle_coach(self, text: str, session_id: str, bridge) -> dict:
        """Route to Coach agent for explanations."""
        from app.db.repositories import ChainRepository, ObservationRepository
        from app.state import state

        coach = self._get_coach()

        # Build session context for Coach
        scan_id = state.active_scan_id or state._last_scan_id
        observations = []
        chains = []

        if scan_id:
            obs_repo = ObservationRepository()
            obs_records = await obs_repo.get_observations(scan_id)

            # Convert DB records to lightweight Observation-like objects for context
            from app.models import (
                EvidenceQuality,
                Observation,
                ObservationSeverity,
                ObservationStatus,
            )

            for rec in obs_records:
                try:
                    observations.append(
                        Observation(
                            id=rec["id"],
                            observation_type=rec.get("check_name", "unknown"),
                            title=rec["title"],
                            description=rec.get("description", ""),
                            severity=ObservationSeverity(rec.get("severity", "info")),
                            status=ObservationStatus(rec.get("verification_status", "pending")),
                            confidence=rec.get("confidence", 0.5) or 0.5,
                            check_name=rec.get("check_name"),
                            discovered_at=rec.get("created_at", datetime.now(UTC)),
                            verification_notes=rec.get("description", ""),
                            evidence_quality=(
                                EvidenceQuality(rec["evidence_quality"])
                                if rec.get("evidence_quality")
                                else None
                            ),
                        )
                    )
                except Exception:
                    continue

            chain_repo = ChainRepository()
            chain_records = await chain_repo.get_chains(scan_id)
            from app.models import AttackChain
            from app.models import ObservationSeverity as _Sev

            for crec in chain_records:
                try:
                    chains.append(
                        AttackChain(
                            id=crec["id"],
                            title=crec["title"],
                            description=crec.get("description", ""),
                            impact_statement="",
                            observation_ids=crec.get("observation_ids", []),
                            individual_severities=[],
                            combined_severity=_Sev(crec.get("severity", "info")),
                            severity_reasoning="",
                            attack_steps=[],
                        )
                    )
                except Exception:
                    continue

        scope_summary = None
        if state.target:
            scope_summary = f"Target: {state.target}"
            if state.exclude:
                scope_summary += f", Exclusions: {', '.join(state.exclude)}"

        answer = await coach.ask(
            question=text,
            observations=observations or None,
            chains=chains or None,
            scope_summary=scope_summary,
        )

        return make_chat_response(
            agent=ComponentType.COACH,
            text=answer,
            route_method="direct",
        )

    async def _handle_check_proof_advisor(self, text: str, session_id: str, bridge) -> dict:
        """Route to CheckProofAdvisor for proof guidance."""
        import re

        from app.advisors.check_proof import CheckProofAdvisor
        from app.db.repositories import ObservationRepository
        from app.state import state

        scan_id = state.active_scan_id or state._last_scan_id
        if not scan_id:
            return make_chat_response(
                agent=ComponentType.CHECK_PROOF_ADVISOR,
                text="No scan data available. Run a scan first, then I can "
                "generate proof guidance for verified findings.",
                route_method="direct",
            )

        # Extract observation ID from message (e.g., "F-003", "proof for F-007")
        id_match = re.search(r"\b(F-\d+)\b", text, re.I)

        repo = ObservationRepository()
        obs_records = await repo.get_observations(scan_id)

        if id_match:
            target_id = id_match.group(1).upper()
            matching = [o for o in obs_records if o["id"] == target_id]
            if not matching:
                return make_chat_response(
                    agent=ComponentType.CHECK_PROOF_ADVISOR,
                    text=f"Observation {target_id} not found in the current scan.",
                    route_method="direct",
                )
        else:
            # No specific ID — generate for all verified
            matching = [o for o in obs_records if o.get("verification_status") == "verified"]
            if not matching:
                return make_chat_response(
                    agent=ComponentType.CHECK_PROOF_ADVISOR,
                    text="No verified observations found. Verify findings first, "
                    "then I can generate proof guidance.",
                    route_method="direct",
                )

        # Convert to Observation models
        from app.models import EvidenceQuality, Observation, ObservationSeverity, ObservationStatus

        observations = []
        for rec in matching:
            try:
                observations.append(
                    Observation(
                        id=rec["id"],
                        observation_type=rec.get("check_name", "unknown"),
                        title=rec["title"],
                        description=rec.get("description", ""),
                        severity=ObservationSeverity(rec.get("severity", "info")),
                        status=ObservationStatus(rec.get("verification_status", "pending")),
                        confidence=rec.get("confidence", 0.5) or 0.5,
                        check_name=rec.get("check_name"),
                        discovered_at=rec.get("created_at", datetime.now(UTC)),
                        evidence_quality=(
                            EvidenceQuality(rec["evidence_quality"])
                            if rec.get("evidence_quality")
                            else None
                        ),
                    )
                )
            except Exception:
                continue

        advisor = CheckProofAdvisor()
        guidances = (
            advisor.generate_batch(observations)
            if len(observations) > 1
            else ([advisor.generate_guidance(observations[0])] if observations else [])
        )

        if not guidances:
            return make_chat_response(
                agent=ComponentType.CHECK_PROOF_ADVISOR,
                text="No proof guidance could be generated for the selected observations.",
                route_method="direct",
            )

        # Format response
        lines = []
        for g in guidances:
            lines.append(f"**[{g.finding_id}] {g.finding_title}**")
            lines.append(
                f"Status: {g.verification_status} | Evidence: {g.evidence_quality or 'N/A'}"
            )
            lines.append("")
            if g.proof_steps:
                lines.append("Reproduction steps:")
                for i, step in enumerate(g.proof_steps, 1):
                    lines.append(f"  {i}. [{step.tool}] `{step.command}`")
                    lines.append(f"     Expected: {step.expected_output}")
                lines.append("")
            if g.severity_rationale:
                lines.append(f"Severity rationale: {g.severity_rationale}")
                lines.append("")
            if g.false_positive_indicators:
                lines.append("False positive indicators:")
                for fp in g.false_positive_indicators:
                    lines.append(f"  - {fp}")
                lines.append("")
            lines.append("---")

        return make_chat_response(
            agent=ComponentType.CHECK_PROOF_ADVISOR,
            text="\n".join(lines),
            route_method="direct",
        )

    async def _handle_researcher(self, text: str, session_id: str, bridge) -> dict:
        """Route to Researcher agent for enrichment (summary in chat)."""
        from app.state import state

        scan_id = state.active_scan_id or state._last_scan_id
        if not scan_id:
            return make_chat_response(
                agent=ComponentType.RESEARCHER,
                text="No scan data available. Run a scan first, then I can "
                "enrich findings with CVE details and exploit information.",
                route_method="direct",
            )

        return make_chat_response(
            agent=ComponentType.RESEARCHER,
            text="Researcher enrichment is available via the scan pipeline. "
            "Trigger it from the scan page or API to enrich findings with "
            "CVE details, exploit availability, and vendor advisories. "
            "Use `POST /api/v1/research/{scan_id}` to run enrichment.",
            route_method="direct",
        )

    async def _persist_and_send(
        self,
        session_id: str,
        engagement_id: str | None,
        msg: dict,
        route_method: str | None,
        agent_type: str | None = None,
    ) -> None:
        """Persist an agent/system message and push it to SSE."""
        await self.repo.save_message(
            msg_id=msg["id"],
            session_id=session_id,
            direction="agent",
            text=msg["text"],
            agent_type=agent_type or msg.get("agent"),
            engagement_id=engagement_id,
            route_method=route_method,
            references=msg.get("references"),
            actions=msg.get("actions"),
        )
        await self.sse.send(session_id, "chat_response", msg)


# ═══════════════════════════════════════════════════════════════════════════════
# Module-level singleton
# ═══════════════════════════════════════════════════════════════════════════════

sse_manager = SSEManager()
chat_repo = ChatRepository()
chat_dispatcher = ChatDispatcher(sse_manager, chat_repo)
