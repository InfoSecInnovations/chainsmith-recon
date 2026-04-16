"""
app/engine/prompt_router.py - Intent Classification & Agent Dispatch

Classifies operator messages and routes them to the correct agent using
a three-layer strategy:
  1. Context routing  — UI state (zero cost)
  2. Keyword routing  — pattern matching (zero cost)
  3. LLM fallback     — small/fast model classification

The Prompt Router is invisible infrastructure. It is NOT a component —
it does not appear in ComponentType, emit events, or generate substantive
responses. It classifies and dispatches.
"""

from __future__ import annotations

import logging
import re

from app.lib.llm import LLMClient
from app.models import ComponentType, RouteDecision

logger = logging.getLogger(__name__)

# ─── Confidence threshold ────────────────────────────────────────
# Below this, the router asks the operator to clarify instead of guessing.
LLM_CONFIDENCE_THRESHOLD = 0.6

# ─── Layer 1: Context routing table ─────────────────────────────

_CONTEXT_ROUTES: dict[str, ComponentType] = {
    "scope": ComponentType.SCAN_PLANNER_ADVISOR,
    "scoping": ComponentType.SCAN_PLANNER_ADVISOR,
    "triage": ComponentType.TRIAGE,
    "adjudication": ComponentType.ADJUDICATOR,
    "observation_detail": ComponentType.VERIFIER,
    "observations": ComponentType.VERIFIER,
    "chains": ComponentType.CHAINSMITH,
}

# ─── Layer 2: Keyword routing table ─────────────────────────────
# Each entry: (compiled regex pattern, target agent)
# Patterns are checked in order; first match wins.

_KEYWORD_RULES: list[tuple[re.Pattern[str], ComponentType]] = [
    # ScanPlannerAdvisor — pre-scan scoping guidance (Phase 41, migrated from Coach)
    (
        re.compile(r"\b(scope|target|exclude|exclusion|timeframe)\b", re.I),
        ComponentType.SCAN_PLANNER_ADVISOR,
    ),
    # Chainsmith — chain building
    (re.compile(r"\b(chain|attack path|attack chain|link)\b", re.I), ComponentType.CHAINSMITH),
    # Chainsmith — check ecosystem management
    (
        re.compile(
            r"\b(validate checks|check graph|custom check|scaffold|disable check|upstream diff|check health)\b",
            re.I,
        ),
        ComponentType.CHAINSMITH,
    ),
    # Adjudicator
    (
        re.compile(r"\b(severity|risk|adjudicat\w*|score|re-?score)\b", re.I),
        ComponentType.ADJUDICATOR,
    ),
    # Verifier
    (
        re.compile(r"\b(verify|verif\w*|check if|is this real|hallucination)\b", re.I),
        ComponentType.VERIFIER,
    ),
    # Triage
    (
        re.compile(
            r"\b(prioriti[zs]\w*|fix first|remediat\w*|action plan|quick win|triage)\b", re.I
        ),
        ComponentType.TRIAGE,
    ),
    # CheckProofAdvisor
    (
        re.compile(r"\b(proof|reproduce|reproduction|evidence|exploit)\b", re.I),
        ComponentType.CHECK_PROOF_ADVISOR,
    ),
    # ScanAnalysisAdvisor — post-scan coverage and gap analysis
    (
        re.compile(r"\b(coverage|gaps|what checks|missed|scan advice|recommendations)\b", re.I),
        ComponentType.SCAN_ANALYSIS_ADVISOR,
    ),
    # Coach — explanations and learning
    (
        re.compile(
            r"\b(explain|what is|what does|why did|how does|teach|help me understand)\b", re.I
        ),
        ComponentType.COACH,
    ),
    # Researcher — enrichment and lookups
    (
        re.compile(r"\b(research|enrich|look ?up|cve detail|exploit db|advisory)\b", re.I),
        ComponentType.RESEARCHER,
    ),
]

# ─── Layer 3: LLM classification prompt ─────────────────────────

_CLASSIFICATION_SYSTEM = """\
You are a message classifier for a security reconnaissance platform.
Classify the operator's message to determine which agent should handle it.

Available agents:
- chainsmith: Attack chain building, check ecosystem management (validate graph, custom checks, upstream diffs, disable impact)
- verifier: Fact-checking observations, re-verification requests
- adjudicator: Risk severity scoring, re-scoring, risk acceptance
- triage: Remediation prioritization, action planning, fix ordering
- check_proof_advisor: Reproduction steps, evidence collection, exploit guidance
- scan_analysis_advisor: Post-scan coverage gaps, missed checks, follow-up recommendations
- scan_planner_advisor: Pre-scan scope planning, check selection guidance, scan readiness
- researcher: CVE enrichment, vulnerability lookups, exploit availability
- coach: Explanations, security concepts, understanding findings and platform behavior

Respond with ONLY a JSON object: {"agent": "<name>", "confidence": <0.0-1.0>}
No other text."""

_CLASSIFICATION_PROMPT = """\
Operator message: "{message}"
UI context: {ui_context}

Classify this message. Respond with ONLY: {{"agent": "<name>", "confidence": <float>}}"""


class PromptRouter:
    """Classifies operator intent and routes to the correct agent.

    Not an agent — invisible infrastructure for the chat system (Phase 35).
    """

    def __init__(self, client: LLMClient):
        self.client = client

    async def route(
        self,
        message: str,
        ui_context: dict[str, str] | None = None,
    ) -> RouteDecision:
        """Classify and route an operator message.

        Layers are tried in order: context → keyword → LLM.
        Returns a RouteDecision with the target agent (or None if
        clarification is needed).
        """
        # Layer 1: context routing
        if ui_context:
            decision = self._context_route(ui_context)
            if decision is not None:
                return decision

        # Layer 2: keyword routing
        decision = self._keyword_route(message)
        if decision is not None:
            return decision

        # Layer 3: LLM fallback
        return await self._llm_route(message, ui_context)

    # ─── Layer 1 ────────────────────────────────────────────────

    def _context_route(self, ui_context: dict[str, str]) -> RouteDecision | None:
        """Route based on UI state. Returns None if no match."""
        # Check active_panel first, then page
        for key in ("active_panel", "page"):
            value = ui_context.get(key, "").lower()
            if value and value in _CONTEXT_ROUTES:
                return RouteDecision(
                    target=_CONTEXT_ROUTES[value],
                    method="context",
                    confidence=1.0,
                )
        return None

    # ─── Layer 2 ────────────────────────────────────────────────

    def _keyword_route(self, message: str) -> RouteDecision | None:
        """Route based on keyword pattern matching. Returns None if no match."""
        matches: dict[ComponentType, int] = {}
        for pattern, agent in _KEYWORD_RULES:
            if pattern.search(message):
                matches[agent] = matches.get(agent, 0) + 1

        if not matches:
            return None

        # Single agent matched — high confidence
        if len(matches) == 1:
            agent = next(iter(matches))
            return RouteDecision(
                target=agent,
                method="keyword",
                confidence=1.0,
            )

        # Multiple agents matched — pick the one with most keyword hits,
        # but lower confidence
        best = max(matches, key=matches.get)  # type: ignore[arg-type]
        return RouteDecision(
            target=best,
            method="keyword",
            confidence=0.7,
        )

    # ─── Layer 3 ────────────────────────────────────────────────

    async def _llm_route(
        self,
        message: str,
        ui_context: dict[str, str] | None,
    ) -> RouteDecision:
        """LLM fallback classification."""
        import json as _json

        ctx_str = _json.dumps(ui_context) if ui_context else "none"
        prompt = _CLASSIFICATION_PROMPT.format(message=message, ui_context=ctx_str)

        response = await self.client.chat(
            prompt=prompt,
            system=_CLASSIFICATION_SYSTEM,
            temperature=0.0,
            max_tokens=60,
        )

        if not response.success:
            logger.warning("LLM classification failed: %s", response.error)
            return RouteDecision(
                target=None,
                method="llm",
                confidence=0.0,
                needs_clarification=True,
                clarification_prompt=(
                    "I wasn't able to determine which agent should handle that. "
                    "Could you clarify what you'd like to do?"
                ),
            )

        return self._parse_llm_response(response.content)

    def _parse_llm_response(self, content: str) -> RouteDecision:
        """Parse the LLM classification response."""
        import json as _json

        # Strip markdown fences if present
        cleaned = content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            cleaned = "\n".join(lines).strip()

        try:
            data = _json.loads(cleaned)
        except (ValueError, _json.JSONDecodeError):
            logger.warning("LLM returned unparseable classification: %s", content[:200])
            return RouteDecision(
                target=None,
                method="llm",
                confidence=0.0,
                needs_clarification=True,
                clarification_prompt=(
                    "I wasn't able to determine which agent should handle that. "
                    "Could you clarify what you'd like to do?"
                ),
            )

        agent_name = data.get("agent", "").lower().strip()
        confidence = float(data.get("confidence", 0.0))

        # Map agent name to ComponentType
        component_map: dict[str, ComponentType] = {
            "chainsmith": ComponentType.CHAINSMITH,
            "verifier": ComponentType.VERIFIER,
            "adjudicator": ComponentType.ADJUDICATOR,
            "triage": ComponentType.TRIAGE,
            "check_proof_advisor": ComponentType.CHECK_PROOF_ADVISOR,
            "scan_analysis_advisor": ComponentType.SCAN_ANALYSIS_ADVISOR,
            "scan_planner_advisor": ComponentType.SCAN_PLANNER_ADVISOR,
            "researcher": ComponentType.RESEARCHER,
            "coach": ComponentType.COACH,
        }

        agent = component_map.get(agent_name)

        if agent is None or confidence < LLM_CONFIDENCE_THRESHOLD:
            return RouteDecision(
                target=agent,
                method="llm",
                confidence=confidence,
                needs_clarification=True,
                clarification_prompt=(
                    "I'm not sure which agent should handle that. "
                    "Could you rephrase or specify what you'd like to do?"
                ),
            )

        return RouteDecision(
            target=agent,
            method="llm",
            confidence=confidence,
        )
