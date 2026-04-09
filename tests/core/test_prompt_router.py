"""
Tests for Prompt Router — Intent Classification & Agent Dispatch

Covers:
- Layer 1: Context routing (UI state → agent)
- Layer 2: Keyword routing (pattern matching → agent)
- Layer 3: LLM fallback classification
- Multi-layer fallthrough (context miss → keyword → LLM)
- Low-confidence LLM → needs_clarification
- LLM failure → needs_clarification
- Unparseable LLM response → needs_clarification
- Ambiguous keyword matches (multiple agents)
- Future agent routing (proof_advisor)
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.engine.prompt_router import PromptRouter, LLM_CONFIDENCE_THRESHOLD
from app.lib.llm import LLMResponse
from app.models import AgentType, RouteDecision

pytestmark = pytest.mark.unit


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def mock_client():
    """LLM client mock — not called unless Layer 3 is reached."""
    client = MagicMock()
    client.chat = AsyncMock()
    return client


@pytest.fixture
def router(mock_client):
    return PromptRouter(client=mock_client)


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 1: Context Routing
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextRouting:
    @pytest.mark.asyncio
    async def test_scope_panel_routes_to_chainsmith(self, router):
        decision = await router.route("anything", ui_context={"active_panel": "scope"})
        assert decision.target == AgentType.CHAINSMITH
        assert decision.method == "context"
        assert decision.confidence == 1.0

    @pytest.mark.asyncio
    async def test_triage_panel_routes_to_triage(self, router):
        decision = await router.route("anything", ui_context={"active_panel": "triage"})
        assert decision.target == AgentType.TRIAGE
        assert decision.method == "context"

    @pytest.mark.asyncio
    async def test_adjudication_panel_routes_to_adjudicator(self, router):
        decision = await router.route("anything", ui_context={"active_panel": "adjudication"})
        assert decision.target == AgentType.ADJUDICATOR
        assert decision.method == "context"

    @pytest.mark.asyncio
    async def test_observation_detail_routes_to_verifier(self, router):
        decision = await router.route("anything", ui_context={"active_panel": "observation_detail"})
        assert decision.target == AgentType.VERIFIER
        assert decision.method == "context"

    @pytest.mark.asyncio
    async def test_page_fallback_when_no_panel(self, router):
        decision = await router.route("anything", ui_context={"page": "triage"})
        assert decision.target == AgentType.TRIAGE
        assert decision.method == "context"

    @pytest.mark.asyncio
    async def test_panel_takes_precedence_over_page(self, router):
        decision = await router.route(
            "anything",
            ui_context={"active_panel": "scope", "page": "triage"},
        )
        assert decision.target == AgentType.CHAINSMITH

    @pytest.mark.asyncio
    async def test_unknown_context_falls_through(self, router, mock_client):
        """Unknown UI context should fall through to keyword/LLM layers."""
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "triage", "confidence": 0.9}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route(
            "prioritize fixes",
            ui_context={"active_panel": "dashboard"},
        )
        # Should have fallen through context → matched keyword
        assert decision.target == AgentType.TRIAGE
        assert decision.method == "keyword"


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 2: Keyword Routing
# ═══════════════════════════════════════════════════════════════════════════════


class TestKeywordRouting:
    @pytest.mark.asyncio
    async def test_scope_keywords(self, router):
        for word in ["scope", "target", "exclude", "exclusion", "timeframe"]:
            decision = await router.route(f"can you {word} this?")
            assert decision.target == AgentType.CHAINSMITH, f"Failed for '{word}'"
            assert decision.method == "keyword"

    @pytest.mark.asyncio
    async def test_chain_keywords(self, router):
        for phrase in ["attack chain", "attack path", "chain", "link"]:
            decision = await router.route(f"show me the {phrase}")
            assert decision.target == AgentType.CHAINSMITH, f"Failed for '{phrase}'"
            assert decision.method == "keyword"

    @pytest.mark.asyncio
    async def test_adjudicator_keywords(self, router):
        for word in ["severity", "risk", "adjudicate", "score", "re-score", "rescore"]:
            decision = await router.route(f"what is the {word}?")
            assert decision.target == AgentType.ADJUDICATOR, f"Failed for '{word}'"
            assert decision.method == "keyword"

    @pytest.mark.asyncio
    async def test_verifier_keywords(self, router):
        for phrase in ["verify", "check if", "is this real", "hallucination"]:
            decision = await router.route(f"can you {phrase} this observation")
            assert decision.target == AgentType.VERIFIER, f"Failed for '{phrase}'"
            assert decision.method == "keyword"

    @pytest.mark.asyncio
    async def test_triage_keywords(self, router):
        for phrase in ["prioritize", "fix first", "remediate", "action plan", "quick win"]:
            decision = await router.route(f"I want to {phrase}")
            assert decision.target == AgentType.TRIAGE, f"Failed for '{phrase}'"
            assert decision.method == "keyword"

    @pytest.mark.asyncio
    async def test_proof_advisor_keywords(self, router):
        for word in ["proof", "reproduce", "reproduction", "evidence"]:
            decision = await router.route(f"show me the {word}")
            assert decision.target == AgentType.PROOF_ADVISOR, f"Failed for '{word}'"
            assert decision.method == "keyword"

    @pytest.mark.asyncio
    async def test_no_keyword_match_falls_to_llm(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "chainsmith", "confidence": 0.95}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("hello, how are you?")
        assert decision.method == "llm"
        mock_client.chat.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ambiguous_keywords_picks_best(self, router):
        """Message with keywords matching multiple agents picks the one with most hits."""
        # "verify" → verifier, "risk" → adjudicator, "score" → adjudicator
        decision = await router.route("verify the risk score")
        assert decision.target == AgentType.ADJUDICATOR
        assert decision.confidence == 0.7  # reduced for ambiguous match

    @pytest.mark.asyncio
    async def test_case_insensitive(self, router):
        decision = await router.route("PRIORITIZE the REMEDIATION")
        assert decision.target == AgentType.TRIAGE


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 3: LLM Fallback
# ═══════════════════════════════════════════════════════════════════════════════


class TestLLMRouting:
    @pytest.mark.asyncio
    async def test_successful_classification(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "adjudicator", "confidence": 0.92}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("how bad is this finding?")
        assert decision.target == AgentType.ADJUDICATOR
        assert decision.method == "llm"
        assert decision.confidence == 0.92
        assert not decision.needs_clarification

    @pytest.mark.asyncio
    async def test_low_confidence_asks_user(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "triage", "confidence": 0.3}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("what do you think?")
        assert decision.needs_clarification is True
        assert decision.clarification_prompt is not None
        assert decision.confidence == 0.3

    @pytest.mark.asyncio
    async def test_confidence_at_threshold_passes(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content=json.dumps({"agent": "triage", "confidence": LLM_CONFIDENCE_THRESHOLD}),
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("what do you think?")
        assert decision.target == AgentType.TRIAGE
        assert not decision.needs_clarification

    @pytest.mark.asyncio
    async def test_confidence_below_threshold_clarifies(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content=json.dumps({"agent": "triage", "confidence": LLM_CONFIDENCE_THRESHOLD - 0.01}),
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("hmm")
        assert decision.needs_clarification is True

    @pytest.mark.asyncio
    async def test_llm_failure_asks_user(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content="",
            model="test",
            provider="test",
            success=False,
            error="Timeout",
        )
        decision = await router.route("something unclear")
        assert decision.needs_clarification is True
        assert decision.target is None
        assert decision.confidence == 0.0

    @pytest.mark.asyncio
    async def test_unparseable_llm_response(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content="I think you should use the adjudicator",
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("do something")
        assert decision.needs_clarification is True
        assert decision.target is None

    @pytest.mark.asyncio
    async def test_unknown_agent_name(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "nonexistent_agent", "confidence": 0.99}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("do something")
        assert decision.needs_clarification is True

    @pytest.mark.asyncio
    async def test_llm_response_with_markdown_fences(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='```json\n{"agent": "verifier", "confidence": 0.85}\n```',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("is this observation real?")
        assert decision.target == AgentType.VERIFIER
        assert not decision.needs_clarification

    @pytest.mark.asyncio
    async def test_llm_prompt_includes_message_and_context(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "triage", "confidence": 0.8}',
            model="test",
            provider="test",
            success=True,
        )
        await router.route(
            "what now?",
            ui_context={"page": "dashboard", "active_panel": "overview"},
        )
        call_kwargs = mock_client.chat.call_args
        prompt = call_kwargs.kwargs.get("prompt", call_kwargs.args[0] if call_kwargs.args else "")
        assert "what now?" in prompt
        assert "dashboard" in prompt

    @pytest.mark.asyncio
    async def test_llm_uses_low_temperature(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "triage", "confidence": 0.8}',
            model="test",
            provider="test",
            success=True,
        )
        await router.route("something")
        call_kwargs = mock_client.chat.call_args.kwargs
        assert call_kwargs.get("temperature") == 0.0
        assert call_kwargs.get("max_tokens") == 60


# ═══════════════════════════════════════════════════════════════════════════════
# Layer Fallthrough
# ═══════════════════════════════════════════════════════════════════════════════


class TestLayerFallthrough:
    @pytest.mark.asyncio
    async def test_context_match_skips_keyword_and_llm(self, router, mock_client):
        decision = await router.route(
            "prioritize fixes",  # keyword would match triage
            ui_context={"active_panel": "scope"},  # context matches chainsmith
        )
        assert decision.target == AgentType.CHAINSMITH
        assert decision.method == "context"
        mock_client.chat.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_keyword_match_skips_llm(self, router, mock_client):
        decision = await router.route("what is the severity?")
        assert decision.target == AgentType.ADJUDICATOR
        assert decision.method == "keyword"
        mock_client.chat.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_context_no_keyword_hits_llm(self, router, mock_client):
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "chainsmith", "confidence": 0.8}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("hello")
        assert decision.method == "llm"
        mock_client.chat.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_context_provided_skips_layer1(self, router, mock_client):
        """Passing no ui_context should skip context routing entirely."""
        mock_client.chat.return_value = LLMResponse(
            content='{"agent": "triage", "confidence": 0.8}',
            model="test",
            provider="test",
            success=True,
        )
        decision = await router.route("hello")
        assert decision.method == "llm"


# ═══════════════════════════════════════════════════════════════════════════════
# RouteDecision Model
# ═══════════════════════════════════════════════════════════════════════════════


class TestRouteDecisionModel:
    def test_basic_construction(self):
        rd = RouteDecision(
            target=AgentType.TRIAGE,
            method="keyword",
        )
        assert rd.target == AgentType.TRIAGE
        assert rd.confidence == 1.0
        assert rd.needs_clarification is False
        assert rd.redirect_message is None
        assert rd.clarification_prompt is None

    def test_clarification_decision(self):
        rd = RouteDecision(
            target=None,
            method="llm",
            confidence=0.2,
            needs_clarification=True,
            clarification_prompt="Please clarify.",
        )
        assert rd.target is None
        assert rd.needs_clarification is True

    def test_serialization(self):
        rd = RouteDecision(
            target=AgentType.CHAINSMITH,
            method="context",
            redirect_message="Passing to scope manager.",
        )
        data = rd.model_dump()
        assert data["target"] == "chainsmith"
        assert data["method"] == "context"
        assert data["redirect_message"] == "Passing to scope manager."
