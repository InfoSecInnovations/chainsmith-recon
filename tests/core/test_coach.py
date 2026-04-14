"""
Tests for Coach Agent

Covers:
- CoachAgent instantiation
- Successful question answering with mocked LLM
- LLM unavailable returns friendly message
- LLM call failure returns error message
- Session memory (stored, capped, cleared)
- Context building (observations, chains, events, scope)
- Event emission
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.agents.coach import CoachAgent
from app.lib.llm import LLMResponse
from app.models import (
    AttackChain,
    EventType,
    Observation,
    ObservationSeverity,
    ObservationStatus,
)

pytestmark = pytest.mark.unit


# ─── Helpers ──────────────────────────────────────────────────────


def _make_client(available: bool = True, content: str = "Coach says hello", success: bool = True):
    """Create a mock LLMClient."""
    from unittest.mock import MagicMock

    client = MagicMock()
    client.is_available.return_value = available
    client.chat = AsyncMock(
        return_value=LLMResponse(
            content=content,
            model="test-model",
            provider="test",
            success=success,
            error=None if success else "LLM error",
        )
    )
    return client


def _make_observation(obs_id: str = "F-001", title: str = "Test Obs") -> Observation:
    return Observation(
        id=obs_id,
        observation_type="test_check",
        title=title,
        description="desc",
        severity=ObservationSeverity.HIGH,
        status=ObservationStatus.VERIFIED,
        confidence=0.8,
        check_name="test_check",
        discovered_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _make_chain(chain_id: str = "C-001") -> AttackChain:
    return AttackChain(
        id=chain_id,
        title="Test Chain",
        description="Test attack chain",
        combined_severity=ObservationSeverity.CRITICAL,
        attack_steps=["step1", "step2"],
        observation_ids=["F-001"],
        prerequisites=["network access"],
        impact_statement="Full compromise possible",
        individual_severities=[ObservationSeverity.HIGH],
        severity_reasoning="Multiple high-severity findings chain together",
    )


# ─── Instantiation ───────────────────────────────────────────────


class TestCoachInstantiation:
    def test_creates_with_defaults(self):
        client = _make_client()
        coach = CoachAgent(client)
        assert coach.client is client
        assert coach.memory_cap == 10
        assert len(coach._memory) == 0

    def test_custom_memory_cap(self):
        coach = CoachAgent(_make_client(), memory_cap=5)
        assert coach.memory_cap == 5


# ─── Question Answering ──────────────────────────────────────────


class TestCoachAsk:
    @pytest.mark.asyncio
    async def test_successful_answer(self):
        client = _make_client(content="  The answer is 42.  ")
        coach = CoachAgent(client)
        result = await coach.ask("What is the answer?")
        assert result == "The answer is 42."
        client.chat.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_unavailable(self):
        client = _make_client(available=False)
        coach = CoachAgent(client)
        result = await coach.ask("Hello?")
        assert "LLM provider" in result
        client.chat.assert_not_called()

    @pytest.mark.asyncio
    async def test_llm_call_failure(self):
        client = _make_client(success=False)
        coach = CoachAgent(client)
        result = await coach.ask("Hello?")
        assert "trouble responding" in result

    @pytest.mark.asyncio
    async def test_answer_with_observations(self):
        client = _make_client(content="Found 1 observation.")
        coach = CoachAgent(client)
        obs = [_make_observation()]
        result = await coach.ask("What did we find?", observations=obs)
        assert result == "Found 1 observation."
        # Check that observation context was included in the prompt
        call_args = client.chat.call_args
        assert "F-001" in call_args.kwargs.get(
            "prompt", call_args.args[0] if call_args.args else ""
        )

    @pytest.mark.asyncio
    async def test_answer_with_chains(self):
        client = _make_client(content="One chain found.")
        coach = CoachAgent(client)
        chains = [_make_chain()]
        result = await coach.ask("What chains?", chains=chains)
        assert result == "One chain found."


# ─── Memory ──────────────────────────────────────────────────────


class TestCoachMemory:
    @pytest.mark.asyncio
    async def test_memory_stores_exchange(self):
        client = _make_client(content="Answer 1")
        coach = CoachAgent(client)
        await coach.ask("Question 1")
        assert len(coach._memory) == 1
        assert coach._memory[0]["question"] == "Question 1"
        assert coach._memory[0]["answer"] == "Answer 1"

    @pytest.mark.asyncio
    async def test_memory_capped(self):
        client = _make_client(content="Answer")
        coach = CoachAgent(client, memory_cap=3)
        for i in range(5):
            client.chat.return_value = LLMResponse(
                content=f"Answer {i}", model="test", provider="test", success=True
            )
            await coach.ask(f"Q{i}")
        assert len(coach._memory) == 3
        # Oldest exchanges should have been dropped
        assert coach._memory[0]["question"] == "Q2"

    @pytest.mark.asyncio
    async def test_memory_not_stored_on_failure(self):
        client = _make_client(success=False)
        coach = CoachAgent(client)
        await coach.ask("Will fail")
        assert len(coach._memory) == 0

    def test_clear_memory(self):
        client = _make_client()
        coach = CoachAgent(client)
        coach._memory.append({"question": "Q", "answer": "A"})
        coach.clear_memory()
        assert len(coach._memory) == 0


# ─── Context Building ────────────────────────────────────────────


class TestCoachContextBuilding:
    def test_empty_context(self):
        coach = CoachAgent(_make_client())
        ctx = coach._build_context(None, None, None, None)
        assert "No scan data available" in ctx

    def test_scope_summary(self):
        coach = CoachAgent(_make_client())
        ctx = coach._build_context(None, None, None, "target: example.com")
        assert "CURRENT SCOPE" in ctx
        assert "example.com" in ctx

    def test_observations_context(self):
        coach = CoachAgent(_make_client())
        obs = [_make_observation("F-001", "SQL Injection")]
        ctx = coach._build_context(obs, None, None, None)
        assert "OBSERVATIONS" in ctx
        assert "F-001" in ctx
        assert "SQL Injection" in ctx

    def test_chains_context(self):
        coach = CoachAgent(_make_client())
        chains = [_make_chain("C-001")]
        ctx = coach._build_context(None, chains, None, None)
        assert "ATTACK CHAINS" in ctx
        assert "C-001" in ctx

    def test_events_context(self):
        coach = CoachAgent(_make_client())
        events = [{"event_type": "INFO", "message": "Scan started"}]
        ctx = coach._build_context(None, None, events, None)
        assert "RECENT EVENTS" in ctx
        assert "Scan started" in ctx


# ─── Event Emission ──────────────────────────────────────────────


class TestCoachEvents:
    @pytest.mark.asyncio
    async def test_emits_start_and_complete_on_success(self):
        client = _make_client(content="OK")
        events = []
        coach = CoachAgent(client, event_callback=AsyncMock(side_effect=lambda e: events.append(e)))
        await coach.ask("Hi")
        event_types = [e.event_type for e in events]
        assert EventType.AGENT_START in event_types
        assert EventType.AGENT_COMPLETE in event_types

    @pytest.mark.asyncio
    async def test_emits_complete_when_unavailable(self):
        client = _make_client(available=False)
        events = []
        coach = CoachAgent(client, event_callback=AsyncMock(side_effect=lambda e: events.append(e)))
        await coach.ask("Hi")
        event_types = [e.event_type for e in events]
        assert EventType.AGENT_COMPLETE in event_types
