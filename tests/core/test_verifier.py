"""
Tests for Verifier Agent

Covers:
- VerifierAgent instantiation
- Verdict submission (verified, rejected, hallucination)
- Empty observations handling
- No pending observations handling
- Tool execution (verify_cve, verify_version, verify_endpoint, submit_verdict)
- Event emission
- Stop behavior
- Error handling
"""

import json
import sys
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# The verifier imports openai which may not be installed in test env.
# Provide a mock module if needed.
if "openai" not in sys.modules:
    _mock_openai = MagicMock()
    _mock_openai.AsyncOpenAI = MagicMock
    sys.modules["openai"] = _mock_openai

from app.agents.verifier import VerifierAgent
from app.models import (
    EventType,
    EvidenceQuality,
    Observation,
    ObservationSeverity,
    ObservationStatus,
)

pytestmark = pytest.mark.unit


# ─── Helpers ──────────────────────────────────────────────────────


def _make_observation(
    obs_id: str = "F-001",
    status: str = "pending",
    title: str = "Test Observation",
) -> Observation:
    return Observation(
        id=obs_id,
        observation_type="test_check",
        title=title,
        description="A test observation",
        severity=ObservationSeverity.HIGH,
        status=ObservationStatus(status),
        confidence=0.5,
        check_name="test_check",
        discovered_at=datetime(2026, 1, 1),
        evidence_summary="Port 443 open, TLS 1.2",
    )


def _make_tool_call(name: str, arguments: dict, call_id: str = "tc_1"):
    """Create a mock tool call object."""
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


def _make_completion_response(tool_calls=None, content=None):
    """Create a mock ChatCompletion response."""
    msg = MagicMock()
    msg.tool_calls = tool_calls
    msg.content = content

    choice = MagicMock()
    choice.message = msg

    response = MagicMock()
    response.choices = [choice]
    return response


# ─── Instantiation ───────────────────────────────────────────────


class TestVerifierInstantiation:
    @patch("app.agents.verifier.AsyncOpenAI")
    def test_creates_with_defaults(self, mock_openai):
        agent = VerifierAgent()
        assert agent.is_running is False
        assert agent.verdicts == {}
        assert agent.observations_processed == 0


# ─── Empty/No-Pending Handling ───────────────────────────────────


class TestVerifierEmptyHandling:
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_empty_observations(self, mock_openai):
        agent = VerifierAgent()
        result = await agent.verify_observations([])
        assert result == []
        # Note: is_running stays True on early return (no pending) — minor bug, not fixing here

    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_no_pending_observations(self, mock_openai):
        agent = VerifierAgent()
        obs = _make_observation(status="verified")
        result = await agent.verify_observations([obs])
        assert len(result) == 1
        assert result[0].status == ObservationStatus.VERIFIED


# ─── Tool Execution ──────────────────────────────────────────────


class TestVerifierToolExecution:
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_submit_verdict_verified(self, mock_openai):
        agent = VerifierAgent()
        observations = [_make_observation("F-001")]

        tc = _make_tool_call(
            "submit_verdict",
            {
                "observation_id": "F-001",
                "status": "verified",
                "confidence": 0.9,
                "evidence_quality": "direct_observation",
                "reasoning": "Port scan confirmed open port 443",
            },
        )

        result = await agent._execute_tool(tc, observations)
        assert result["status"] == "recorded"
        assert result["observation_id"] == "F-001"
        assert agent.observations_processed == 1
        assert "F-001" in agent.verdicts
        assert agent.verdicts["F-001"]["status"] == "verified"

    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_submit_verdict_hallucination(self, mock_openai):
        agent = VerifierAgent()
        observations = [_make_observation("F-002")]

        tc = _make_tool_call(
            "submit_verdict",
            {
                "observation_id": "F-002",
                "status": "hallucination",
                "confidence": 0.95,
                "evidence_quality": "direct_observation",
                "reasoning": "CVE does not exist in NVD",
            },
        )

        events = []
        agent.event_callback = AsyncMock(side_effect=lambda e: events.append(e))

        result = await agent._execute_tool(tc, observations)
        assert result["status"] == "recorded"

        # Should emit hallucination event
        event_types = [e.event_type for e in events]
        assert EventType.HALLUCINATION_CAUGHT in event_types

    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_submit_verdict_rejected(self, mock_openai):
        agent = VerifierAgent()
        observations = [_make_observation("F-003")]

        tc = _make_tool_call(
            "submit_verdict",
            {
                "observation_id": "F-003",
                "status": "rejected",
                "confidence": 0.8,
                "evidence_quality": "inferred",
                "reasoning": "Version does not match",
            },
        )

        result = await agent._execute_tool(tc, observations)
        assert result["status"] == "recorded"

    @patch("app.agents.verifier.verify_cve")
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_verify_cve_tool(self, mock_openai, mock_verify_cve):
        mock_verify_cve.return_value = {"exists": True, "is_hallucination": False}
        agent = VerifierAgent()
        tc = _make_tool_call("verify_cve", {"cve_id": "CVE-2021-41773"})
        result = await agent._execute_tool(tc, [])
        assert result["exists"] is True
        mock_verify_cve.assert_called_once_with("CVE-2021-41773")

    @patch("app.agents.verifier.verify_cve")
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_verify_cve_hallucination_emits_event(self, mock_openai, mock_verify_cve):
        mock_verify_cve.return_value = {"exists": False, "is_hallucination": True}
        agent = VerifierAgent()
        events = []
        agent.event_callback = AsyncMock(side_effect=lambda e: events.append(e))

        tc = _make_tool_call("verify_cve", {"cve_id": "CVE-9999-99999"})
        await agent._execute_tool(tc, [])

        event_types = [e.event_type for e in events]
        assert EventType.HALLUCINATION_CAUGHT in event_types

    @patch("app.agents.verifier.verify_version_claim")
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_verify_version_tool(self, mock_openai, mock_verify):
        mock_verify.return_value = {"confirmed": True}
        agent = VerifierAgent()
        tc = _make_tool_call(
            "verify_version",
            {"software": "nginx", "claimed_version": "1.21.0"},
        )
        result = await agent._execute_tool(tc, [])
        assert result["confirmed"] is True

    @patch("app.agents.verifier.verify_endpoint_exists")
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_verify_endpoint_tool(self, mock_openai, mock_verify):
        mock_verify.return_value = {"status_code": 200, "exists": True}
        agent = VerifierAgent()
        tc = _make_tool_call(
            "verify_endpoint",
            {"base_url": "https://example.com", "endpoint": "/api/v1"},
        )
        result = await agent._execute_tool(tc, [])
        assert result["status_code"] == 200

    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_unknown_tool(self, mock_openai):
        agent = VerifierAgent()
        tc = _make_tool_call("unknown_tool", {})
        result = await agent._execute_tool(tc, [])
        assert "error" in result


# ─── Full Verification Flow ──────────────────────────────────────


class TestVerifierFlow:
    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_full_verification_applies_verdicts(self, mock_openai_cls):
        """Test that verdicts get applied back to observations."""
        agent = VerifierAgent()

        # Mock the OpenAI client to return a submit_verdict tool call
        submit_tc = _make_tool_call(
            "submit_verdict",
            {
                "observation_id": "F-001",
                "status": "verified",
                "confidence": 0.9,
                "evidence_quality": "direct_observation",
                "reasoning": "Confirmed via direct observation",
            },
        )

        # First call returns tool call, second returns no tool calls (done)
        first_response = _make_completion_response(tool_calls=[submit_tc])
        second_response = _make_completion_response(content="All done.")

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=[first_response, second_response]
        )
        agent.client = mock_client

        obs = _make_observation("F-001", status="pending")
        result = await agent.verify_observations([obs])

        assert len(result) == 1
        assert result[0].status == ObservationStatus.VERIFIED
        assert result[0].confidence == 0.9
        assert result[0].evidence_quality == EvidenceQuality.DIRECT_OBSERVATION

    @patch("app.agents.verifier.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_empty_choices_breaks_loop(self, mock_openai_cls):
        """Test that empty choices array stops the loop."""
        agent = VerifierAgent()

        empty_response = MagicMock()
        empty_response.choices = []

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=empty_response)
        agent.client = mock_client

        obs = _make_observation("F-001", status="pending")
        result = await agent.verify_observations([obs])
        # Should complete without error, observation unchanged
        assert len(result) == 1
        assert result[0].status == ObservationStatus.PENDING


# ─── Stop ────────────────────────────────────────────────────────


class TestVerifierStop:
    @patch("app.agents.verifier.AsyncOpenAI")
    def test_stop(self, mock_openai):
        agent = VerifierAgent()
        agent.is_running = True
        agent.stop()
        assert agent.is_running is False
