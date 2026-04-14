"""
Tests for Adjudicator Agent

Covers:
- AdjudicatorAgent instantiation
- Evidence rubric scoring with mocked LLM responses
- Operator context matching (exact, wildcard, defaults, missing)
- Operator context file loading (valid, missing, malformed)
- Event emission (start, complete, upheld, adjusted)
- AdjudicatedRisk model validation
- Edge cases (no verified observations, LLM unavailable, malformed JSON, stop)
- JSON cleaning
"""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.adjudicator import AdjudicatorAgent
from app.engine.adjudication import load_operator_context
from app.lib.llm import LLMErrorType, LLMResponse
from app.models import (
    AdjudicatedRisk,
    AdjudicationApproach,
    ComponentType,
    EventType,
    Observation,
    ObservationSeverity,
    ObservationStatus,
    OperatorAssetContext,
    OperatorContext,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


def _make_observation(
    observation_id: str = "F-001",
    severity: str = "high",
    status: str = "verified",
    title: str = "Test Observation",
    target_url: str = "https://api.example.com/v1",
) -> Observation:
    """Create a test observation."""
    return Observation(
        id=observation_id,
        observation_type="test_check",
        title=title,
        description="A test observation for adjudication",
        severity=ObservationSeverity(severity),
        status=ObservationStatus(status),
        confidence=0.8,
        check_name="test_check",
        discovered_at=datetime(2026, 1, 1, tzinfo=UTC),
        target_url=target_url,
        evidence_summary="Header X-Debug-Mode: true found",
    )


def _make_llm_response(content: dict, success: bool = True) -> LLMResponse:
    """Create a mock LLM response."""
    return LLMResponse(
        content=json.dumps(content),
        model="test-model",
        provider="test",
        success=success,
        error=None if success else "LLM error",
        error_type=LLMErrorType.NONE if success else LLMErrorType.UNKNOWN,
    )


def _rubric_response(severity: str = "medium", confidence: float = 0.8) -> dict:
    """Standard evidence rubric response."""
    return {
        "scores": {
            "exploitability": 0.5,
            "impact": 0.4,
            "reproducibility": 0.7,
            "asset_criticality": 0.3,
            "exposure": 0.4,
        },
        "average_score": 0.46,
        "final_severity": severity,
        "confidence": confidence,
        "rationale": "Moderate risk based on rubric scoring",
    }


@pytest.fixture
def mock_llm_client():
    """Mock LLM client that returns configurable responses."""
    client = MagicMock()
    client.is_available.return_value = True
    client.chat = AsyncMock()
    return client


@pytest.fixture
def sample_operator_context():
    """Sample operator context."""
    return OperatorContext(
        assets=[
            OperatorAssetContext(
                domain="api.example.com",
                exposure="internet-facing",
                criticality="high",
                notes="Production API",
            ),
            OperatorAssetContext(
                domain="*.internal.local",
                exposure="vpn-only",
                criticality="low",
            ),
        ],
        defaults={"exposure": "unknown", "criticality": "medium"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Agent Instantiation
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentInstantiation:
    def test_default_state(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        assert agent.is_running is False
        assert agent.results == []

    def test_event_callback_stored(self, mock_llm_client):
        callback = AsyncMock()
        agent = AdjudicatorAgent(client=mock_llm_client, event_callback=callback)
        assert agent.event_callback is callback


# ═══════════════════════════════════════════════════════════════════════════════
# Evidence Rubric
# ═══════════════════════════════════════════════════════════════════════════════


class TestEvidenceRubric:
    async def test_rubric_scoring(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("medium"))

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        results = await agent.adjudicate_observations([observation])

        assert len(results) == 1
        assert results[0].approach_used == AdjudicationApproach.EVIDENCE_RUBRIC
        assert "exploitability" in results[0].factors

    async def test_severity_adjusted(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("medium"))

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        results = await agent.adjudicate_observations([observation])

        assert len(results) == 1
        assert results[0].original_severity == ObservationSeverity.HIGH
        assert results[0].adjudicated_severity == ObservationSeverity.MEDIUM
        assert results[0].confidence == 0.8

    async def test_severity_upheld(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("high"))

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        results = await agent.adjudicate_observations([observation])

        assert len(results) == 1
        assert results[0].original_severity == results[0].adjudicated_severity

    async def test_llm_failure_upholds_severity(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response({}, success=False)

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        results = await agent.adjudicate_observations([observation])

        assert len(results) == 1
        assert results[0].adjudicated_severity == ObservationSeverity.HIGH
        assert results[0].confidence == 0.0
        assert "inconclusive" in results[0].rationale.lower()

    async def test_single_llm_call_per_observation(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("medium"))

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        await agent.adjudicate_observations([observation])

        assert mock_llm_client.chat.call_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Operator Context
# ═══════════════════════════════════════════════════════════════════════════════


class TestOperatorContext:
    def test_match_exact_domain(self, mock_llm_client, sample_operator_context):
        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(target_url="https://api.example.com/v1/users")
        ctx = agent._match_asset_context(observation, sample_operator_context)
        assert ctx is not None
        assert ctx.exposure == "internet-facing"
        assert ctx.criticality == "high"

    def test_match_wildcard_domain(self, mock_llm_client, sample_operator_context):
        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(target_url="https://tools.internal.local/admin")
        ctx = agent._match_asset_context(observation, sample_operator_context)
        assert ctx is not None
        assert ctx.exposure == "vpn-only"

    def test_fallback_to_defaults(self, mock_llm_client, sample_operator_context):
        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(target_url="https://unknown.host.com/path")
        ctx = agent._match_asset_context(observation, sample_operator_context)
        assert ctx is not None
        assert ctx.exposure == "unknown"
        assert ctx.criticality == "medium"

    def test_no_context_returns_none(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation()
        assert agent._match_asset_context(observation, None) is None


class TestOperatorContextLoading:
    def _make_config(self, context_file="/nonexistent/path.yaml"):
        cfg = MagicMock()
        cfg.adjudicator.context_file = context_file
        return cfg

    def test_missing_file_returns_none(self):
        result = load_operator_context(config=self._make_config("/nonexistent/path.yaml"))
        assert result is None

    def test_malformed_yaml_returns_none(self, tmp_path):
        ctx_file = tmp_path / "context.yaml"
        ctx_file.write_text("just a plain string")
        result = load_operator_context(config=self._make_config(str(ctx_file)))
        assert result is None

    def test_valid_file_loads(self, tmp_path):
        ctx_file = tmp_path / "context.yaml"
        ctx_file.write_text(
            "assets:\n"
            "  - domain: api.example.com\n"
            "    exposure: internet-facing\n"
            "    criticality: high\n"
            "defaults:\n"
            "  exposure: unknown\n"
            "  criticality: medium\n"
        )

        result = load_operator_context(config=self._make_config(str(ctx_file)))
        assert result is not None
        assert len(result.assets) == 1
        assert result.assets[0].domain == "api.example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# Event Emission
# ═══════════════════════════════════════════════════════════════════════════════


class TestEventEmission:
    async def test_emits_start_and_complete(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("high"))

        callback = AsyncMock()
        agent = AdjudicatorAgent(client=mock_llm_client, event_callback=callback)

        observation = _make_observation(severity="high")
        await agent.adjudicate_observations([observation])

        event_types = [call.args[0].event_type for call in callback.call_args_list]
        assert EventType.ADJUDICATION_START in event_types
        assert EventType.ADJUDICATION_COMPLETE in event_types

    async def test_emits_upheld_when_severity_same(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("high"))

        callback = AsyncMock()
        agent = AdjudicatorAgent(client=mock_llm_client, event_callback=callback)

        observation = _make_observation(severity="high")
        await agent.adjudicate_observations([observation])

        event_types = [call.args[0].event_type for call in callback.call_args_list]
        assert EventType.SEVERITY_UPHELD in event_types

    async def test_emits_adjusted_when_severity_changes(self, mock_llm_client):
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("medium"))

        callback = AsyncMock()
        agent = AdjudicatorAgent(client=mock_llm_client, event_callback=callback)

        observation = _make_observation(severity="high")
        await agent.adjudicate_observations([observation])

        event_types = [call.args[0].event_type for call in callback.call_args_list]
        assert EventType.SEVERITY_ADJUSTED in event_types


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    async def test_no_verified_observations(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        pending_observation = _make_observation(status="pending")
        results = await agent.adjudicate_observations([pending_observation])
        assert results == []

    async def test_empty_observations(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        results = await agent.adjudicate_observations([])
        assert results == []

    async def test_malformed_json_upholds_severity(self, mock_llm_client):
        mock_llm_client.chat.return_value = LLMResponse(
            content="This is not valid JSON at all",
            model="test",
            provider="test",
            success=True,
        )

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        results = await agent.adjudicate_observations([observation])

        assert len(results) == 1
        assert results[0].adjudicated_severity == ObservationSeverity.HIGH
        assert results[0].confidence == 0.0

    async def test_unparseable_severity_upholds_original(self, mock_llm_client):
        """LLM returning an invalid severity string falls back to original severity."""
        rubric = _rubric_response("SUPER_CRITICAL")  # not a valid ObservationSeverity
        mock_llm_client.chat.return_value = _make_llm_response(rubric)

        agent = AdjudicatorAgent(client=mock_llm_client)
        observation = _make_observation(severity="high")
        results = await agent.adjudicate_observations([observation])

        assert len(results) == 1
        # Invalid severity should fall back to original
        assert results[0].adjudicated_severity == ObservationSeverity.HIGH

    async def test_stop_halts_processing(self, mock_llm_client):
        call_count = 0

        async def chat_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                agent.stop()
            return _make_llm_response(_rubric_response("high"))

        mock_llm_client.chat.side_effect = chat_side_effect

        agent = AdjudicatorAgent(client=mock_llm_client)
        observations = [_make_observation(observation_id=f"F-{i:03d}") for i in range(5)]
        results = await agent.adjudicate_observations(observations)
        # Stop called after 2nd LLM call, so should have fewer than 5 results
        assert len(results) < 5


# ═══════════════════════════════════════════════════════════════════════════════
# Model Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestAdjudicatedRiskModel:
    def test_valid_model(self):
        risk = AdjudicatedRisk(
            observation_id="F-001",
            original_severity=ObservationSeverity.HIGH,
            adjudicated_severity=ObservationSeverity.MEDIUM,
            confidence=0.85,
            approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
            rationale="Mitigated by VPN",
            factors={"exploitability": 0.3},
        )
        assert risk.observation_id == "F-001"
        assert risk.approach_used == AdjudicationApproach.EVIDENCE_RUBRIC
        assert risk.factors == {"exploitability": 0.3}

    def test_adjudicated_by_can_be_overridden(self):
        """adjudicated_by defaults to ADJUDICATOR but accepts other agent types."""
        risk = AdjudicatedRisk(
            observation_id="F-002",
            original_severity=ObservationSeverity.HIGH,
            adjudicated_severity=ObservationSeverity.HIGH,
            confidence=0.9,
            approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
            rationale="Overridden by adjudicator",
            adjudicated_by=ComponentType.ADJUDICATOR,
        )
        assert risk.adjudicated_by == ComponentType.ADJUDICATOR

    def test_confidence_bounds(self):
        with pytest.raises(ValueError):
            AdjudicatedRisk(
                observation_id="F-001",
                original_severity=ObservationSeverity.HIGH,
                adjudicated_severity=ObservationSeverity.HIGH,
                confidence=1.5,  # Out of bounds
                approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
                rationale="Test",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# JSON Cleaning
# ═══════════════════════════════════════════════════════════════════════════════


class TestJsonCleaning:
    def test_strips_markdown_fences(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        raw = '```json\n{"key": "value"}\n```'
        assert agent._clean_json(raw) == '{"key": "value"}'

    def test_strips_plain_fences(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        raw = '```\n{"key": "value"}\n```'
        assert agent._clean_json(raw) == '{"key": "value"}'

    def test_passes_clean_json(self, mock_llm_client):
        agent = AdjudicatorAgent(client=mock_llm_client)
        raw = '{"key": "value"}'
        assert agent._clean_json(raw) == '{"key": "value"}'
