"""
Tests for Phase 21a Adjudicator Agent

Covers:
- AdjudicatorAgent instantiation and approach defaults
- Auto tiering logic (severity -> approach mapping)
- Each approach with mocked LLM responses
- Operator context loading (file exists, missing, malformed)
- Event emission (correct types and counts)
- AdjudicatedRisk model validation
- Edge cases (no verified findings, LLM unavailable, all upheld)
- Approach resolution priority
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agents.adjudicator import AdjudicatorAgent
from app.engine.adjudication import load_operator_context, resolve_approach
from app.lib.llm import LLMErrorType, LLMResponse
from app.models import (
    AdjudicatedRisk,
    AdjudicationApproach,
    AgentType,
    EventType,
    Finding,
    FindingSeverity,
    FindingStatus,
    OperatorAssetContext,
    OperatorContext,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


def _make_finding(
    finding_id: str = "F-001",
    severity: str = "high",
    status: str = "verified",
    title: str = "Test Finding",
    target_url: str = "https://api.example.com/v1",
) -> Finding:
    """Create a test finding."""
    return Finding(
        id=finding_id,
        finding_type="test_check",
        title=title,
        description="A test finding for adjudication",
        severity=FindingSeverity(severity),
        status=FindingStatus(status),
        confidence=0.8,
        discovered_by=AgentType.SCOUT,
        discovered_at=datetime(2026, 1, 1),
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


def _challenge_response(severity: str = "medium", confidence: float = 0.85) -> dict:
    """Standard structured challenge response."""
    return {
        "challenge_argument": "The severity seems overstated given context",
        "final_severity": severity,
        "confidence": confidence,
        "rationale": "Finding is valid but mitigated by VPN access requirement",
        "factors": {
            "attack_vector": "network",
            "complexity": "high",
            "privileges_required": "low",
            "impact": "medium",
        },
    }


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

    @patch("app.agents.adjudicator.get_llm_client")
    def test_default_approach_is_auto(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        assert agent.approach == AdjudicationApproach.AUTO

    @patch("app.agents.adjudicator.get_llm_client")
    def test_explicit_approach(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent(approach=AdjudicationApproach.ADVERSARIAL_DEBATE)
        assert agent.approach == AdjudicationApproach.ADVERSARIAL_DEBATE

    @patch("app.agents.adjudicator.get_llm_client")
    def test_event_callback_stored(self, mock_get):
        mock_get.return_value = MagicMock()
        callback = AsyncMock()
        agent = AdjudicatorAgent(event_callback=callback)
        assert agent.event_callback is callback


# ═══════════════════════════════════════════════════════════════════════════════
# Auto Tiering
# ═══════════════════════════════════════════════════════════════════════════════


class TestAutoTiering:

    @patch("app.agents.adjudicator.get_llm_client")
    def test_critical_uses_adversarial(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(severity="critical")
        assert agent._resolve_approach(finding) == AdjudicationApproach.ADVERSARIAL_DEBATE

    @patch("app.agents.adjudicator.get_llm_client")
    def test_high_uses_adversarial(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(severity="high")
        assert agent._resolve_approach(finding) == AdjudicationApproach.ADVERSARIAL_DEBATE

    @patch("app.agents.adjudicator.get_llm_client")
    def test_medium_uses_rubric(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(severity="medium")
        assert agent._resolve_approach(finding) == AdjudicationApproach.EVIDENCE_RUBRIC

    @patch("app.agents.adjudicator.get_llm_client")
    def test_low_uses_challenge(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(severity="low")
        assert agent._resolve_approach(finding) == AdjudicationApproach.STRUCTURED_CHALLENGE

    @patch("app.agents.adjudicator.get_llm_client")
    def test_info_uses_challenge(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(severity="info")
        assert agent._resolve_approach(finding) == AdjudicationApproach.STRUCTURED_CHALLENGE

    @patch("app.agents.adjudicator.get_llm_client")
    def test_explicit_approach_overrides_auto(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent(approach=AdjudicationApproach.EVIDENCE_RUBRIC)
        finding = _make_finding(severity="critical")
        assert agent._resolve_approach(finding) == AdjudicationApproach.EVIDENCE_RUBRIC


# ═══════════════════════════════════════════════════════════════════════════════
# Structured Challenge
# ═══════════════════════════════════════════════════════════════════════════════


class TestStructuredChallenge:

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_severity_adjusted(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response(_challenge_response("medium"))

        agent = AdjudicatorAgent(approach=AdjudicationApproach.STRUCTURED_CHALLENGE)
        finding = _make_finding(severity="high")
        results = await agent.adjudicate_findings([finding])

        assert len(results) == 1
        assert results[0].original_severity == FindingSeverity.HIGH
        assert results[0].adjudicated_severity == FindingSeverity.MEDIUM
        assert results[0].approach_used == AdjudicationApproach.STRUCTURED_CHALLENGE
        assert results[0].confidence == 0.85

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_severity_upheld(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response(_challenge_response("high"))

        agent = AdjudicatorAgent(approach=AdjudicationApproach.STRUCTURED_CHALLENGE)
        finding = _make_finding(severity="high")
        results = await agent.adjudicate_findings([finding])

        assert len(results) == 1
        assert results[0].original_severity == results[0].adjudicated_severity

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_llm_failure_upholds_severity(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response({}, success=False)

        agent = AdjudicatorAgent(approach=AdjudicationApproach.STRUCTURED_CHALLENGE)
        finding = _make_finding(severity="high")
        results = await agent.adjudicate_findings([finding])

        assert len(results) == 1
        assert results[0].adjudicated_severity == FindingSeverity.HIGH
        assert results[0].confidence == 0.0
        assert "inconclusive" in results[0].rationale.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# Adversarial Debate
# ═══════════════════════════════════════════════════════════════════════════════


class TestAdversarialDebate:

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_three_llm_calls(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client

        prosecution = {"argument": "This is critical", "suggested_severity": "critical", "key_factors": ["exposed"]}
        defense = {"argument": "This is overstated", "suggested_severity": "low", "key_factors": ["vpn"]}
        verdict = _challenge_response("medium", 0.9)

        mock_llm_client.chat.side_effect = [
            _make_llm_response(prosecution),
            _make_llm_response(defense),
            _make_llm_response(verdict),
        ]

        agent = AdjudicatorAgent(approach=AdjudicationApproach.ADVERSARIAL_DEBATE)
        finding = _make_finding(severity="high")
        results = await agent.adjudicate_findings([finding])

        assert mock_llm_client.chat.call_count == 3
        assert len(results) == 1
        assert results[0].approach_used == AdjudicationApproach.ADVERSARIAL_DEBATE
        assert results[0].adjudicated_severity == FindingSeverity.MEDIUM


# ═══════════════════════════════════════════════════════════════════════════════
# Evidence Rubric
# ═══════════════════════════════════════════════════════════════════════════════


class TestEvidenceRubric:

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_rubric_scoring(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response(_rubric_response("medium"))

        agent = AdjudicatorAgent(approach=AdjudicationApproach.EVIDENCE_RUBRIC)
        finding = _make_finding(severity="high")
        results = await agent.adjudicate_findings([finding])

        assert len(results) == 1
        assert results[0].approach_used == AdjudicationApproach.EVIDENCE_RUBRIC
        assert "exploitability" in results[0].factors


# ═══════════════════════════════════════════════════════════════════════════════
# Operator Context
# ═══════════════════════════════════════════════════════════════════════════════


class TestOperatorContext:

    @patch("app.agents.adjudicator.get_llm_client")
    def test_match_exact_domain(self, mock_get, sample_operator_context):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(target_url="https://api.example.com/v1/users")
        ctx = agent._match_asset_context(finding, sample_operator_context)
        assert ctx is not None
        assert ctx.exposure == "internet-facing"
        assert ctx.criticality == "high"

    @patch("app.agents.adjudicator.get_llm_client")
    def test_match_wildcard_domain(self, mock_get, sample_operator_context):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(target_url="https://tools.internal.local/admin")
        ctx = agent._match_asset_context(finding, sample_operator_context)
        assert ctx is not None
        assert ctx.exposure == "vpn-only"

    @patch("app.agents.adjudicator.get_llm_client")
    def test_fallback_to_defaults(self, mock_get, sample_operator_context):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding(target_url="https://unknown.host.com/path")
        ctx = agent._match_asset_context(finding, sample_operator_context)
        assert ctx is not None
        assert ctx.exposure == "unknown"
        assert ctx.criticality == "medium"

    @patch("app.agents.adjudicator.get_llm_client")
    def test_no_context_returns_none(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        finding = _make_finding()
        assert agent._match_asset_context(finding, None) is None


class TestOperatorContextLoading:

    @patch("app.engine.adjudication.get_config")
    def test_missing_file_returns_none(self, mock_config):
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.context_file = "/nonexistent/path.yaml"
        result = load_operator_context()
        assert result is None

    @patch("app.engine.adjudication._YAML_AVAILABLE", False)
    @patch("app.engine.adjudication.get_config")
    def test_no_yaml_returns_none(self, mock_config, tmp_path):
        ctx_file = tmp_path / "context.yaml"
        ctx_file.write_text("assets: []")
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.context_file = str(ctx_file)
        result = load_operator_context()
        assert result is None

    @patch("app.engine.adjudication._yaml")
    @patch("app.engine.adjudication._YAML_AVAILABLE", True)
    @patch("app.engine.adjudication.get_config")
    def test_valid_file_loads(self, mock_config, mock_yaml, tmp_path):
        ctx_file = tmp_path / "context.yaml"
        ctx_file.write_text("placeholder")
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.context_file = str(ctx_file)

        mock_yaml.safe_load.return_value = {
            "assets": [
                {"domain": "api.example.com", "exposure": "internet-facing", "criticality": "high"}
            ],
            "defaults": {"exposure": "unknown", "criticality": "medium"},
        }

        result = load_operator_context()
        assert result is not None
        assert len(result.assets) == 1
        assert result.assets[0].domain == "api.example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# Event Emission
# ═══════════════════════════════════════════════════════════════════════════════


class TestEventEmission:

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_emits_start_and_complete(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response(_challenge_response("high"))

        callback = AsyncMock()
        agent = AdjudicatorAgent(
            event_callback=callback,
            approach=AdjudicationApproach.STRUCTURED_CHALLENGE,
        )

        finding = _make_finding(severity="high")
        await agent.adjudicate_findings([finding])

        event_types = [call.args[0].event_type for call in callback.call_args_list]
        assert EventType.ADJUDICATION_START in event_types
        assert EventType.ADJUDICATION_COMPLETE in event_types

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_emits_upheld_when_severity_same(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response(_challenge_response("high"))

        callback = AsyncMock()
        agent = AdjudicatorAgent(
            event_callback=callback,
            approach=AdjudicationApproach.STRUCTURED_CHALLENGE,
        )

        finding = _make_finding(severity="high")
        await agent.adjudicate_findings([finding])

        event_types = [call.args[0].event_type for call in callback.call_args_list]
        assert EventType.SEVERITY_UPHELD in event_types

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_emits_adjusted_when_severity_changes(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = _make_llm_response(_challenge_response("medium"))

        callback = AsyncMock()
        agent = AdjudicatorAgent(
            event_callback=callback,
            approach=AdjudicationApproach.STRUCTURED_CHALLENGE,
        )

        finding = _make_finding(severity="high")
        await agent.adjudicate_findings([finding])

        event_types = [call.args[0].event_type for call in callback.call_args_list]
        assert EventType.SEVERITY_ADJUSTED in event_types


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_no_verified_findings(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        pending_finding = _make_finding(status="pending")
        results = await agent.adjudicate_findings([pending_finding])
        assert results == []

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_empty_findings(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        results = await agent.adjudicate_findings([])
        assert results == []

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_malformed_json_upholds_severity(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client
        mock_llm_client.chat.return_value = LLMResponse(
            content="This is not valid JSON at all",
            model="test",
            provider="test",
            success=True,
        )

        agent = AdjudicatorAgent(approach=AdjudicationApproach.STRUCTURED_CHALLENGE)
        finding = _make_finding(severity="high")
        results = await agent.adjudicate_findings([finding])

        assert len(results) == 1
        assert results[0].adjudicated_severity == FindingSeverity.HIGH
        assert results[0].confidence == 0.0

    @pytest.mark.asyncio
    @patch("app.agents.adjudicator.get_llm_client")
    async def test_stop_halts_processing(self, mock_get, mock_llm_client):
        mock_get.return_value = mock_llm_client

        call_count = 0

        async def chat_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                agent.stop()
            return _make_llm_response(_challenge_response("high"))

        mock_llm_client.chat.side_effect = chat_side_effect

        agent = AdjudicatorAgent(approach=AdjudicationApproach.STRUCTURED_CHALLENGE)
        findings = [_make_finding(finding_id=f"F-{i:03d}") for i in range(5)]
        results = await agent.adjudicate_findings(findings)
        # Stop called after 2nd LLM call, so should have fewer than 5 results
        assert len(results) < 5


# ═══════════════════════════════════════════════════════════════════════════════
# Model Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestAdjudicatedRiskModel:

    def test_valid_model(self):
        risk = AdjudicatedRisk(
            finding_id="F-001",
            original_severity=FindingSeverity.HIGH,
            adjudicated_severity=FindingSeverity.MEDIUM,
            confidence=0.85,
            approach_used=AdjudicationApproach.STRUCTURED_CHALLENGE,
            rationale="Mitigated by VPN",
            factors={"attack_vector": "local"},
        )
        assert risk.finding_id == "F-001"
        assert risk.adjudicated_by == AgentType.ADJUDICATOR

    def test_confidence_bounds(self):
        with pytest.raises(ValueError):
            AdjudicatedRisk(
                finding_id="F-001",
                original_severity=FindingSeverity.HIGH,
                adjudicated_severity=FindingSeverity.HIGH,
                confidence=1.5,  # Out of bounds
                approach_used=AdjudicationApproach.AUTO,
                rationale="Test",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Approach Resolution
# ═══════════════════════════════════════════════════════════════════════════════


class TestApproachResolution:

    @patch("app.engine.adjudication.get_config")
    def test_api_param_wins(self, mock_config):
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.default_approach = "auto"
        result = resolve_approach("adversarial_debate")
        assert result == AdjudicationApproach.ADVERSARIAL_DEBATE

    @patch("app.engine.adjudication.get_config")
    def test_config_default_used(self, mock_config):
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.default_approach = "evidence_rubric"
        result = resolve_approach(None)
        assert result == AdjudicationApproach.EVIDENCE_RUBRIC

    @patch("app.engine.adjudication.get_config")
    def test_invalid_api_param_falls_back(self, mock_config):
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.default_approach = "auto"
        result = resolve_approach("invalid_approach")
        assert result == AdjudicationApproach.AUTO

    @patch("app.engine.adjudication.get_config")
    def test_invalid_config_falls_back_to_auto(self, mock_config):
        mock_config.return_value = MagicMock()
        mock_config.return_value.adjudicator.default_approach = "invalid"
        result = resolve_approach(None)
        assert result == AdjudicationApproach.AUTO


# ═══════════════════════════════════════════════════════════════════════════════
# JSON Cleaning
# ═══════════════════════════════════════════════════════════════════════════════


class TestJsonCleaning:

    @patch("app.agents.adjudicator.get_llm_client")
    def test_strips_markdown_fences(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        raw = '```json\n{"key": "value"}\n```'
        assert agent._clean_json(raw) == '{"key": "value"}'

    @patch("app.agents.adjudicator.get_llm_client")
    def test_strips_plain_fences(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        raw = '```\n{"key": "value"}\n```'
        assert agent._clean_json(raw) == '{"key": "value"}'

    @patch("app.agents.adjudicator.get_llm_client")
    def test_passes_clean_json(self, mock_get):
        mock_get.return_value = MagicMock()
        agent = AdjudicatorAgent()
        raw = '{"key": "value"}'
        assert agent._clean_json(raw) == '{"key": "value"}'
