"""
Tests for Chainsmith Agent

Covers:
- ChainsmithAgent instantiation and pattern loading
- ValidationResult model
- ValidationIssue model
- Graph validation (dead checks, orphaned outputs)
- Chain pattern validation
- Chain building from verified observations
- Scaffold check generation
- Content analysis (LLM available/unavailable)
- Disable impact analysis
- Event emission
"""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from app.agents.chainsmith import ChainsmithAgent, ValidationIssue, ValidationResult
from app.lib.llm import LLMResponse
from app.models import (
    EventType,
    Observation,
    ObservationSeverity,
    ObservationStatus,
)

pytestmark = pytest.mark.unit


# ─── Helpers ──────────────────────────────────────────────────────


def _make_observation(
    obs_id: str = "F-001",
    title: str = "Test Observation",
    check_name: str = "test_check",
    status: str = "verified",
) -> Observation:
    return Observation(
        id=obs_id,
        observation_type=check_name,
        title=title,
        description="Test description",
        severity=ObservationSeverity.HIGH,
        status=ObservationStatus(status),
        confidence=0.8,
        check_name=check_name,
        discovered_at=datetime(2026, 1, 1),
    )


# ─── ValidationIssue ─────────────────────────────────────────────


class TestValidationIssue:
    def test_to_dict(self):
        issue = ValidationIssue(
            category="graph",
            severity="error",
            message="Dead check",
            check_name="foo_check",
            suggestion="Remove it",
        )
        d = issue.to_dict()
        assert d["category"] == "graph"
        assert d["severity"] == "error"
        assert d["message"] == "Dead check"
        assert d["check_name"] == "foo_check"
        assert d["suggestion"] == "Remove it"

    def test_repr(self):
        issue = ValidationIssue(category="graph", severity="warning", message="Orphaned output")
        assert "WARNING" in repr(issue)
        assert "graph" in repr(issue)


# ─── ValidationResult ────────────────────────────────────────────


class TestValidationResult:
    def test_empty_result_is_healthy(self):
        result = ValidationResult()
        assert result.healthy is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0

    def test_error_makes_unhealthy(self):
        result = ValidationResult()
        result.issues.append(ValidationIssue(category="graph", severity="error", message="broken"))
        assert result.healthy is False
        assert len(result.errors) == 1

    def test_warning_still_healthy(self):
        result = ValidationResult()
        result.issues.append(ValidationIssue(category="graph", severity="warning", message="meh"))
        assert result.healthy is True
        assert len(result.warnings) == 1

    def test_summary_no_issues(self):
        result = ValidationResult()
        result.checks_analyzed = 50
        result.patterns_analyzed = 10
        summary = result.summary()
        assert "healthy" in summary
        assert "50 checks" in summary

    def test_summary_with_issues(self):
        result = ValidationResult()
        result.checks_analyzed = 50
        result.patterns_analyzed = 10
        result.issues.append(
            ValidationIssue(
                category="graph",
                severity="error",
                message="Dead check found",
                suggestion="Remove it",
            )
        )
        summary = result.summary()
        assert "1 error" in summary
        assert "Dead check found" in summary
        assert "Remove it" in summary

    def test_to_dict(self):
        result = ValidationResult()
        result.checks_analyzed = 5
        result.patterns_analyzed = 2
        d = result.to_dict()
        assert d["healthy"] is True
        assert d["checks_analyzed"] == 5
        assert d["patterns_analyzed"] == 2
        assert isinstance(d["issues"], list)


# ─── Instantiation ───────────────────────────────────────────────


class TestChainsmithInstantiation:
    @patch("app.agents.chainsmith.get_llm_client")
    @patch("app.agents.chainsmith.ATTACK_PATTERNS_PATH", "/nonexistent/path.json")
    def test_creates_with_missing_patterns_file(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()
        assert agent.attack_patterns == []

    @patch("app.agents.chainsmith.get_llm_client")
    def test_creates_with_patterns(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()
        # attack_patterns should be loaded (may be empty list or have data)
        assert isinstance(agent.attack_patterns, list)


# ─── Chain Building ──────────────────────────────────────────────


class TestChainsmithChainBuilding:
    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_build_chains_too_few_observations(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()
        # Need at least 2 verified observations
        obs = [_make_observation()]
        result = await agent.build_chains(obs)
        assert result == []

    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_build_chains_no_verified(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()
        obs = [
            _make_observation(status="pending"),
            _make_observation(obs_id="F-002", status="pending"),
        ]
        result = await agent.build_chains(obs)
        assert result == []

    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_build_chains_emits_events(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        events = []
        agent = ChainsmithAgent(event_callback=AsyncMock(side_effect=lambda e: events.append(e)))
        # Not enough observations to build chains, but should still emit events
        await agent.build_chains([_make_observation()])
        event_types = [e.event_type for e in events]
        assert EventType.AGENT_START in event_types
        assert EventType.AGENT_COMPLETE in event_types


# ─── Scaffold Check ──────────────────────────────────────────────


class TestChainsmithScaffold:
    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_scaffold_check_basic(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()

        with patch("os.path.exists", return_value=False):
            result = await agent.scaffold_check(
                name="my_custom_check",
                description="A custom security check",
                suite="web",
            )

        assert result["class_name"] == "MyCustomCheckCheck"
        assert result["code"] is not None
        assert "BaseCheck" in result["code"]
        assert result["registered"] is False

    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_scaffold_check_already_exists(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()

        with patch("os.path.exists", return_value=True):
            result = await agent.scaffold_check(
                name="existing_check",
                description="Already exists",
                suite="web",
            )

        assert result.get("error") is not None
        assert "already exists" in result["error"]


# ─── Content Analysis ────────────────────────────────────────────


class TestChainsmithContentAnalysis:
    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_content_analysis_no_llm(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        agent = ChainsmithAgent()
        agent.llm_client = None
        result = await agent.analyze_content(checks=[])
        assert "requires an LLM client" in result

    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_content_analysis_with_llm(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        llm = AsyncMock()
        llm.chat.return_value = LLMResponse(
            content="Analysis: 2 overlapping checks found.",
            model="test",
            provider="test",
            success=True,
        )
        agent = ChainsmithAgent(llm_client=llm)
        result = await agent.analyze_content(checks=[])
        # No check summaries extractable → returns message
        assert isinstance(result, str)

    @patch("app.agents.chainsmith.get_llm_client")
    @pytest.mark.asyncio
    async def test_content_analysis_llm_failure(self, mock_llm):
        mock_llm.return_value = AsyncMock()
        llm = AsyncMock()
        llm.chat.return_value = LLMResponse(
            content="",
            model="test",
            provider="test",
            success=False,
            error="Rate limited",
        )
        agent = ChainsmithAgent(llm_client=llm)
        # Provide a real check so we get past the empty check guard
        from unittest.mock import MagicMock

        mock_check = MagicMock()
        mock_check.name = "test_check"
        mock_check.description = "A test check"
        mock_check.__module__ = "app.checks.test"
        result = await agent.analyze_content(checks=[mock_check])
        assert "failed" in result.lower() or "No check" in result
