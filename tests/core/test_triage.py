"""
Tests for Triage Agent

Covers:
- TriageAgent instantiation
- Single LLM call triage with mocked responses
- Team context load/save (valid, missing, malformed)
- Remediation KB loading and matching
- Event emission (start, complete, action)
- TriagePlan / TriageAction model validation
- Edge cases (no observations, LLM unavailable, malformed JSON, stop)
- Feasibility classification based on team context
- Workstream generation for multi-person teams
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.triage import TriageAgent, _clean_json, _match_kb_entries, load_remediation_kb
from app.engine.triage import load_team_context, save_team_context
from app.lib.llm import LLMErrorType, LLMResponse
from app.models import (
    ActionFeasibility,
    AdjudicatedRisk,
    AdjudicationApproach,
    AttackChain,
    ComponentType,
    EventType,
    Observation,
    ObservationSeverity,
    ObservationStatus,
    TeamContext,
    TriageAction,
    TriagePlan,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


def _make_observation(
    observation_id: str = "obs-001",
    severity: str = "high",
    status: str = "verified",
    title: str = "Test Observation",
    target_url: str = "https://api.example.com/v1",
    observation_type: str = "verbose_errors",
) -> Observation:
    """Create a test observation."""
    return Observation(
        id=observation_id,
        observation_type=observation_type,
        title=title,
        description="A test observation for triage",
        severity=ObservationSeverity(severity),
        status=ObservationStatus(status),
        confidence=0.8,
        check_name=observation_type,
        discovered_at=datetime(2026, 1, 1),
        target_url=target_url,
        evidence_summary="Test evidence found",
    )


def _make_adjudication(
    observation_id: str = "obs-001",
    original: str = "high",
    adjudicated: str = "high",
    confidence: float = 0.8,
) -> AdjudicatedRisk:
    """Create a test adjudication result."""
    return AdjudicatedRisk(
        observation_id=observation_id,
        original_severity=ObservationSeverity(original),
        adjudicated_severity=ObservationSeverity(adjudicated),
        confidence=confidence,
        approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
        rationale="Test rationale",
        factors={"exploitability": 0.7, "impact": 0.8},
    )


def _make_chain(
    chain_id: str = "chain-001",
    observation_ids: list[str] | None = None,
) -> AttackChain:
    """Create a test attack chain."""
    return AttackChain(
        id=chain_id,
        title="Test Attack Chain",
        description="A test chain",
        impact_statement="Could lead to data exposure",
        observation_ids=observation_ids or ["obs-001", "obs-002"],
        individual_severities=[ObservationSeverity.HIGH, ObservationSeverity.MEDIUM],
        combined_severity=ObservationSeverity.HIGH,
        severity_reasoning="Combined severity is high",
        attack_steps=["Step 1: Enumerate", "Step 2: Exploit"],
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


def _triage_response() -> dict:
    """Standard triage response."""
    return {
        "summary": "Fix credential rotation first, then harden headers.",
        "actions": [
            {
                "priority": 1,
                "action": "Rotate exposed credentials",
                "targets": ["obs-001"],
                "chains_neutralized": ["chain-001"],
                "reasoning": "Breaks highest-severity chain",
                "effort_estimate": "low",
                "impact_estimate": "high",
                "feasibility": "direct",
                "remediation_guidance": ["Step 1", "Step 2"],
                "observations_resolved": ["obs-001"],
                "category": "credential_management",
            },
            {
                "priority": 2,
                "action": "Disable verbose errors",
                "targets": ["obs-002"],
                "chains_neutralized": [],
                "reasoning": "Reduces information disclosure",
                "effort_estimate": "low",
                "impact_estimate": "medium",
                "feasibility": "direct",
                "remediation_guidance": ["Set DEBUG=false"],
                "observations_resolved": ["obs-002"],
                "category": "information_disclosure",
            },
        ],
        "workstreams": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Model tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTriageModels:
    """Test triage-related Pydantic models."""

    def test_team_context_defaults(self):
        ctx = TeamContext()
        assert ctx.deployment_velocity is None
        assert ctx.incident_response is None
        assert ctx.remediation_surface is None
        assert ctx.team_size is None
        assert ctx.off_limits is None
        assert ctx.answered_at is None

    def test_team_context_populated(self):
        ctx = TeamContext(
            deployment_velocity="yes",
            incident_response="partially",
            remediation_surface="app_only",
            team_size="2_to_3",
            off_limits="Auth service",
        )
        assert ctx.deployment_velocity == "yes"
        assert ctx.team_size == "2_to_3"

    def test_action_feasibility_values(self):
        assert ActionFeasibility.DIRECT == "direct"
        assert ActionFeasibility.ESCALATE == "escalate"
        assert ActionFeasibility.BLOCKED == "blocked"

    def test_triage_action_creation(self):
        action = TriageAction(
            priority=1,
            action="Fix something",
            reasoning="Because it's broken",
            effort_estimate="low",
            impact_estimate="high",
        )
        assert action.priority == 1
        assert action.feasibility == ActionFeasibility.DIRECT

    def test_triage_plan_creation(self):
        plan = TriagePlan(scan_id="test-scan")
        assert plan.scan_id == "test-scan"
        assert plan.actions == []
        assert plan.team_context_available is False
        assert plan.caveat is None

    def test_triage_plan_with_actions(self):
        action = TriageAction(
            priority=1,
            action="Fix it",
            reasoning="Urgent",
            effort_estimate="low",
            impact_estimate="high",
        )
        plan = TriagePlan(
            scan_id="test-scan",
            actions=[action],
            quick_wins=1,
            team_context_available=True,
        )
        assert len(plan.actions) == 1
        assert plan.quick_wins == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Team context load/save tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTeamContextLoadSave:
    """Test team context YAML loading and saving."""

    def test_load_missing_file(self, tmp_path):
        """Returns None when file doesn't exist."""
        cfg = MagicMock()
        cfg.triage.context_file = str(tmp_path / "nonexistent.yaml")
        result = load_team_context(cfg)
        assert result is None

    def test_load_valid_file(self, tmp_path):
        """Loads valid YAML correctly."""
        yaml_content = (
            "deployment_velocity: yes\n"
            "incident_response: partially\n"
            "remediation_surface: app_only\n"
            "team_size: 2_to_3\n"
            'off_limits: "Auth service"\n'
            'answered_at: "2026-04-09T14:30:00Z"\n'
        )
        yaml_file = tmp_path / "triage_context.yaml"
        yaml_file.write_text(yaml_content)

        cfg = MagicMock()
        cfg.triage.context_file = str(yaml_file)
        result = load_team_context(cfg)

        assert result is not None
        assert result.deployment_velocity == "yes"
        assert result.incident_response == "partially"
        assert result.remediation_surface == "app_only"
        assert result.team_size == "2_to_3"
        assert result.off_limits == "Auth service"
        assert result.answered_at is not None

    def test_load_partial_file(self, tmp_path):
        """Loads partial YAML — missing fields are None."""
        yaml_content = "deployment_velocity: no\n"
        yaml_file = tmp_path / "triage_context.yaml"
        yaml_file.write_text(yaml_content)

        cfg = MagicMock()
        cfg.triage.context_file = str(yaml_file)
        result = load_team_context(cfg)

        assert result is not None
        assert result.deployment_velocity == "no"
        assert result.incident_response is None

    def test_load_malformed_file(self, tmp_path):
        """Returns None for non-mapping YAML."""
        yaml_file = tmp_path / "triage_context.yaml"
        yaml_file.write_text("- just\n- a\n- list\n")

        cfg = MagicMock()
        cfg.triage.context_file = str(yaml_file)
        result = load_team_context(cfg)
        assert result is None

    def test_save_and_reload(self, tmp_path):
        """Round-trip: save then load."""
        ctx = TeamContext(
            deployment_velocity="with_approval",
            incident_response="yes",
            remediation_surface="both",
            team_size="4_plus",
            off_limits="Production DB",
            answered_at=datetime(2026, 4, 9, 14, 30),
        )

        yaml_file = tmp_path / "triage_context.yaml"
        cfg = MagicMock()
        cfg.triage.context_file = str(yaml_file)

        assert save_team_context(ctx, cfg) is True
        assert yaml_file.exists()

        loaded = load_team_context(cfg)
        assert loaded is not None
        assert loaded.deployment_velocity == "with_approval"
        assert loaded.team_size == "4_plus"
        assert loaded.off_limits == "Production DB"


# ═══════════════════════════════════════════════════════════════════════════════
# Remediation KB tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRemediationKB:
    """Test remediation knowledge base loading and matching."""

    def test_load_missing_kb(self):
        result = load_remediation_kb("/nonexistent/path.json")
        assert result == []

    def test_load_valid_kb(self):
        result = load_remediation_kb("app/data/remediation_guidance.json")
        assert isinstance(result, list)
        assert len(result) > 0
        assert "check_id" in result[0]

    def test_match_kb_entries(self):
        obs = [_make_observation(observation_type="verbose_errors")]
        kb = [
            {"check_id": "verbose_errors", "title": "Fix verbose errors"},
            {"check_id": "cors_misconfigured", "title": "Fix CORS"},
        ]
        matched = _match_kb_entries(obs, kb)
        assert len(matched) == 1
        assert matched[0]["check_id"] == "verbose_errors"

    def test_match_kb_no_matches(self):
        obs = [_make_observation(observation_type="unknown_check")]
        kb = [{"check_id": "verbose_errors", "title": "Fix verbose errors"}]
        matched = _match_kb_entries(obs, kb)
        assert len(matched) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# TriageAgent tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTriageAgent:
    """Test the TriageAgent class."""

    def _make_agent(self, response: dict | None = None, success: bool = True):
        """Create a TriageAgent with a mocked LLM client."""
        client = MagicMock()
        if response is None:
            response = _triage_response()
        client.chat = AsyncMock(return_value=_make_llm_response(response, success))
        return TriageAgent(client=client), client

    @pytest.mark.asyncio
    async def test_basic_triage(self):
        """Produces a plan with actions from LLM response."""
        agent, client = self._make_agent()

        obs = [
            _make_observation("obs-001", severity="high"),
            _make_observation("obs-002", severity="medium", title="Verbose errors"),
        ]
        adj = [_make_adjudication("obs-001"), _make_adjudication("obs-002", adjudicated="medium")]
        chains = [_make_chain()]

        plan = await agent.triage(obs, chains, adj, scan_id="scan-001")

        assert isinstance(plan, TriagePlan)
        assert plan.scan_id == "scan-001"
        assert len(plan.actions) == 2
        assert plan.actions[0].priority == 1
        assert plan.actions[0].action == "Rotate exposed credentials"
        assert plan.quick_wins == 1  # low effort + high impact
        assert plan.team_context_available is False
        assert plan.caveat is not None  # no team context = caveat

        # LLM was called once
        client.chat.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_triage_with_team_context(self):
        """Plan reflects team context availability."""
        agent, _ = self._make_agent()

        obs = [_make_observation()]
        adj = [_make_adjudication()]
        team = TeamContext(deployment_velocity="yes", team_size="solo")

        plan = await agent.triage(obs, [], adj, team_context=team, scan_id="scan-002")

        assert plan.team_context_available is True
        assert plan.caveat is None

    @pytest.mark.asyncio
    async def test_triage_no_observations(self):
        """Returns empty plan when no observations."""
        agent, client = self._make_agent()

        plan = await agent.triage([], [], [], scan_id="scan-003")

        assert plan.scan_id == "scan-003"
        assert len(plan.actions) == 0
        assert "No observations" in plan.summary
        client.chat.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_triage_llm_failure(self):
        """Returns fallback plan when LLM fails."""
        agent, _ = self._make_agent(response={}, success=False)

        obs = [_make_observation()]
        adj = [_make_adjudication()]

        plan = await agent.triage(obs, [], adj, scan_id="scan-004")

        assert "failed" in plan.summary.lower()
        assert len(plan.actions) == 0

    @pytest.mark.asyncio
    async def test_triage_malformed_json(self):
        """Returns fallback plan when LLM returns invalid JSON."""
        client = MagicMock()
        client.chat = AsyncMock(
            return_value=LLMResponse(
                content="This is not JSON at all",
                model="test",
                provider="test",
                success=True,
            )
        )
        agent = TriageAgent(client=client)

        obs = [_make_observation()]
        adj = [_make_adjudication()]

        plan = await agent.triage(obs, [], adj, scan_id="scan-005")

        assert "unparseable" in plan.summary.lower()
        assert len(plan.actions) == 0

    @pytest.mark.asyncio
    async def test_event_emission(self):
        """Emits start, action, and complete events."""
        agent, _ = self._make_agent()
        events = []
        agent.event_callback = AsyncMock(side_effect=lambda e: events.append(e))

        obs = [_make_observation()]
        adj = [_make_adjudication()]

        await agent.triage(obs, [], adj, scan_id="scan-006")

        event_types = [e.event_type for e in events]
        assert EventType.TRIAGE_START in event_types
        assert EventType.TRIAGE_ACTION in event_types
        assert EventType.TRIAGE_COMPLETE in event_types

        # All events from TRIAGE agent
        for e in events:
            assert e.agent == ComponentType.TRIAGE

    @pytest.mark.asyncio
    async def test_stop(self):
        """Stop cancels triage."""
        agent, _ = self._make_agent()
        agent.stop()
        assert agent.is_running is False

    @pytest.mark.asyncio
    async def test_feasibility_parsing(self):
        """Correctly parses feasibility values from LLM."""
        response = _triage_response()
        response["actions"][0]["feasibility"] = "escalate"
        response["actions"][1]["feasibility"] = "blocked"

        agent, _ = self._make_agent(response)
        obs = [_make_observation("obs-001"), _make_observation("obs-002")]
        adj = [_make_adjudication("obs-001"), _make_adjudication("obs-002")]

        plan = await agent.triage(obs, [], adj, scan_id="scan-007")

        assert plan.actions[0].feasibility == ActionFeasibility.ESCALATE
        assert plan.actions[1].feasibility == ActionFeasibility.BLOCKED

    @pytest.mark.asyncio
    async def test_workstreams_included(self):
        """Workstreams are included when present in LLM response."""
        response = _triage_response()
        response["workstreams"] = [
            {"name": "Credentials", "assignable_to": 1, "actions": [1]},
            {"name": "Headers", "assignable_to": 1, "actions": [2]},
        ]

        agent, _ = self._make_agent(response)
        obs = [_make_observation()]
        adj = [_make_adjudication()]
        team = TeamContext(team_size="2_to_3")

        plan = await agent.triage(obs, [], adj, team_context=team, scan_id="scan-008")

        assert plan.workstreams is not None
        assert len(plan.workstreams) == 2

    @pytest.mark.asyncio
    async def test_prompt_includes_chain_info(self):
        """Prompt sent to LLM includes chain details."""
        agent, client = self._make_agent()

        obs = [_make_observation()]
        adj = [_make_adjudication()]
        chain = _make_chain()

        await agent.triage(obs, [chain], adj, scan_id="scan-009")

        # Check the prompt includes chain info
        call_args = client.chat.call_args
        prompt = call_args.kwargs.get("prompt") or call_args[0][0]
        assert "ATTACK CHAINS" in prompt
        assert "chain-001" in prompt

    @pytest.mark.asyncio
    async def test_prompt_includes_team_context(self):
        """Prompt includes team context when provided."""
        agent, client = self._make_agent()

        obs = [_make_observation()]
        adj = [_make_adjudication()]
        team = TeamContext(
            deployment_velocity="no",
            off_limits="Auth service",
        )

        await agent.triage(obs, [], adj, team_context=team, scan_id="scan-010")

        call_args = client.chat.call_args
        prompt = call_args.kwargs.get("prompt") or call_args[0][0]
        assert "TEAM CONTEXT" in prompt
        assert "Auth service" in prompt

    @pytest.mark.asyncio
    async def test_prompt_includes_kb_entries(self):
        """Prompt includes matched KB entries."""
        agent, client = self._make_agent()

        obs = [_make_observation()]
        adj = [_make_adjudication()]
        kb = [{"check_id": "verbose_errors", "title": "Fix errors", "steps": ["Step 1"]}]

        await agent.triage(obs, [], adj, kb_entries=kb, scan_id="scan-011")

        call_args = client.chat.call_args
        prompt = call_args.kwargs.get("prompt") or call_args[0][0]
        assert "REMEDIATION KNOWLEDGE BASE" in prompt
        assert "verbose_errors" in prompt


# ═══════════════════════════════════════════════════════════════════════════════
# Utility tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCleanJson:
    """Test JSON cleaning utility."""

    def test_clean_plain_json(self):
        assert _clean_json('{"a": 1}') == '{"a": 1}'

    def test_clean_fenced_json(self):
        text = '```json\n{"a": 1}\n```'
        assert _clean_json(text) == '{"a": 1}'

    def test_clean_whitespace(self):
        assert _clean_json('  {"a": 1}  ') == '{"a": 1}'
