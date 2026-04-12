"""
Tests for Researcher Agent

Covers:
- ResearcherAgent instantiation
- Enrichment of observations with mocked LLM
- Empty observations handling
- LLM unavailable skips enrichment
- Tool execution (lookup_cve, lookup_exploit_db, enrich_version_info, submit_enrichment)
- Offline mode
- Tool call extraction (JSON and text-based patterns)
- Event emission
- Stop behavior
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock

import pytest

from app.agents.researcher import (
    ResearcherAgent,
    _enrich_version_info,
    _fetch_vendor_advisory,
    _lookup_cve,
    _lookup_exploit_db,
)
from app.lib.llm import LLMResponse
from app.models import (
    EventType,
    Observation,
    ObservationSeverity,
    ObservationStatus,
)

pytestmark = pytest.mark.unit


# ─── Helpers ──────────────────────────────────────────────────────


def _make_client(available: bool = True, content: str = "", success: bool = True):
    from unittest.mock import MagicMock

    client = MagicMock()
    client.is_available.return_value = available
    client.chat = AsyncMock(
        return_value=LLMResponse(
            content=content,
            model="test",
            provider="test",
            success=success,
            error=None if success else "LLM error",
        )
    )
    return client


def _make_observation(
    obs_id: str = "F-001",
    title: str = "Test Observation",
    evidence: str = "Evidence here",
) -> Observation:
    return Observation(
        id=obs_id,
        observation_type="test_check",
        title=title,
        description="Test description",
        severity=ObservationSeverity.HIGH,
        status=ObservationStatus.VERIFIED,
        confidence=0.8,
        check_name="test_check",
        discovered_at=datetime(2026, 1, 1),
        evidence_summary=evidence,
    )


# ─── Instantiation ───────────────────────────────────────────────


class TestResearcherInstantiation:
    def test_creates_with_defaults(self):
        client = _make_client()
        agent = ResearcherAgent(client)
        assert agent.is_running is False
        assert agent.enrichments == {}
        assert agent.offline_mode is False

    def test_offline_mode(self):
        agent = ResearcherAgent(_make_client(), offline_mode=True)
        assert agent.offline_mode is True


# ─── Empty/Unavailable Handling ──────────────────────────────────


class TestResearcherEmptyHandling:
    @pytest.mark.asyncio
    async def test_empty_observations(self):
        agent = ResearcherAgent(_make_client())
        result = await agent.enrich_observations([])
        assert result == {}
        assert agent.is_running is False

    @pytest.mark.asyncio
    async def test_llm_unavailable(self):
        client = _make_client(available=False)
        agent = ResearcherAgent(client)
        obs = [_make_observation()]
        result = await agent.enrich_observations(obs)
        assert result == {}
        client.chat.assert_not_called()


# ─── Tool Implementations ────────────────────────────────────────


class TestResearcherTools:
    @pytest.mark.asyncio
    async def test_lookup_cve_found(self):
        result = await _lookup_cve("CVE-2021-41773")
        assert result["found"] is True
        assert "description" in result

    @pytest.mark.asyncio
    async def test_lookup_cve_not_found(self):
        result = await _lookup_cve("CVE-9999-99999")
        assert result["found"] is False

    @pytest.mark.asyncio
    async def test_lookup_cve_offline(self):
        result = await _lookup_cve("CVE-2021-41773", offline=True)
        assert result["found"] is True
        assert result["offline_mode"] is True

    @pytest.mark.asyncio
    async def test_lookup_cve_offline_not_found(self):
        result = await _lookup_cve("CVE-9999-99999", offline=True)
        assert result["found"] is False
        assert result["offline_mode"] is True

    @pytest.mark.asyncio
    async def test_lookup_exploit_db_found(self):
        result = await _lookup_exploit_db("CVE-2021-41773")
        assert result["found"] is True
        assert len(result["exploits"]) > 0

    @pytest.mark.asyncio
    async def test_lookup_exploit_db_not_found(self):
        result = await _lookup_exploit_db("CVE-9999-99999")
        assert result["found"] is False
        assert result["exploits"] == []

    @pytest.mark.asyncio
    async def test_enrich_version_info(self):
        result = await _enrich_version_info("apache", "2.4.49")
        assert result["product"] == "apache"
        assert result["version"] == "2.4.49"
        assert result["vulnerabilities_found"] >= 0

    @pytest.mark.asyncio
    async def test_fetch_vendor_advisory_offline(self):
        result = await _fetch_vendor_advisory("https://example.com/advisory", offline=True)
        assert result["fetched"] is False
        assert result["offline_mode"] is True


# ─── Tool Call Extraction ─────────────────────────────────────────


class TestToolCallExtraction:
    def test_extract_json_tool_calls(self):
        agent = ResearcherAgent(_make_client())
        content = json.dumps(
            {"tool_calls": [{"name": "lookup_cve", "arguments": {"cve_id": "CVE-2021-41773"}}]}
        )
        calls = agent._extract_tool_calls(content)
        assert len(calls) == 1
        assert calls[0][0] == "lookup_cve"
        assert calls[0][1]["cve_id"] == "CVE-2021-41773"

    def test_extract_text_based_calls(self):
        agent = ResearcherAgent(_make_client())
        content = 'lookup_cve({"cve_id": "CVE-2024-3094"})'
        calls = agent._extract_tool_calls(content)
        assert len(calls) == 1
        assert calls[0][0] == "lookup_cve"

    def test_extract_no_calls(self):
        agent = ResearcherAgent(_make_client())
        calls = agent._extract_tool_calls("No tool calls here, just text.")
        assert len(calls) == 0

    def test_ignores_unknown_functions(self):
        agent = ResearcherAgent(_make_client())
        content = 'random_function({"key": "value"})'
        calls = agent._extract_tool_calls(content)
        assert len(calls) == 0


# ─── Submit Enrichment ────────────────────────────────────────────


class TestResearcherSubmitEnrichment:
    def test_handle_submit_enrichment(self):
        agent = ResearcherAgent(_make_client())
        result = agent._handle_submit_enrichment(
            {
                "observation_id": "F-001",
                "cve_details": [
                    {
                        "cve_id": "CVE-2021-41773",
                        "description": "Path traversal",
                        "cvss_score": 7.5,
                        "severity": "HIGH",
                    }
                ],
                "exploit_availability": [],
                "vendor_advisories": [],
                "data_sources": ["NVD"],
            }
        )
        assert result["status"] == "recorded"
        assert result["observation_id"] == "F-001"
        assert result["cve_count"] == 1
        assert "F-001" in agent.enrichments

    def test_handle_submit_enrichment_minimal(self):
        agent = ResearcherAgent(_make_client())
        result = agent._handle_submit_enrichment(
            {
                "observation_id": "F-002",
                "data_sources": ["manual review"],
            }
        )
        assert result["status"] == "recorded"
        assert agent.enrichments["F-002"].cve_details == []


# ─── Event Emission ──────────────────────────────────────────────


class TestResearcherEvents:
    @pytest.mark.asyncio
    async def test_emits_start_and_complete(self):
        client = _make_client(content="no tool calls")
        events = []
        agent = ResearcherAgent(
            client, event_callback=AsyncMock(side_effect=lambda e: events.append(e))
        )
        await agent.enrich_observations([_make_observation()])
        event_types = [e.event_type for e in events]
        assert EventType.RESEARCH_REQUESTED in event_types
        assert EventType.RESEARCH_COMPLETE in event_types


# ─── Stop ────────────────────────────────────────────────────────


class TestResearcherStop:
    def test_stop(self):
        agent = ResearcherAgent(_make_client())
        agent.is_running = True
        agent.stop()
        assert agent.is_running is False
