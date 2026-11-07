"""
Lab backports 4a and 4b: engine visibility.

4a: a check's `result.errors` are logged on the local launcher path, not only
    forwarded by the swarm, so "failed on every target" no longer looks like
    "found nothing".
4b: rule-based chains are saved before the LLM chain pass starts, and that pass
    has a timeout, so a slow or hung model cannot hide every chain.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from app.check_launcher import CheckLauncher
from app.checks.base import CheckResult
from app.config import ChainsConfig, get_config
from app.engine import chains as chains_mod
from app.lib.llm import LLMErrorType
from app.scan_session import ScanSession

pytestmark = pytest.mark.unit


# ── 4a ───────────────────────────────────────────────────────────────


class _ErroringCheck:
    name = "web_erroring"
    conditions: list = []
    produces: list = []

    async def execute(self, context):
        return CheckResult(
            success=True,
            errors=["http://a.test: timed out", "http://b.test: Out of scope"],
        )


class _CleanCheck(_ErroringCheck):
    name = "web_clean"

    async def execute(self, context):
        return CheckResult(success=True)


async def test_result_errors_are_logged_with_count_and_first(caplog):
    with caplog.at_level(logging.WARNING, logger="app.check_launcher"):
        await CheckLauncher([_ErroringCheck()], {}).run_all()

    assert "web_erroring reported 2 error(s); first: http://a.test: timed out" in caplog.text


async def test_a_check_without_errors_logs_no_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="app.check_launcher"):
        await CheckLauncher([_CleanCheck()], {}).run_all()

    assert "reported" not in caplog.text


# ── 4b ───────────────────────────────────────────────────────────────


RULE_CHAIN = {"id": "C-001", "title": "rule chain", "source": "rule-based", "observations": []}


@pytest.fixture
def recorded(monkeypatch):
    """Replace the DB writes and the rule pass, recording the call order."""
    calls: list[tuple] = []

    async def persist(scan_id, chains):
        calls.append(("persist", [c["id"] for c in chains]))

    async def status(scan_id, **fields):
        calls.append(("status", fields.get("chain_status")))

    async def load(scan_id):
        return [{"id": "obs-1", "title": "t", "severity": "high"}]

    monkeypatch.setattr(chains_mod, "_persist_chains", persist)
    monkeypatch.setattr(chains_mod, "_update_chain_status_in_db", status)
    monkeypatch.setattr(chains_mod, "_load_observations_for_chains", load)
    monkeypatch.setattr(chains_mod, "detect_rule_based_chains", lambda obs: [dict(RULE_CHAIN)])

    async def no_proactive(session, count):
        return None

    monkeypatch.setattr(chains_mod, "_emit_chain_identified_proactive", no_proactive)
    return calls


def _session() -> ScanSession:
    session = ScanSession(id="scan-chains-1", target="example.com")
    session.chain_status = "analyzing"
    return session


async def test_rule_chains_are_saved_before_the_llm_pass_starts(recorded, monkeypatch):
    seen_at_llm_start: list = []

    async def llm(session, observations, existing):
        seen_at_llm_start.extend(recorded)
        return chains_mod.ChainAnalysisResult(llm_status="not_configured")

    monkeypatch.setattr(chains_mod, "detect_llm_chains", llm)

    await chains_mod.run_chain_analysis(_session())

    assert ("persist", ["C-001"]) in seen_at_llm_start
    assert ("status", "rules_done") in seen_at_llm_start
    assert recorded[-1] == ("status", "complete")


async def test_a_hung_llm_pass_times_out_and_keeps_rule_chains(recorded, monkeypatch):
    monkeypatch.setattr(get_config(), "chains", ChainsConfig(llm_timeout_seconds=1))

    async def hung(session, observations, existing):
        await asyncio.sleep(30)

    monkeypatch.setattr(chains_mod, "detect_llm_chains", hung)
    session = _session()

    await asyncio.wait_for(chains_mod.run_chain_analysis(session), timeout=10)

    assert session.chain_status == "partial"
    assert recorded[-2] == ("persist", ["C-001"])
    assert recorded[-1] == ("status", "partial")


async def test_the_timeout_is_reported_as_a_retryable_llm_failure(monkeypatch):
    monkeypatch.setattr(get_config(), "chains", ChainsConfig(llm_timeout_seconds=1))

    async def hung(session, observations, existing):
        await asyncio.sleep(30)

    monkeypatch.setattr(chains_mod, "detect_llm_chains", hung)

    result = await chains_mod._detect_llm_chains_bounded(_session(), [], 0)
    analysis = result.to_analysis_dict()

    assert result.llm_status == "failed"
    assert analysis["error_type"] == LLMErrorType.TIMEOUT.value
    assert analysis["retryable"] is True
    assert "timed out after 1s" in analysis["error_message"]


def test_the_chains_yaml_block_sets_the_timeout():
    from app.config import ChainsmithConfig, _apply_yaml

    cfg = ChainsmithConfig()
    assert cfg.chains.llm_timeout_seconds == 300

    _apply_yaml(cfg, {"chains": {"llm_timeout_seconds": "45"}})
    assert cfg.chains.llm_timeout_seconds == 45
