"""
Grading inside a real scan loop — Phase 57 success criteria 1 and 4 (§10).

`tests/grading/test_grading.py` covers `grade_result()` in isolation. These run
it where it actually runs, inside `CheckLauncher.run_all()`, because both
criteria are claims about a *scan*, not about one function:

1. Every observation traces to evidence and a named grading tier — including the
   ones nobody graded, which must say so rather than look graded.
4. An ungraded observation never blocks a scan. A check whose grader raises, and
   a check with no grader at all, both still complete, still hand their outputs
   downstream, and still report their candidates at the provisional severity.

The assertions read the records `run_all()` returns, which are the same
`to_dict()` records the launcher streams to the observation writer — so what is
checked here is what gets persisted, not an in-memory object that might differ.

Criterion 4's second half — "a later re-grade pass fills them in without
re-scanning" — is asserted in `tests/grading/test_regrade.py`, against a scan
that ran through this same launcher.
"""

import pytest

from app.check_launcher import CheckLauncher
from app.checks.base import CheckCondition, CheckResult
from app.grading import (
    Candidate,
    Evidence,
    GradeContext,
    GradingState,
    Verdict,
    exchange_from_payload,
)

pytestmark = pytest.mark.unit

HOST = "acme.test"


class _ProbeCheck:
    """A check whose probe records one exchange and hands over one candidate."""

    def __init__(self, name, *, provisional="low", produces=None, conditions=None):
        self.name = name
        self.produces = list(produces or [])
        self.conditions = list(conditions or [])
        self._provisional = provisional

    async def execute(self, context):
        result = CheckResult(success=True)
        exchange = exchange_from_payload(
            "http", HOST, check_name=self.name, request_body="GET /", response_body="ok"
        )
        candidate = Candidate(
            check_name=self.name,
            host=HOST,
            provisional_severity=self._provisional,
            discriminator=f"{self.name}-subject",
        )
        candidate.attach(exchange)
        result.candidates.append(candidate)
        for key in self.produces:
            result.outputs[key] = True
        return result


class _GradedCheck(_ProbeCheck):
    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchange = evidence.first()
        return [
            Verdict(
                severity="medium",
                confidence=0.7,
                discriminator=f"{self.name}-subject",
                title=f"{self.name} verdict",
                reasoning="the recorded response says so",
                tier=ctx.tier,
                evidence_ids=[exchange.id],
            )
        ]


class _RaisingCheck(_ProbeCheck):
    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        raise RuntimeError("grader blew up")


def _by_check(records):
    return {record["check_name"]: record for record in records}


async def _scan():
    raising = _RaisingCheck("web_raising", provisional="high", produces=["raising_done"])
    ungraded = _ProbeCheck("web_ungraded", provisional="low")
    downstream = _GradedCheck(
        "web_downstream", conditions=[CheckCondition("raising_done", "truthy")]
    )
    launcher = CheckLauncher([raising, ungraded, downstream], {})
    records = await launcher.run_all()
    return launcher, records


# ── Criterion 4: ungraded never blocks ───────────────────────────────


async def test_a_raising_grader_does_not_fail_the_check_or_the_scan():
    launcher, records = await _scan()

    assert launcher.failed == set()
    assert {"web_raising", "web_ungraded", "web_downstream"} <= launcher.completed
    assert len(records) == 3


async def test_a_check_whose_grader_raised_still_feeds_its_dependents():
    launcher, records = await _scan()

    assert launcher.context.get("raising_done") is True
    assert _by_check(records)["web_downstream"]["grading_state"] == str(GradingState.GRADED)


async def test_failed_and_missing_graders_report_at_the_provisional_severity():
    _, records = await _scan()
    by_check = _by_check(records)

    failed = by_check["web_raising"]
    assert failed["grading_state"] == str(GradingState.GRADING_FAILED)
    assert failed["severity"] == "high"
    assert failed["provisional_severity"] == "high"
    assert failed["confidence"] is None
    assert "grader blew up" in (failed["grading_reasoning"] or "")

    missing = by_check["web_ungraded"]
    assert missing["grading_state"] == str(GradingState.UNGRADED)
    assert missing["severity"] == "low"
    assert missing["confidence"] is None


# ── Criterion 1: every observation traces to evidence and a tier ─────


async def test_every_record_names_its_grading_state_tier_and_evidence():
    _, records = await _scan()

    for record in records:
        name = record["check_name"]
        assert record["grading_state"] in {str(s) for s in GradingState}, name
        assert record["grading_tier"], f"{name} names no grading tier"
        assert record["evidence_ids"], f"{name} traces to no exchange"
        assert record["evidence_source"] in {"corpus", "memory"}, name


async def test_graded_and_ungraded_records_are_told_apart_by_tier():
    _, records = await _scan()
    by_check = _by_check(records)

    assert by_check["web_downstream"]["grading_tier"] == "rule"
    assert by_check["web_downstream"]["confidence"] == 0.7
    assert by_check["web_raising"]["grading_tier"] == "none"
    assert by_check["web_ungraded"]["grading_tier"] == "none"


async def test_the_graded_verdict_binds_the_exchange_it_read():
    """The candidate binding (D-22): a verdict names the exchange it was derived
    from, and that id reaches the persisted record."""
    _, records = await _scan()
    downstream = _by_check(records)["web_downstream"]

    assert len(downstream["evidence_ids"]) == 1
    assert downstream["evidence_source"] == "memory"
