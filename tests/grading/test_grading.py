"""
Tests for the probe/grade framework — Phase 57.3, design §6.

The properties that matter here are structural, not about any one check:

- A grader reads evidence and nothing else, so the same bytes give the same
  verdict whether they came from the corpus or from the probe's own hand-off.
- Ungraded never blocks. A missing grader, a raising grader, an unreadable
  corpus — each produces an observation at its provisional severity, marked,
  and the scan goes on.
- Nothing subtracts. A verdict is attached to an observation; suppression is
  reported rather than applied by removal.
"""

import pytest

from app.checks.base import CheckResult, Observation, Service
from app.grading import (
    Candidate,
    Evidence,
    GradeContext,
    GradingState,
    Verdict,
    evidence_for,
    exchange_from_payload,
    exchange_from_response,
    grade_result,
    is_graded_check,
)
from app.lib.http import HttpResponse
from app.lib.observations import partition_by_verdict, suppression_note

pytestmark = pytest.mark.unit


def make_service() -> Service:
    return Service(
        url="https://acme.test",
        host="acme.test",
        port=443,
        scheme="https",
        service_type="http",
    )


def make_response(headers: dict | None = None, **overrides) -> HttpResponse:
    base = {
        "url": "https://acme.test",
        "status_code": 200,
        "headers": headers or {"Server": "nginx/1.2.3"},
        "body": "hello",
        "elapsed_ms": 12.0,
    }
    base.update(overrides)
    return HttpResponse(**base)


def make_candidate(**overrides) -> Candidate:
    base = {
        "check_name": "web_header_analysis",
        "host": "acme.test",
        "provisional_severity": "low",
    }
    base.update(overrides)
    return Candidate(**base)


class ProbeOnlyCheck:
    """A check whose probe ran but which has no grader yet."""

    name = "web_probe_only"


class GradedCheck(ProbeOnlyCheck):
    name = "web_graded"

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchange = evidence.first()
        return [
            Verdict(
                severity="high",
                confidence=0.9,
                discriminator="found-it",
                title="Found it",
                description="The evidence says so",
                evidence="Server: nginx",
                reasoning="because the recorded response says so",
                signals={"host": ctx.host},
                evidence_ids=[exchange.id] if exchange else [],
            )
        ]


class AsyncGradedCheck(ProbeOnlyCheck):
    name = "web_async_graded"

    async def grade(self, evidence: Evidence, ctx: GradeContext) -> Verdict:
        return Verdict(severity="medium", confidence=0.5, discriminator="async", title="Async")


class BrokenGradedCheck(ProbeOnlyCheck):
    name = "web_broken"

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        raise RuntimeError("rubric is malformed")


# ═══════════════════════════════════════════════════════════════════
# Candidate and Verdict
# ═══════════════════════════════════════════════════════════════════


class TestCandidate:
    def test_candidate_id_matches_observation_identity(self):
        """Observation identity is unchanged by 57.3 (§6.1)."""
        candidate = make_candidate(discriminator="missing-csp")
        assert candidate.id == "web_header_analysis-acme.test-missing-csp"

    def test_candidate_carries_a_provisional_severity(self):
        """The launcher needs an answer before grading (§6.1)."""
        assert make_candidate().provisional_severity == "low"

    def test_attach_ignores_none(self):
        """A probe can pass a capture result straight through: when capture is
        off `record()` returns None and the probe should not have to care."""
        candidate = make_candidate()
        candidate.attach(None)
        assert candidate.exchanges == []

    def test_attach_collects_exchanges(self):
        candidate = make_candidate()
        candidate.attach(exchange_from_payload("dns", "acme.test", check_name="c"))
        assert len(candidate.exchanges) == 1


# ═══════════════════════════════════════════════════════════════════
# Evidence resolution
# ═══════════════════════════════════════════════════════════════════


class TestEvidenceResolution:
    def test_probe_handoff_is_used_when_the_corpus_is_empty(self):
        """Capture is off by default; grading still has to work (§0.4)."""
        candidate = make_candidate()
        candidate.attach(exchange_from_response(make_response(), check_name="web_header_analysis"))

        evidence = evidence_for(candidate, [])

        assert evidence.source == "memory"
        assert len(evidence) == 1

    def test_the_corpus_copy_wins_and_brings_its_id(self):
        """Matched by content_hash: same request, same response, same bytes.

        The stored row is the one that can be bound to a verdict, because only
        it has the store's exchange id.
        """
        stored = exchange_from_response(make_response(), check_name="web_header_analysis")
        stored.id = "stored-id"
        in_memory = exchange_from_response(make_response(), check_name="web_header_analysis")

        candidate = make_candidate()
        candidate.attach(in_memory)

        evidence = evidence_for(candidate, [stored])

        assert evidence.source == "corpus"
        assert evidence.ids() == ["stored-id"]

    def test_different_bytes_do_not_pair(self):
        stored = exchange_from_response(
            make_response(headers={"Server": "apache"}), check_name="web_header_analysis"
        )
        candidate = make_candidate()
        candidate.attach(exchange_from_response(make_response(), check_name="web_header_analysis"))

        evidence = evidence_for(candidate, [stored])

        assert evidence.source == "memory"

    def test_corpus_is_scoped_to_the_candidates_host(self):
        mine = exchange_from_payload("dns", "acme.test", check_name="c", response_body="1.2.3.4")
        theirs = exchange_from_payload("dns", "other.test", check_name="c", response_body="5.6.7.8")

        evidence = evidence_for(make_candidate(), [mine, theirs])

        assert evidence.source == "corpus"
        assert [e.host for e in evidence] == ["acme.test"]

    def test_no_evidence_at_all_is_a_valid_state(self):
        evidence = evidence_for(make_candidate(), [])
        assert evidence.source == "empty"
        assert not evidence


class TestEvidenceHelpers:
    def test_completed_excludes_failed_probes(self):
        ok = exchange_from_payload("http", "acme.test", check_name="c")
        failed = exchange_from_payload("http", "acme.test", check_name="c", error="timeout")
        evidence = Evidence([ok, failed], "memory")
        assert evidence.completed() == [ok]

    def test_by_protocol_and_for_url(self):
        http = exchange_from_response(make_response(), check_name="c")
        dns = exchange_from_payload("dns", "acme.test", check_name="c")
        evidence = Evidence([http, dns], "memory")

        assert evidence.by_protocol("dns") == [dns]
        assert evidence.for_url("https://acme.test") == [http]


# ═══════════════════════════════════════════════════════════════════
# The stage
# ═══════════════════════════════════════════════════════════════════


class TestGradingStage:
    async def test_legacy_checks_pass_straight_through(self):
        """A check written before 57.3 emits no candidates and is untouched."""
        result = CheckResult(success=True)
        result.observations.append(
            Observation(id="x", title="t", description="d", severity="high", evidence="e")
        )

        await grade_result(ProbeOnlyCheck(), result, {})

        assert len(result.observations) == 1
        assert result.observations[0].grading_state == "ungraded"

    async def test_a_graded_candidate_becomes_an_observation(self):
        result = CheckResult(success=True)
        candidate = make_candidate(check_name="web_graded", target=make_service())
        candidate.attach(exchange_from_response(make_response(), check_name="web_graded"))
        result.candidates.append(candidate)

        await grade_result(GradedCheck(), result, {})

        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.id == "web_graded-acme.test-found-it"
        assert observation.severity == "high"
        assert observation.confidence == 0.9
        assert observation.grading_state == GradingState.GRADED
        assert observation.grading_tier == "rule"
        assert observation.grading_reasoning
        assert observation.evidence_source == "memory"
        assert observation.target_host == "acme.test"

    async def test_the_provisional_severity_is_kept_alongside_the_graded_one(self):
        """ "Provisional low, graded high" must be inspectable, not overwritten (§6.1)."""
        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_graded"))

        await grade_result(GradedCheck(), result, {})

        observation = result.observations[0]
        assert observation.severity == "high"
        assert observation.provisional_severity == "low"

    async def test_candidates_are_consumed(self):
        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_graded"))

        await grade_result(GradedCheck(), result, {})

        assert result.candidates == []

    async def test_an_async_grader_works_and_a_single_verdict_needs_no_list(self):
        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_async_graded"))

        await grade_result(AsyncGradedCheck(), result, {})

        assert len(result.observations) == 1
        assert result.observations[0].severity == "medium"

    async def test_an_ungraded_candidate_is_still_reported(self):
        """Ungraded never blocks and is never dropped (§6.3)."""
        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_probe_only"))

        await grade_result(ProbeOnlyCheck(), result, {})

        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.grading_state == GradingState.UNGRADED
        assert observation.severity == "low"  # the provisional value
        assert observation.confidence is None

    async def test_a_raising_grader_costs_a_verdict_not_the_candidate(self):
        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_broken"))

        await grade_result(BrokenGradedCheck(), result, {})

        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.grading_state == GradingState.GRADING_FAILED
        assert "rubric is malformed" in (observation.grading_reasoning or "")

    async def test_one_candidate_can_yield_several_verdicts(self):
        """One response, several independent judgements — see models.py."""

        class MultiCheck(ProbeOnlyCheck):
            name = "web_multi"

            def grade(self, evidence, ctx):
                return [
                    Verdict(severity="low", discriminator="a", title="A"),
                    Verdict(severity="high", discriminator="b", title="B"),
                ]

        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_multi"))

        await grade_result(MultiCheck(), result, {})

        assert [o.id for o in result.observations] == [
            "web_multi-acme.test-a",
            "web_multi-acme.test-b",
        ]

    async def test_a_grader_that_finds_nothing_emits_nothing(self):
        class QuietCheck(ProbeOnlyCheck):
            name = "web_quiet"

            def grade(self, evidence, ctx):
                return []

        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_quiet"))

        await grade_result(QuietCheck(), result, {})

        assert result.observations == []

    async def test_is_graded_check(self):
        assert is_graded_check(GradedCheck())
        assert not is_graded_check(ProbeOnlyCheck())


# ═══════════════════════════════════════════════════════════════════
# Candidate binding (D-22)
# ═══════════════════════════════════════════════════════════════════


class TestCandidateBinding:
    async def test_a_verdict_binds_the_exchanges_it_read(self, monkeypatch):
        """The grade-side join: the grader names what it read, the stage records it."""
        bound: list[tuple[str, list[str], str]] = []

        async def fake_bind(scan_id, exchange_ids, candidate_id):
            bound.append((scan_id, list(exchange_ids), candidate_id))
            return len(exchange_ids)

        from app import capture

        monkeypatch.setattr(capture, "bind_candidate", fake_bind)

        result = CheckResult(success=True)
        candidate = make_candidate(check_name="web_graded")
        exchange = exchange_from_response(make_response(), check_name="web_graded")
        candidate.attach(exchange)
        result.candidates.append(candidate)

        await grade_result(GradedCheck(), result, {"scan_id": "scan-1"})

        assert bound == [("scan-1", [exchange.id], "web_graded-acme.test-found-it")]

    async def test_binding_failure_does_not_break_the_scan(self, monkeypatch):
        async def boom(*args, **kwargs):
            raise RuntimeError("database is gone")

        from app import capture

        monkeypatch.setattr(capture, "bind_candidate", boom)

        result = CheckResult(success=True)
        candidate = make_candidate(check_name="web_graded")
        candidate.attach(exchange_from_response(make_response(), check_name="web_graded"))
        result.candidates.append(candidate)

        await grade_result(GradedCheck(), result, {"scan_id": "scan-1"})

        assert len(result.observations) == 1

    async def test_nothing_is_bound_without_a_scan(self, monkeypatch):
        """A row with no scan cannot be linked to anything."""
        called = False

        async def fake_bind(*args, **kwargs):
            nonlocal called
            called = True

        from app import capture

        monkeypatch.setattr(capture, "bind_candidate", fake_bind)

        result = CheckResult(success=True)
        result.candidates.append(make_candidate(check_name="web_graded"))

        await grade_result(GradedCheck(), result, {})

        assert called is False


class TestStoreBinding:
    def test_the_document_records_the_binding(self, tmp_path):
        """The document is the evidence: a corpus without its index still has
        to answer which verdict came from these bytes."""
        from app.capture.store import EvidenceStore

        store = EvidenceStore(root=tmp_path / "evidence")
        exchange = exchange_from_response(make_response(), check_name="c")
        exchange.scan_id = "scan-1"
        store.write(exchange)

        assert store.bind_candidate("scan-1", exchange.id, "obs-1") is True
        assert store.read("scan-1", exchange.id).candidate_id == "obs-1"

    def test_binding_a_missing_document_is_not_an_error(self, tmp_path):
        from app.capture.store import EvidenceStore

        store = EvidenceStore(root=tmp_path / "evidence")
        assert store.bind_candidate("scan-1", "nope", "obs-1") is False

    def test_binding_leaves_the_hashes_alone(self, tmp_path):
        """They identify what was captured, not what a grader decided later."""
        from app.capture.store import EvidenceStore

        store = EvidenceStore(root=tmp_path / "evidence")
        exchange = exchange_from_response(make_response(), check_name="c")
        exchange.scan_id = "scan-1"
        store.write(exchange)
        before = (exchange.probe_hash, exchange.content_hash)

        store.bind_candidate("scan-1", exchange.id, "obs-1")
        after = store.read("scan-1", exchange.id)

        assert (after.probe_hash, after.content_hash) == before


# ═══════════════════════════════════════════════════════════════════
# Suppression, not subtraction (§2)
# ═══════════════════════════════════════════════════════════════════


class TestSuppression:
    def test_rejected_observations_are_partitioned_not_dropped(self):
        observations = [
            {"id": "a", "verification_status": "verified"},
            {"id": "b", "verification_status": "rejected"},
            {"id": "c", "verification_status": "hallucination"},
            {"id": "d"},
        ]

        carried, suppressed = partition_by_verdict(observations)

        assert [o["id"] for o in carried] == ["a", "d"]
        assert [o["id"] for o in suppressed] == ["b", "c"]

    def test_the_note_is_operator_facing(self):
        assert suppression_note([]) == ""
        assert suppression_note([1]) == "1 observation suppressed by Verifier"
        assert suppression_note([1, 2]) == "2 observations suppressed by Verifier"


# ═══════════════════════════════════════════════════════════════════
# The record carries grading across layers
# ═══════════════════════════════════════════════════════════════════


class TestObservationRecord:
    def test_grading_state_survives_to_dict(self):
        observation = Observation(
            id="x",
            title="t",
            description="d",
            severity="high",
            evidence="e",
            provisional_severity="low",
            confidence=0.9,
            grading_state="graded",
            grading_tier="rule",
            evidence_ids=["ex1"],
            evidence_source="corpus",
        )

        as_dict = observation.to_dict()

        assert as_dict["provisional_severity"] == "low"
        assert as_dict["grading_state"] == "graded"
        assert as_dict["evidence_ids"] == ["ex1"]
        assert as_dict["evidence_source"] == "corpus"

    def test_grading_survives_the_model_layer_round_trip(self):
        """An agent must be able to tell a verdict from a probe's guess."""
        from app.lib.observations import check_to_model_observation, model_to_check_observation

        original = Observation(
            id="x",
            title="t",
            description="d",
            severity="high",
            evidence="e",
            target_host="acme.test",
            check_name="web_graded",
            provisional_severity="low",
            confidence=0.9,
            grading_state="graded",
            grading_tier="rule",
            grading_reasoning="because",
            evidence_ids=["ex1"],
            evidence_source="corpus",
        )

        round_tripped = model_to_check_observation(check_to_model_observation(original))

        assert round_tripped.grading_state == "graded"
        assert round_tripped.provisional_severity == "low"
        assert round_tripped.confidence == 0.9
        assert round_tripped.evidence_ids == ["ex1"]
        assert round_tripped.evidence_source == "corpus"
