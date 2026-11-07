"""
The D-2 observation-id collision guard in the grading stage.

Observation ids are `check-host-discriminator`. A check that emits one candidate
per endpoint with a discriminator that does not name the endpoint mints the same
id twice, and the database keeps only the first. The guard renames later
colliders instead, in a way the offline re-grade reproduces.
"""

import pytest

from app.checks.base import CheckResult, Observation, Service
from app.grading import Candidate, Verdict, exchange_from_payload, grade_result
from app.grading.stage import claim_observation_id

pytestmark = pytest.mark.unit

HOST = "acme.test"


class SameDiscriminatorCheck:
    """One verdict per candidate, always with the same discriminator."""

    name = "ai_collides"

    def __init__(self, verdicts_per_candidate: int = 1):
        self.verdicts_per_candidate = verdicts_per_candidate

    def grade(self, evidence, ctx):
        return [
            Verdict(
                severity="medium",
                confidence=0.8,
                discriminator="prompt-leaked",
                title="leaked",
                tier=ctx.tier,
            )
            for _ in range(self.verdicts_per_candidate)
        ]


def _candidate(path: str) -> Candidate:
    url = f"https://{HOST}{path}"
    candidate = Candidate(
        check_name="ai_collides",
        host=HOST,
        provisional_severity="low",
        discriminator="prompt-leaked",
        target=Service(url=url, host=HOST, port=443, scheme="https"),
        target_url=url,
    )
    candidate.attach(
        exchange_from_payload("http", HOST, check_name="ai_collides", request_body=path)
    )
    return candidate


async def _grade(check, *paths) -> list[str]:
    result = CheckResult(success=True, candidates=[_candidate(p) for p in paths])
    await grade_result(check, result, {})
    return [o.id for o in result.observations]


class TestGuard:
    async def test_ids_that_do_not_collide_are_unchanged(self):
        ids = await _grade(SameDiscriminatorCheck(), "/chat")
        assert ids == ["ai_collides-acme.test-prompt-leaked"]

    async def test_a_second_endpoint_gets_a_suffix_naming_its_url(self):
        ids = await _grade(SameDiscriminatorCheck(), "/chat", "/v1/chat")

        assert ids[0] == "ai_collides-acme.test-prompt-leaked"
        assert ids[1].startswith("ai_collides-acme.test-prompt-leaked-")
        assert len(set(ids)) == 2

    async def test_the_suffix_is_stable_for_the_same_url(self):
        first = await _grade(SameDiscriminatorCheck(), "/chat", "/v1/chat")
        second = await _grade(SameDiscriminatorCheck(), "/chat", "/v1/chat")
        assert first == second

    async def test_two_verdicts_on_one_url_fall_back_to_an_ordinal(self):
        ids = await _grade(SameDiscriminatorCheck(verdicts_per_candidate=3), "/chat")

        base = "ai_collides-acme.test-prompt-leaked"
        assert ids[0] == base
        assert len(set(ids)) == 3
        assert ids[2] in {f"{base}-2", f"{base}-3"}

    async def test_a_directly_appended_observation_keeps_its_id(self):
        result = CheckResult(success=True, candidates=[_candidate("/chat")])
        result.observations.append(
            Observation(
                id="ai_collides-acme.test-prompt-leaked",
                title="t",
                description="d",
                severity="high",
                evidence="e",
            )
        )

        await grade_result(SameDiscriminatorCheck(), result, {})

        ids = [o.id for o in result.observations]
        assert ids[0] == "ai_collides-acme.test-prompt-leaked"
        assert len(set(ids)) == 2

    async def test_ungraded_candidates_are_guarded_too(self):
        class NoGrader:
            name = "ai_collides"

        ids = await _grade(NoGrader(), "/chat", "/v1/chat")
        assert len(set(ids)) == 2

    async def test_a_collision_is_logged(self, caplog):
        with caplog.at_level("WARNING", logger="app.grading.stage"):
            await _grade(SameDiscriminatorCheck(), "/chat", "/v1/chat")
        assert "Observation id collision in ai_collides" in caplog.text

    def test_claim_without_a_url_uses_an_ordinal(self):
        seen = {"x"}
        observation = Observation(id="x", title="t", description="d", severity="low", evidence="e")

        assert claim_observation_id(observation, seen) == "x-2"
        assert observation.id == "x-2"
        assert seen == {"x", "x-2"}
