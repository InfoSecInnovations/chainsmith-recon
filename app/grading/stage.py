"""
app/grading/stage.py - The grading stage.

A **separate stage**, not a step inside `BaseCheck.execute()`. The check runs,
returns its candidates, and then this stage grades them. That placement is the
point: the same function that grades during a scan grades a stored corpus six
months later, and neither path is privileged.

    result = await check.execute(context)
    await grade_result(check, result, context)   # <- here

**Ungraded never blocks** (§6.3). A check with no `grade()`, a grader that
raises, a corpus that cannot be read — each produces an observation at its
*provisional* severity, marked `ungraded` or `grading_failed`, and the scan goes
on. Nothing stalls, nothing is dropped, and the gap is on the record instead of
being silent.

**Legacy checks are untouched.** A check that appends to `result.observations`
the way all of them did before 57.3 emits no candidates, and this stage returns
on its first line. 57.4 migrates them; until then both shapes run side by side,
and a half-migrated check (some candidates, some direct observations) works too.

**A capturing scan leaves a grading record** (57.4). Before grading, the stage
writes the candidates and the context it is about to grade against beside the
corpus (`app/grading/record.py`). That is what lets `app/grading/regrade.py`
replay this very call later, from the workspace alone.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
from typing import TYPE_CHECKING, Any

from app.grading.evidence import evidence_for, load_scan_evidence
from app.grading.models import (
    Candidate,
    Evidence,
    GradeContext,
    GradingState,
    GradingTier,
    Verdict,
)
from app.grading.record import record_grading

if TYPE_CHECKING:
    from app.capture.models import Exchange
    from app.checks.base import CheckResult, Observation

logger = logging.getLogger(__name__)


def is_graded_check(check: Any) -> bool:
    """True when a check has been migrated to probe/grade."""
    return callable(getattr(check, "grade", None))


async def grade_result(
    check: Any,
    result: CheckResult,
    context: dict[str, Any] | None = None,
    *,
    stored: list[Exchange] | None = None,
    bind: bool = True,
    persist: bool = True,
    seen_ids: set[str] | None = None,
) -> CheckResult:
    """
    Grade every candidate on one check result, in place.

    Appends one observation per verdict to `result.observations` and clears the
    candidates it consumed. Returns the same result for convenience.

    The keyword arguments belong to the offline re-grade and a scan never passes
    them: it hands over the corpus it already read (`stored`), must not stamp
    bindings while it is only computing a diff (`bind`), and must not overwrite
    the grading record it is replaying (`persist`). The re-grade also grades one
    candidate per call, so it passes one `seen_ids` set per check across those
    calls. That way the collision guard (`claim_observation_id`) gives the same
    ids it gave at scan time.
    """
    candidates = list(getattr(result, "candidates", None) or [])
    if not candidates:
        return result

    # Ids already taken in this check's result. Seeded with any observations the
    # check appended directly (a legacy or custom check), which keep their ids.
    if seen_ids is None:
        seen_ids = set()
    seen_ids.update(o.id for o in result.observations if getattr(o, "id", None))

    context = context or {}
    scan_id = context.get("scan_id") or ""
    check_name = getattr(check, "name", "") or result.check_name
    if stored is None:
        stored = load_scan_evidence(scan_id, check_name)
    grader = getattr(check, "grade", None)

    # Written before grading, so a grader that raises still leaves something a
    # fixed grader can replay later. No-op when the scan is not capturing.
    if persist:
        record_grading(scan_id, check_name, candidates, context)

    bindings: list[tuple[str, list[str]]] = []

    for candidate in candidates:
        evidence = evidence_for(candidate, stored)
        ctx = GradeContext(
            scan_id=scan_id,
            check_name=check_name,
            host=candidate.host,
            target=candidate.target,
            target_url=candidate.target_url,
            tier=GradingTier.RULE,
            severity=dict(getattr(check, "severity", None) or {}),
            context=context,
        )

        if grader is None:
            observation = _ungraded(candidate, GradingState.UNGRADED, evidence)
            claim_observation_id(observation, seen_ids)
            result.observations.append(observation)
            continue

        try:
            verdicts = await _invoke(grader, evidence, ctx)
        except Exception as exc:
            # A grader that raises must not cost the scan its candidate. The
            # provisional severity stands, and the failure is on the record.
            logger.warning(
                "Grading failed for %s (%s): %s", check_name, candidate.id, exc, exc_info=True
            )
            observation = _ungraded(
                candidate, GradingState.GRADING_FAILED, evidence, reason=str(exc)
            )
            claim_observation_id(observation, seen_ids)
            result.observations.append(observation)
            continue

        for verdict in verdicts or []:
            observation = _observation_from(candidate, verdict, evidence)
            claim_observation_id(observation, seen_ids)
            result.observations.append(observation)
            ids = verdict.evidence_ids or evidence.ids()
            if ids:
                bindings.append((observation.id, ids))

    result.candidates = []

    if bind and bindings and scan_id:
        await _bind(scan_id, bindings)

    return result


def claim_observation_id(observation: Observation, seen: set[str]) -> str:
    """Give `observation` an id no earlier observation in this check has taken.

    This is the D-2 guard. Observation ids are `check-host-discriminator`. A check
    that emits one candidate per endpoint with a discriminator that does not name
    the endpoint, or the same hostname on two ports, mints the same id twice. The
    database rejects the second row, so before this guard the writer kept it out
    of the scan.

    The first observation keeps its bare id, so ids that never collide do not
    change. A later one gets a suffix. The suffix is a short hash of its target
    URL when it has one, so the suffix names the endpoint. Which observation keeps
    the bare id still depends on grading order. If that is also taken (one grade() returned
    two verdicts with the same discriminator on the same URL), the suffix is an
    ordinal, `-2`, `-3`, in grading order. Grading order is the recorded
    candidate order, so the offline re-grade reproduces it.

    Mutates `observation.id`, records the id in `seen`, and returns it.
    """
    base = observation.id
    if base not in seen:
        seen.add(base)
        return base

    new_id = None
    url = getattr(observation, "target_url", None) or ""
    if url:
        hashed = f"{base}-{hashlib.sha256(url.encode()).hexdigest()[:6]}"
        if hashed not in seen:
            new_id = hashed
    n = 2
    while new_id is None:
        if f"{base}-{n}" not in seen:
            new_id = f"{base}-{n}"
        n += 1

    logger.warning(
        "Observation id collision in %s: %r already used; renamed to %r. "
        "The check's discriminator does not tell these observations apart.",
        observation.check_name,
        base,
        new_id,
    )
    observation.id = new_id
    seen.add(new_id)
    return new_id


async def _invoke(grader: Any, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
    """Call `grade()` whether it was written sync or async, and normalise a
    single verdict to a list — returning one is the common case and making
    authors wrap it in a list would be noise."""
    outcome = grader(evidence, ctx)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    if outcome is None:
        return []
    if isinstance(outcome, Verdict):
        return [outcome]
    return list(outcome)


def _observation_from(candidate: Candidate, verdict: Verdict, evidence: Evidence) -> Observation:
    """A graded Candidate is an Observation (§6.1)."""
    from app.checks.base import Observation
    from app.lib.observations import make_observation_id

    discriminator = verdict.discriminator or candidate.discriminator
    raw_data = dict(candidate.raw_data or {})
    raw_data.update(verdict.raw_data or {})

    return Observation(
        id=make_observation_id(candidate.check_name, candidate.host, discriminator),
        title=verdict.title,
        description=verdict.description,
        severity=verdict.severity,
        evidence=verdict.evidence,
        target=candidate.target,
        target_url=candidate.target_url or (candidate.target.url if candidate.target else None),
        target_host=candidate.host,
        check_name=candidate.check_name,
        raw_data=raw_data or None,
        references=list(verdict.references or []),
        provisional_severity=candidate.provisional_severity,
        confidence=verdict.confidence,
        grading_state=str(GradingState.GRADED),
        grading_tier=str(verdict.tier),
        grading_reasoning=verdict.reasoning or None,
        evidence_ids=list(verdict.evidence_ids or evidence.ids()),
        evidence_source=evidence.source,
        signals=dict(verdict.signals or {}) or None,
    )


def _ungraded(
    candidate: Candidate,
    state: GradingState,
    evidence: Evidence,
    reason: str | None = None,
) -> Observation:
    """An observation nobody graded, at the severity the probe assumed.

    It is reported, not hidden: §6.3's whole argument is that a gap in grading
    should be visible in the output rather than stall the scan or vanish from it.
    """
    from app.checks.base import Observation

    subject = candidate.discriminator or candidate.check_name
    return Observation(
        id=candidate.id,
        title=f"Ungraded: {subject} on {candidate.host}",
        description=(
            "This candidate was recorded but not graded"
            + (f" ({reason})" if reason else "")
            + ". Its severity is the probe's provisional value, not a verdict."
        ),
        severity=candidate.provisional_severity,
        evidence=f"{len(evidence)} exchange(s) captured ({evidence.source})",
        target=candidate.target,
        target_url=candidate.target_url or (candidate.target.url if candidate.target else None),
        target_host=candidate.host,
        check_name=candidate.check_name,
        raw_data=candidate.raw_data,
        provisional_severity=candidate.provisional_severity,
        confidence=None,
        grading_state=str(state),
        grading_tier=str(GradingTier.NONE),
        grading_reasoning=reason,
        evidence_ids=evidence.ids(),
        evidence_source=evidence.source,
    )


async def _bind(scan_id: str, bindings: list[tuple[str, list[str]]]) -> None:
    """Stamp each verdict's observation id onto the exchanges it was graded from.

    This is the candidate binding (D-22), done from the grade side: the grader
    names what it read, and the join from a verdict back to its bytes is exact
    rather than declared up front by a probe that did not yet know what it had.
    Best-effort, like every other capture write — a corpus with an unstamped row
    is still a corpus.
    """
    from app import capture

    for observation_id, exchange_ids in bindings:
        try:
            await capture.bind_candidate(scan_id, exchange_ids, observation_id)
        except Exception:
            logger.debug("Candidate binding failed for %s", observation_id, exc_info=True)


def grade_result_sync(check: Any, result: CheckResult, context: dict[str, Any]) -> CheckResult:
    """Blocking entry point, for tooling and tests outside an event loop."""
    return asyncio.run(grade_result(check, result, context))
