"""
app/grading/models.py - The probe/grade vocabulary.

Four types sit on the capture line (§2, §6):

    Candidate      what a probe emits: a subject to be judged, carrying a
                   *provisional* severity and nothing else that resembles a
                   verdict.
    Evidence       the bytes a grader is allowed to read. Exchanges, nothing
                   parsed, nothing interpreted.
    Verdict        what a grader returns: severity, confidence, reasoning, and
                   the evidence ids the judgement was derived from.
    GradeContext   what the grader knows besides the evidence — which scan,
                   which check, which host, which tier.

An `Observation` is a graded Candidate. Until it is graded it still exists, at
its provisional severity, marked `ungraded` — grading state lives on the
observation and never on the scan (§6.3), so nothing ever stalls waiting for a
grader.

**A Candidate may yield more than one Verdict.** §6.1 describes the 1:1 case and
it is the common one, but a probe unit is an *exchange*, and one exchange can
support several independent judgements — one HTTP response carries CSP, HSTS,
CORS and Server, each its own observation. Forcing 1:1 would have meant either
parsing in the probe (to know how many candidates to emit) or one request per
judgement. Both lose more than the symmetry is worth, so a Candidate is the
subject and each Verdict names its own discriminator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from app.capture.models import Exchange

if TYPE_CHECKING:
    from app.checks.base import Service


class GradingState(StrEnum):
    """Where one observation stands with its grader. Never a scan status (§6.3)."""

    UNGRADED = "ungraded"
    GRADED = "graded"
    GRADING_FAILED = "grading_failed"
    #: An ungraded or failed placeholder that an offline re-grade replaced with
    #: verdicts under different ids. Kept rather than deleted — chains name
    #: observation ids, and nothing subtracts (§2). Set only by `regrade --apply`.
    SUPERSEDED = "superseded"


#: Rows that stand in for a candidate rather than record a verdict: shown at
#: their provisional severity and labelled as such. `superseded` is deliberately
#: not one — it has a successor, so it is excluded rather than labelled.
PLACEHOLDER_STATES = frozenset({str(GradingState.UNGRADED), str(GradingState.GRADING_FAILED)})


class GradingTier(StrEnum):
    """Which grader placed the severity. `LLM` arrives with phase 58."""

    RULE = "rule"
    LLM = "llm"
    NONE = "none"


@dataclass
class Evidence:
    """The exchanges one grader may read, and where they came from.

    `source` is part of the record rather than a debugging aid: a verdict graded
    from `corpus` is reproducible byte for byte, one graded from `memory` is not
    — capture was off for that run, so the bytes existed only while the check
    held them. Phase 58's cache keys on the difference.
    """

    exchanges: list[Exchange] = field(default_factory=list)
    source: str = "empty"  # corpus | memory | empty

    def __iter__(self):
        return iter(self.exchanges)

    def __len__(self) -> int:
        return len(self.exchanges)

    def __bool__(self) -> bool:
        return bool(self.exchanges)

    def ids(self) -> list[str]:
        """Every exchange id, for a verdict that was derived from all of them."""
        return [e.id for e in self.exchanges]

    def first(self) -> Exchange | None:
        return self.exchanges[0] if self.exchanges else None

    def latest(self) -> Exchange | None:
        return self.exchanges[-1] if self.exchanges else None

    def by_protocol(self, protocol: str) -> list[Exchange]:
        return [e for e in self.exchanges if e.protocol == protocol]

    def for_host(self, host: str) -> list[Exchange]:
        return [e for e in self.exchanges if e.host == host]

    def for_url(self, url: str) -> list[Exchange]:
        return [e for e in self.exchanges if e.request_url == url]

    def completed(self) -> list[Exchange]:
        """Exchanges that actually produced a response."""
        return [e for e in self.exchanges if e.completed]


@dataclass
class GradeContext:
    """What a grader knows besides the bytes."""

    scan_id: str = ""
    check_name: str = ""
    host: str = ""
    target: Service | None = None
    target_url: str | None = None
    tier: str = GradingTier.RULE
    #: The check's declared severity block, straight from `contract.yaml`
    #: (57.4, §7): `model`, `default`, `observations`, `range`, `rubric`,
    #: `signals`. Empty for a check that has not declared one, so readers must
    #: still treat a missing key as "not declared".
    severity: dict[str, Any] = field(default_factory=dict)
    #: The scan context dict, for graders that need an upstream check's output.
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    """A subject to be graded: identity, provisional severity, and its bytes.

    Everything an `Observation` has *except* verdict and confidence (§6.1). The
    provisional severity is what the launcher reads if grading is deferred or
    fails; it is never presented as a graded answer.
    """

    check_name: str
    host: str
    provisional_severity: str = "info"
    discriminator: str | None = None
    target: Service | None = None
    target_url: str | None = None
    raw_data: dict | None = None

    #: Exchanges this probe produced, handed over in memory. They are the
    #: grading input when capture is off — which is the default posture — and
    #: are never persisted from here: when capture *is* on the same bytes are
    #: already in the corpus, and `load_evidence` prefers that copy.
    exchanges: list[Exchange] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Observation identity, unchanged from `app/lib/observations.py`."""
        from app.lib.observations import make_observation_id

        return make_observation_id(self.check_name, self.host, self.discriminator)

    def attach(self, exchange: Exchange | None) -> Candidate:
        """Hand one exchange to the grader. `None` is ignored, so a probe can
        pass a capture result straight through without checking it."""
        if exchange is not None:
            self.exchanges.append(exchange)
        return self


@dataclass
class Verdict:
    """One graded judgement over a candidate's evidence.

    `confidence` is mandatory in spirit and defaulted in code: today's
    classifiers assert with no measure of how sure they are, which is exactly
    how a `"policy"` substring collision passes unnoticed. Phase 58 escalates on
    it, so it has to be a real number per judgement rather than a constant.

    `evidence_ids` is the candidate binding (D-22): the grader names the
    exchanges it actually read, and the stage stamps this verdict's observation
    id onto those rows. That is the join from a verdict back to the bytes that
    produced it.
    """

    severity: str
    confidence: float = 0.5
    discriminator: str | None = None
    title: str = ""
    description: str = ""
    evidence: str = ""
    reasoning: str = ""
    signals: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    raw_data: dict | None = None
    evidence_ids: list[str] = field(default_factory=list)
    tier: str = GradingTier.RULE
