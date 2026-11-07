"""
app/grading - Probe and grade.

The capture line's upper half, still with no model in it. A check *probes* —
sends, records, and asserts nothing beyond a provisional severity — and a
*grader* reads the recorded bytes and places the final severity, confidence and
reasoning. An LLM tier is planned behind the same seam; what exists today is
the shape and the rule tier.

    from app.grading import Candidate, Evidence, GradeContext, Verdict, grade_result

Three properties hold everywhere in here:

- **The grader never touches the network.** It reads `Evidence` and nothing else,
  which is what lets it run during a scan or six months later against the corpus.
- **Ungraded never blocks.** Grading state lives on the observation (§6.3); a
  scan never waits for a grader and never drops a candidate because of one.
- **Nothing subtracts.** A verdict is attached to an observation, never used to
  remove it. Reports filter on verdict, visibly (§2).
"""

from app.grading.evidence import (
    evidence_for,
    exchange_from_payload,
    exchange_from_response,
    load_scan_evidence,
)
from app.grading.models import (
    Candidate,
    Evidence,
    GradeContext,
    GradingState,
    GradingTier,
    Verdict,
)
from app.grading.stage import grade_result, grade_result_sync, is_graded_check

__all__ = [
    "Candidate",
    "Evidence",
    "GradeContext",
    "GradingState",
    "GradingTier",
    "Verdict",
    "evidence_for",
    "exchange_from_payload",
    "exchange_from_response",
    "grade_result",
    "grade_result_sync",
    "is_graded_check",
    "load_scan_evidence",
]
