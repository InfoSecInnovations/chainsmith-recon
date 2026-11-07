"""
app/lib/observations.py - Observation Builder

Stable observation ID generation and structured observation construction.

ID Format: {check_id}-{host}-{discriminator}
  - check_id:      check name, e.g. "headers"
  - host:          target hostname, e.g. "www.example.com"
  - discriminator: per-check qualifier, e.g. "missing-csp" (optional)

Examples:
  dns-www.example.com
  headers-www.example.com-missing-csp
  headers-www.example.com-missing-hsts
  llm_endpoint-chat.example.com
"""

import hashlib
import re

from app.checks.base import Observation, Service
from app.checks.base import Observation as CheckObservation
from app.lib.timeutils import now_utc
from app.models import Observation as ModelObservation
from app.models import ObservationSeverity, ObservationStatus


def _slugify(value: str) -> str:
    """Convert a value to a safe slug for use in observation IDs."""
    value = value.lower().strip()
    # Replace colons and slashes (ports, paths) with dashes
    value = re.sub(r"[:/]", "-", value)
    # Remove any character that isn't alphanumeric, dash, or dot
    value = re.sub(r"[^a-z0-9_\-.]", "", value)
    # Collapse multiple dashes
    value = re.sub(r"-{2,}", "-", value)
    return value.strip("-")


def make_observation_id(
    check_id: str,
    host: str,
    discriminator: str | None = None,
) -> str:
    """
    Generate a stable, human-readable observation ID.

    Args:
        check_id:      The check's name attribute (e.g. "dns_enumeration")
        host:          The target host (e.g. "www.example.com" or "10.0.0.1:8080")
        discriminator: Optional per-observation qualifier (e.g. "missing-csp")

    Returns:
        e.g. "dns_enumeration-www.example.com"
             "headers-www.example.com-missing-csp"
    """
    parts = [_slugify(check_id), _slugify(host)]
    if discriminator:
        parts.append(_slugify(discriminator))
    return "-".join(p for p in parts if p)


def make_observation_id_hashed(
    check_id: str,
    host: str,
    discriminator: str | None = None,
    extra: str | None = None,
) -> str:
    """
    Generate a stable ID with a short hash suffix for high-cardinality observations.

    Useful when discriminators might collide (e.g. many path observations on same host).

    Returns:
        e.g. "paths-www.example.com-admin-a3f2"
    """
    base = make_observation_id(check_id, host, discriminator)
    payload = f"{check_id}:{host}:{discriminator or ''}:{extra or ''}"
    suffix = hashlib.sha256(payload.encode()).hexdigest()[:4]
    return f"{base}-{suffix}"


def build_observation(
    check_name: str,
    title: str,
    description: str,
    severity: str,
    evidence: str,
    host: str,
    discriminator: str | None = None,
    target: Service | None = None,
    target_url: str | None = None,
    raw_data: dict | None = None,
    references: list[str] | None = None,
) -> Observation:
    """
    Construct an Observation with a stable ID.

    Args:
        check_name:    The check's name (used for ID prefix)
        title:         Brief description of the observation
        description:   Detailed explanation
        severity:      info | low | medium | high | critical
        evidence:      Raw proof (header value, response snippet, etc.)
        host:          Target hostname (used for ID)
        discriminator: Optional per-check qualifier for ID uniqueness
        target:        Service object (optional)
        target_url:    Specific URL (optional, falls back to target.url)
        raw_data:      Full raw data dict (optional)
        references:    CVE, OWASP, etc. (optional)

    Returns:
        Observation with stable ID assigned
    """
    observation_id = make_observation_id(check_name, host, discriminator)

    return Observation(
        id=observation_id,
        title=title,
        description=description,
        severity=severity,
        evidence=evidence,
        target=target,
        target_url=target_url or (target.url if target else None),
        check_name=check_name,
        raw_data=raw_data,
        references=references or [],
    )


# ── Observation type conversion ───────────────────────────────────
#
# Two Observation types exist:
#   - app.checks.base.Observation (dataclass) — produced by checks
#   - app.models.Observation (Pydantic)        — used by agents/engine
#
# These functions convert between them.


def check_to_model_observation(obs: CheckObservation) -> ModelObservation:
    """Convert a check-layer Observation (dataclass) to a model-layer Observation (Pydantic)."""
    return ModelObservation(
        id=obs.id,
        observation_type=obs.check_name or "unknown",
        title=obs.title,
        description=obs.description,
        severity=ObservationSeverity(obs.severity),
        status=ObservationStatus.PENDING,
        check_name=obs.check_name,
        discovered_at=now_utc(),
        target_url=obs.target_url,
        target_host=obs.target_host,
        target_service=obs.target.url if obs.target else None,
        evidence_summary=obs.evidence,
        references=obs.references or [],
        # Grading travels with the observation across the layer boundary.
        # Without it an agent reading a model-layer observation
        # cannot tell a graded verdict from a probe's provisional guess.
        confidence=obs.confidence if obs.confidence is not None else 0.5,
        provisional_severity=(
            ObservationSeverity(obs.provisional_severity) if obs.provisional_severity else None
        ),
        grading_state=obs.grading_state,
        grading_tier=obs.grading_tier,
        grading_reasoning=obs.grading_reasoning,
        evidence_ids=list(obs.evidence_ids or []),
        evidence_source=obs.evidence_source,
        signals=dict(obs.signals or {}),
    )


def model_to_check_observation(obs: ModelObservation) -> CheckObservation:
    """Convert a model-layer Observation (Pydantic) to a check-layer Observation (dataclass)."""
    return CheckObservation(
        id=obs.id,
        title=obs.title,
        description=obs.description,
        severity=str(obs.severity),
        evidence=obs.evidence_summary or "",
        target_url=obs.target_url,
        target_host=obs.target_host,
        check_name=obs.check_name,
        references=obs.references or [],
        provisional_severity=(str(obs.provisional_severity) if obs.provisional_severity else None),
        confidence=obs.confidence,
        grading_state=obs.grading_state,
        grading_tier=obs.grading_tier,
        grading_reasoning=obs.grading_reasoning,
        evidence_ids=list(obs.evidence_ids or []),
        evidence_source=obs.evidence_source,
        signals=dict(obs.signals) if obs.signals else None,
    )


# ── Severity helpers ──────────────────────────────────────────────

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def validate_severity(severity: str) -> str:
    """
    Normalize and validate a severity string.
    Raises ValueError for unrecognized values.
    """
    normalized = severity.lower().strip()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}"
        )
    return normalized


# ── Suppression, not subtraction ──────────
#
# "AI never subtracts." A verifier's rejection is a verdict *attached to* an
# observation, never a reason to remove it from the record. Every consumer that
# narrows to verified observations does so through here, so the narrowing is
# counted and can be reported instead of happening silently.

#: Verdicts that keep an observation out of a default report view. It is still
#: stored, still returned by the API, and still listed when the operator asks.
SUPPRESSED_STATUSES = frozenset({"rejected", "hallucination"})


def _status_of(observation) -> str:
    """Read a verdict off either observation shape, dict or object."""
    if isinstance(observation, dict):
        raw = observation.get("verification_status") or observation.get("status") or "pending"
    else:
        raw = getattr(observation, "verification_status", None) or getattr(
            observation, "status", "pending"
        )
    return str(raw).lower()


def partition_by_verdict(observations: list) -> tuple[list, list]:
    """
    Split observations into (carried, suppressed) by verification verdict.

    Nothing is dropped here — the caller gets both halves and is expected to
    account for the second one. A report says "3 observations suppressed by
    Verifier"; an agent stage logs how many it is not being shown.
    """
    carried, suppressed = [], []
    for observation in observations:
        (suppressed if _status_of(observation) in SUPPRESSED_STATUSES else carried).append(
            observation
        )
    return carried, suppressed


def suppression_note(suppressed: list) -> str:
    """The operator-facing sentence for a suppressed set, or "" if none."""
    if not suppressed:
        return ""
    count = len(suppressed)
    return f"{count} observation{'s' if count != 1 else ''} suppressed by Verifier"


# ── Supersession, not double counting ───────
#
# `regrade --apply` marks a placeholder `superseded` when its candidate now
# grades under different ids. Borrow suppression's *stated, not silent* half and
# not its counting half: a suppressed row is the only copy of its finding, but a
# superseded row always has a successor (or a re-grade that produced no verdict),
# so counting it counts one subject twice. It is excluded from counts and
# default views, and a report says how many it set aside.


def _grading_state_of(observation) -> str:
    """Read a grading state off either observation shape. A missing state (rows
    from before 57.3) reads as `ungraded`, as the repository serialises it."""
    if isinstance(observation, dict):
        raw = observation.get("grading_state")
    else:
        raw = getattr(observation, "grading_state", None)
    return str(raw or "ungraded").lower()


def is_superseded(observation) -> bool:
    from app.grading.models import GradingState

    return _grading_state_of(observation) == GradingState.SUPERSEDED


def is_placeholder(observation) -> bool:
    """Does this row stand in for a candidate, at its provisional severity?"""
    from app.grading.models import PLACEHOLDER_STATES

    return _grading_state_of(observation) in PLACEHOLDER_STATES


def partition_by_grading(observations: list) -> tuple[list, list]:
    """
    Split observations into (current, superseded).

    Counts and listings read the first half. The second is stated — a note, and
    in the technical report an appendix — never folded into a total: each row in
    it already has its successor in the first half.
    """
    current, superseded = [], []
    for observation in observations:
        (superseded if is_superseded(observation) else current).append(observation)
    return current, superseded


def supersession_note(superseded: list) -> str:
    """The operator-facing sentence for a superseded set, or "" if none."""
    if not superseded:
        return ""
    count = len(superseded)
    return f"{count} observation{'s' if count != 1 else ''} superseded by re-grade"


def superseded_by(observation) -> list[str]:
    """The stored ids that replaced a superseded row — empty when the re-grade
    produced no verdict for its candidate. `regrade --apply` records them in
    `raw_data["superseded_by"]`."""
    if isinstance(observation, dict):
        raw = observation.get("raw_data")
    else:
        raw = getattr(observation, "raw_data", None)
    return list((raw or {}).get("superseded_by") or [])


def resolve_superseded_ids(observation_ids: list, superseded: list[dict]) -> list:
    """
    A chain's observation ids, each superseded id replaced by its successors.

    Chain rows are never rewritten; this is for rendering one. An id superseded
    into no verdict is kept, so the chain still names what it was built on.
    Order is preserved and a successor named twice appears once.
    """
    successors = {row.get("id"): superseded_by(row) for row in superseded}
    resolved: list = []
    for observation_id in observation_ids or []:
        for replacement in successors.get(observation_id) or [observation_id]:
            if replacement not in resolved:
                resolved.append(replacement)
    return resolved
