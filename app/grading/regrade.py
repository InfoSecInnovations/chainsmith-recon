"""
app/grading/regrade.py - The offline re-grade pass.

§10 criterion 4 ends "a later re-grade pass fills them in without re-scanning",
and criterion 2 asks that re-grading a stored corpus produce "an inspectable
diff against the original". This is that pass.

    report = await regrade_scan(scan_id, stored_rows)   # read-only
    print(render_report(report))                         # the diff
    await apply_regrade(report)                          # only on --apply

It replays `grade_result()` — the same function a scan calls (D-23) — against
three things and nothing else: the corpus, the grading record the scan left
beside it (`record.py`), and the check's *current* `grade()`. No probe runs and
no target is contacted. What can differ from the scan is therefore the grader,
the contract's declared severity, or the operator's pre-run overrides — never
the bytes.

**Only corpus evidence is replayed.** A candidate whose exchanges are not all in
the corpus was graded from memory at scan time; grading it now would grade
different evidence. It is skipped and named, not approximated.

**Nothing subtracts** (§2). `--apply` rewrites what the re-grade reproduced,
inserts verdicts it newly produced, and marks a *placeholder* it superseded — an
`ungraded` or `grading_failed` row whose candidate now grades under different
ids, or into no verdict at all — as `superseded`. A graded row the re-grade did
not reproduce is reported and left alone. No row is ever deleted: chains store
observation ids, and a report should read a superseded row, not a missing one.
Reports and default reads exclude superseded rows from counts and state them.

**Status history follows.** A write changes which fingerprints the scan holds,
so `--apply` rebuilds `ObservationStatusHistory` for the scan and every later
scan of its target (`ComparisonRepository.recompute_statuses_from`).

**Known limit:** a check's tunable config is not recorded, so a grader that
reads a knob grades against today's value rather than the scan's.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from app.grading.models import PLACEHOLDER_STATES, GradingState
from app.grading.record import (
    READABLE_VERSIONS,
    candidate_from_dict,
    context_from_record,
    restore_context,
)
from app.grading.stage import grade_result

if TYPE_CHECKING:
    from app.capture.store import EvidenceStore
    from app.checks.base import Observation
    from app.db.repositories import ComparisonRepository, ObservationRepository

logger = logging.getLogger(__name__)

#: What a grader owns on an observation, and so what a re-grade compares.
#: `raw_data` is deliberately absent: the launcher annotates it after grading
#: (critical-host cross-suite notes, pre-run override audit), so it would
#: differ for reasons that have nothing to do with the verdict.
GRADED_FIELDS: tuple[str, ...] = (
    "severity",
    "confidence",
    "grading_state",
    "grading_tier",
    "title",
    "description",
    "evidence",
    "grading_reasoning",
    "evidence_ids",
    "evidence_source",
    "signals",
)


class ChangeKind(StrEnum):
    UNCHANGED = "unchanged"
    CHANGED = "changed"
    ADDED = "added"
    SUPERSEDED = "superseded"
    NOT_REPRODUCED = "not_reproduced"


@dataclass
class ObservationChange:
    """One stored or re-graded observation, and what happened to it."""

    kind: str
    check_name: str
    #: The stored (scan-scoped) id.
    observation_id: str
    before: dict | None = None
    after: dict | None = None
    #: field -> (stored value, re-graded value), for `changed` only.
    fields: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    #: Stored ids of the verdicts that replaced a `superseded` placeholder.
    superseded_by: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class SkippedCandidate:
    check_name: str
    #: None when the whole check was skipped.
    candidate_id: str | None
    reason: str


@dataclass
class RegradeReport:
    scan_id: str
    #: Checks at least one candidate of which was re-graded.
    checks: list[str] = field(default_factory=list)
    changes: list[ObservationChange] = field(default_factory=list)
    skipped: list[SkippedCandidate] = field(default_factory=list)
    records_found: int = 0

    def of_kind(self, kind: str) -> list[ObservationChange]:
        return [change for change in self.changes if change.kind == kind]

    @property
    def has_changes(self) -> bool:
        """Is there anything `--apply` would write?"""
        return any(
            change.kind in (ChangeKind.CHANGED, ChangeKind.ADDED, ChangeKind.SUPERSEDED)
            for change in self.changes
        )

    def counts(self) -> dict[str, int]:
        counts = {str(kind): 0 for kind in ChangeKind}
        for change in self.changes:
            counts[str(change.kind)] += 1
        counts["skipped"] = len(self.skipped)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "records_found": self.records_found,
            "checks": list(self.checks),
            "counts": self.counts(),
            "changes": [
                {
                    "kind": str(change.kind),
                    "check_name": change.check_name,
                    "observation_id": change.observation_id,
                    "fields": {name: list(pair) for name, pair in change.fields.items()},
                    "superseded_by": list(change.superseded_by),
                    "note": change.note,
                    "before": change.before,
                    "after": change.after,
                }
                for change in self.changes
            ],
            "skipped": [
                {
                    "check_name": skip.check_name,
                    "candidate_id": skip.candidate_id,
                    "reason": skip.reason,
                }
                for skip in self.skipped
            ],
        }


# ─── the pass ───────────────────────────────────────────────────


def _default_resolver() -> Callable[[str], Any]:
    """Check instances by name, discovered once for the whole pass."""
    from app.check_resolver import get_real_checks

    return {check.name: check for check in get_real_checks()}.get


async def regrade_scan(
    scan_id: str,
    stored_rows: list[dict],
    *,
    store: EvidenceStore | None = None,
    resolve_check: Callable[[str], Any] | None = None,
    only: Iterable[str] | None = None,
) -> RegradeReport:
    """
    Re-grade one stored scan and diff it against `stored_rows`.

    `stored_rows` are the scan's observations as persisted
    (`ObservationRepository.get_records`). Reads only; writes nothing.
    """
    from app.capture.store import EvidenceStore
    from app.checks.base import CheckResult
    from app.db.repositories import scoped_observation_id

    store = store or EvidenceStore()
    wanted = set(only) if only else None
    report = RegradeReport(scan_id=scan_id)

    records = [
        record
        for record in store.read_grading_records(scan_id)
        if wanted is None or record.get("check_name") in wanted
    ]
    report.records_found = len(records)
    if not records:
        return report

    resolve_check = resolve_check or _default_resolver()
    corpus = store.read_scan(scan_id)

    produced: dict[str, dict] = {}
    #: stored id of a candidate (= its placeholder's id) -> stored ids it graded into
    graded_into: dict[str, list[str]] = {}
    skipped_per_check: dict[str, int] = {}

    for record in records:
        name = record.get("check_name") or ""
        if record.get("version") not in READABLE_VERSIONS:
            report.skipped.append(
                SkippedCandidate(
                    name,
                    None,
                    f"grading record version {record.get('version')!r} is not one of "
                    f"{sorted(READABLE_VERSIONS)}",
                )
            )
            continue
        check = resolve_check(name)
        if check is None:
            report.skipped.append(
                SkippedCandidate(
                    name, None, "check is not in this tree (removed, renamed or disabled)"
                )
            )
            continue

        stored = [exchange for exchange in corpus if exchange.check_name == name]
        by_hash = {exchange.content_hash: exchange for exchange in stored if exchange.content_hash}
        snapshot, missing_keys = context_from_record(record, store, scan_id)
        if missing_keys:
            report.skipped.append(
                SkippedCandidate(
                    name,
                    None,
                    "stored context value(s) missing for "
                    f"{', '.join(missing_keys)}; the check would grade against a different "
                    "context than the scan did",
                )
            )
            continue
        context = restore_context(snapshot)
        context["scan_id"] = scan_id
        graded_any = False
        # One set per check across its candidates, so the D-2 id-collision guard
        # renames the same observations it renamed at scan time.
        seen_ids: set[str] = set()

        for doc in record.get("candidates") or []:
            candidate, missing = candidate_from_dict(doc, by_hash)
            if missing:
                skipped_per_check[name] = skipped_per_check.get(name, 0) + 1
                report.skipped.append(
                    SkippedCandidate(
                        name,
                        candidate.id,
                        f"{missing} of {missing + len(candidate.exchanges)} exchange(s) not in "
                        "the corpus; graded from memory at scan time, so not reproducible",
                    )
                )
                continue

            # One candidate per call, so each verdict is attributable to the
            # candidate it came from — which is what decides "superseded".
            result = CheckResult(success=True, check_name=name, candidates=[candidate])
            await grade_result(
                check,
                result,
                context,
                stored=stored,
                bind=False,
                persist=False,
                seen_ids=seen_ids,
            )
            graded_any = True

            ids = []
            for observation in result.observations:
                stored_id = scoped_observation_id(scan_id, observation.id)
                produced[stored_id] = _as_record(observation)
                ids.append(stored_id)
            graded_into[scoped_observation_id(scan_id, candidate.id)] = ids

        if graded_any:
            report.checks.append(name)

    _diff(report, stored_rows, produced, graded_into, skipped_per_check)
    return report


def _as_record(observation: Observation) -> dict:
    """A re-graded observation in the shape the launcher persists — including
    the operator's pre-run severity override, so the diff is like for like."""
    from app.customizations import apply_pre_run_override

    record = observation.to_dict()
    record["raw_data"] = dict(observation.raw_data or {})
    return apply_pre_run_override(record)


def _diff(
    report: RegradeReport,
    stored_rows: list[dict],
    produced: dict[str, dict],
    graded_into: dict[str, list[str]],
    skipped_per_check: dict[str, int],
) -> None:
    regraded = set(report.checks)
    before_by_id = {row["id"]: row for row in stored_rows if row.get("check_name") in regraded}

    for stored_id, after in produced.items():
        before = before_by_id.get(stored_id)
        check_name = after.get("check_name") or ""
        if before is None:
            report.changes.append(
                ObservationChange(ChangeKind.ADDED, check_name, stored_id, after=after)
            )
            continue
        fields = diff_fields(before, after)
        report.changes.append(
            ObservationChange(
                ChangeKind.CHANGED if fields else ChangeKind.UNCHANGED,
                check_name,
                stored_id,
                before=before,
                after=after,
                fields=fields,
            )
        )

    for stored_id, before in before_by_id.items():
        if stored_id in produced:
            continue
        state = before.get("grading_state")
        # Settled by an earlier --apply; re-reporting it would make every
        # later re-grade of this scan look like it still had work to do.
        if state == GradingState.SUPERSEDED:
            continue
        check_name = before.get("check_name") or ""
        successors = graded_into.get(stored_id)
        if successors is not None and state in PLACEHOLDER_STATES:
            report.changes.append(
                ObservationChange(
                    ChangeKind.SUPERSEDED,
                    check_name,
                    stored_id,
                    before=before,
                    superseded_by=list(successors),
                )
            )
            continue
        note = ""
        if skipped_per_check.get(check_name):
            note = (
                f"{skipped_per_check[check_name]} candidate(s) of this check could not be "
                "re-graded; this row may belong to one"
            )
        report.changes.append(
            ObservationChange(
                ChangeKind.NOT_REPRODUCED, check_name, stored_id, before=before, note=note
            )
        )


def diff_fields(before: dict, after: dict) -> dict[str, tuple[Any, Any]]:
    """The graded fields that differ, as (stored, re-graded)."""
    return {
        name: (before.get(name), after.get(name))
        for name in GRADED_FIELDS
        if _normalise(name, before.get(name)) != _normalise(name, after.get(name))
    }


def _normalise(name: str, value: Any) -> Any:
    """Absorb the storage round trip: the table hands back `[]` for no evidence
    ids and `None` for no signals, a float column may wobble, and an empty
    string and a null say the same thing."""
    if name == "evidence_ids":
        return list(value or [])
    if name == "signals":
        return dict(value or {})
    if name == "confidence":
        return None if value is None else round(float(value), 6)
    if value == "":
        return None
    return value


# ─── --apply ────────────────────────────────────────────────────


async def apply_regrade(
    report: RegradeReport,
    repo: ObservationRepository | None = None,
    *,
    store: EvidenceStore | None = None,
    comparisons: ComparisonRepository | None = None,
) -> dict[str, int]:
    """Write a re-grade back. Returns counts: updated, inserted, superseded,
    bound, and statuses_recomputed (scans whose status history was rebuilt)."""
    from app.db.repositories import ComparisonRepository, ObservationRepository
    from app.lib.timeutils import now_utc

    repo = repo or ObservationRepository()
    stamp = now_utc().isoformat(timespec="seconds")
    superseded = report.of_kind(ChangeKind.SUPERSEDED)

    counts = await repo.apply_regrade(
        report.scan_id,
        changed=[change.after for change in report.of_kind(ChangeKind.CHANGED) if change.after],
        added=[change.after for change in report.of_kind(ChangeKind.ADDED) if change.after],
        superseded={
            change.observation_id: _superseded_reasoning(change, stamp) for change in superseded
        },
        successors={change.observation_id: list(change.superseded_by) for change in superseded},
    )
    counts["bound"] = await _bind(report, store)

    recomputed: list[str] = []
    if counts["updated"] or counts["inserted"] or counts["superseded"]:
        comparisons = comparisons or ComparisonRepository()
        recomputed = await comparisons.recompute_statuses_from(report.scan_id)
    counts["statuses_recomputed"] = len(recomputed)
    return counts


def _superseded_reasoning(change: ObservationChange, stamp: str) -> str:
    successors = ", ".join(change.superseded_by)
    return f"Superseded by offline re-grade ({stamp}): " + (
        successors or "the re-grade produced no verdict for this candidate"
    )


async def _bind(report: RegradeReport, store: EvidenceStore | None) -> int:
    """Stamp re-graded verdicts onto the exchanges they read (D-22), exactly as
    the scan-time stage does. Best-effort, like every binding."""
    from app.capture.store import EvidenceStore
    from app.db.repositories import EvidenceRepository

    store = store or EvidenceStore()
    bound = 0
    for change in report.of_kind(ChangeKind.CHANGED) + report.of_kind(ChangeKind.ADDED):
        after = change.after or {}
        exchange_ids = list(after.get("evidence_ids") or [])
        observation_id = after.get("id") or ""
        if not exchange_ids or not observation_id:
            continue
        for exchange_id in exchange_ids:
            with suppress(Exception):
                if store.bind_candidate(report.scan_id, exchange_id, observation_id):
                    bound += 1
        try:
            await EvidenceRepository().bind_candidate(report.scan_id, exchange_ids, observation_id)
        except Exception:
            logger.debug("Re-grade binding index update failed", exc_info=True)
    return bound


# ─── presentation ───────────────────────────────────────────────

_ORDER = (
    ChangeKind.CHANGED,
    ChangeKind.ADDED,
    ChangeKind.SUPERSEDED,
    ChangeKind.NOT_REPRODUCED,
    ChangeKind.UNCHANGED,
)
_TAGS = {
    ChangeKind.CHANGED: "CHANGED",
    ChangeKind.ADDED: "ADDED",
    ChangeKind.SUPERSEDED: "SUPERSEDED",
    ChangeKind.NOT_REPRODUCED: "NOT REPRODUCED",
    ChangeKind.UNCHANGED: "UNCHANGED",
}


def _short(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_report(report: RegradeReport, *, show_unchanged: bool = False) -> str:
    """The diff, for a terminal."""
    counts = report.counts()
    lines = [
        f"Re-grade of scan {report.scan_id}: {len(report.checks)} check(s) re-graded "
        f"from {report.records_found} grading record(s)",
        "  "
        + ", ".join(f"{_TAGS[kind].lower()} {counts[str(kind)]}" for kind in _ORDER)
        + f", skipped {counts['skipped']}",
    ]

    for kind in _ORDER:
        if kind == ChangeKind.UNCHANGED and not show_unchanged:
            continue
        for change in sorted(report.of_kind(kind), key=lambda c: (c.check_name, c.observation_id)):
            lines.append(f"{_TAGS[kind]:<16}{change.check_name}  {change.observation_id}")
            if kind == ChangeKind.CHANGED:
                for name, (old, new) in change.fields.items():
                    lines.append(f"    {name}: {_short(old)} -> {_short(new)}")
            elif kind == ChangeKind.ADDED and change.after:
                after = change.after
                lines.append(
                    f"    {after.get('severity')} ({after.get('grading_state')}, "
                    f"{after.get('grading_tier')}, confidence {after.get('confidence')}): "
                    f"{after.get('title')}"
                )
            elif kind == ChangeKind.SUPERSEDED:
                lines.append("    by " + (", ".join(change.superseded_by) or "no verdict"))
            elif change.note:
                lines.append(f"    {change.note}")

    for skip in report.skipped:
        lines.append(f"{'SKIPPED':<16}{skip.check_name}  {skip.candidate_id or '(whole check)'}")
        lines.append(f"    {skip.reason}")

    return "\n".join(lines)
