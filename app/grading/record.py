"""
app/grading/record.py - What a re-grade needs besides the bytes.

The corpus holds exchanges, and a grader reads exchanges (D-11). But a grading
*call* has two more inputs the corpus does not hold:

  **the candidates** — identity, provisional severity, `raw_data`, and which
  exchanges the probe handed each one. They are consumed into observations,
  and one candidate may become several (D-24), so they cannot be rebuilt from
  the observations afterwards.

  **the scan context** — 24 of the 133 built-in graders read an upstream
  check's output from `ctx.context`. It lives in memory and is gone when the
  scan ends.

So when capture is on, the grading stage writes both beside the evidence:

    <workspace>/evidence/<scan_id>/grading/<check_name>.json
    <workspace>/evidence/<scan_id>/grading/context/<sha256>.json

**Each context value is stored once per scan** (version 2). A record holds
`context_refs`, key -> SHA-256 of the value's canonical JSON, and the value lives
in `context/`. The context a check sees is everything upstream checks have
produced so far, so version 1 — the whole context inline in every record — wrote
the same upstream results over and over: D-21 measured 56% of 4.7 MB of records
per fakobanko scan as repeated context. Values are written before the record
that references them. Version 1 records are still read.

**Exchanges are referenced, not copied.** A candidate records the
`content_hash` of each exchange it was handed. Copying the bytes would store
evidence the check's capture policy (D-20) chose not to keep; a reference means
a re-grade can reproduce only what the corpus actually holds, and says so when
it cannot. That is the same line `Evidence.source` already draws between
`corpus` and `memory`.

**The context is serialised the way the swarm already serialises it**
(`SwarmCoordinator._snapshot_context`): anything with `to_dict()` becomes a
dict, and `services` come back as `Service` objects. A grader therefore sees on
re-grade exactly the shape a check running on a swarm agent grades against. A
value that cannot be made JSON is dropped and *named* in the record — never
guessed at.

Writing never breaks a scan, and is skipped entirely when capture is off: with
no corpus there is nothing a record could be replayed against.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from app.grading.models import Candidate

if TYPE_CHECKING:
    from pathlib import Path

    from app.capture.models import Exchange
    from app.capture.store import EvidenceStore

logger = logging.getLogger(__name__)

#: Bumped when the document shape changes, so a reader can refuse what it
#: does not understand instead of misreading it.
RECORD_VERSION = 2

#: Versions `context_from_record` reads. Version 1 held the context inline.
READABLE_VERSIONS = frozenset({1, 2})

#: Context keys that are scan machinery rather than grading input. Left out
#: silently, so `dropped_context_keys` names only what a grader might miss.
_NOT_GRADING_INPUT = frozenset({"capture_settings"})


# ─── serialisation ──────────────────────────────────────────────


def _jsonable(value: Any) -> Any:
    """A JSON-safe copy of `value`, or `TypeError` if there is none."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, set | frozenset):
        return [_jsonable(v) for v in sorted(value, key=repr)]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _jsonable(to_dict())
    raise TypeError(f"not JSON-serialisable: {type(value).__name__}")


def snapshot_context(context: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The scan context as JSON, plus the keys that could not be kept."""
    snapshot: dict[str, Any] = {}
    dropped: list[str] = []
    for key, value in context.items():
        if key in _NOT_GRADING_INPUT:
            continue
        try:
            snapshot[key] = _jsonable(value)
        except (TypeError, ValueError, RecursionError):
            dropped.append(key)
    return snapshot, sorted(dropped)


def restore_context(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The inverse of `snapshot_context`, as far as the swarm agent goes."""
    from app.checks.base import Service

    context = dict(snapshot)
    services = context.get("services")
    if isinstance(services, list):
        context["services"] = [Service.from_dict(s) if isinstance(s, dict) else s for s in services]
    return context


def candidate_to_dict(candidate: Candidate) -> dict[str, Any]:
    try:
        raw_data = _jsonable(candidate.raw_data)
        raw_dropped = False
    except (TypeError, ValueError, RecursionError):
        raw_data, raw_dropped = None, True
    return {
        "check_name": candidate.check_name,
        "host": candidate.host,
        "provisional_severity": candidate.provisional_severity,
        "discriminator": candidate.discriminator,
        "target": candidate.target.to_dict() if candidate.target is not None else None,
        "target_url": candidate.target_url,
        "raw_data": raw_data,
        "raw_data_dropped": raw_dropped,
        # References into the corpus, in the order the probe attached them.
        "exchanges": [exchange.content_hash for exchange in candidate.exchanges],
    }


def candidate_from_dict(doc: dict[str, Any], by_hash: dict[str, Exchange]) -> tuple[Candidate, int]:
    """
    Rebuild one candidate against a corpus. Returns `(candidate, missing)`.

    `missing` counts referenced exchanges the corpus does not hold. A caller
    grading a candidate with `missing > 0` would grade different evidence than
    the scan did, so the re-grade skips it rather than silently degrading.
    """
    from app.checks.base import Service

    exchanges = [by_hash.get(content_hash) for content_hash in doc.get("exchanges") or []]
    target = doc.get("target")
    candidate = Candidate(
        check_name=doc.get("check_name") or "",
        host=doc.get("host") or "",
        provisional_severity=doc.get("provisional_severity") or "info",
        discriminator=doc.get("discriminator"),
        target=Service.from_dict(target) if isinstance(target, dict) else None,
        target_url=doc.get("target_url"),
        raw_data=doc.get("raw_data"),
        exchanges=[exchange for exchange in exchanges if exchange is not None],
    )
    return candidate, sum(1 for exchange in exchanges if exchange is None)


def encode_value(value: Any) -> tuple[str, str]:
    """`(sha256, canonical JSON)` for one JSON-safe context value."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest(), encoded


def build_record(
    scan_id: str,
    check_name: str,
    candidates: list[Candidate],
    context: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """The record document, and the context values it references (sha256 -> JSON)."""
    from app.lib.timeutils import now_utc

    snapshot, dropped = snapshot_context(context)
    refs: dict[str, str] = {}
    values: dict[str, str] = {}
    for key, value in snapshot.items():
        digest, encoded = encode_value(value)
        refs[key] = digest
        values[digest] = encoded
    record = {
        "version": RECORD_VERSION,
        "scan_id": scan_id,
        "check_name": check_name,
        "recorded_at": now_utc().isoformat(),
        "context_refs": refs,
        "dropped_context_keys": dropped,
        "candidates": [candidate_to_dict(candidate) for candidate in candidates],
    }
    return record, values


def context_from_record(
    record: dict[str, Any], store: EvidenceStore, scan_id: str
) -> tuple[dict[str, Any], list[str]]:
    """
    The context snapshot a record was graded against, and the keys whose stored
    value could not be found. A caller grading with missing keys would grade
    against a different context than the scan did.
    """
    if record.get("version") == 1:
        return dict(record.get("context") or {}), []
    snapshot: dict[str, Any] = {}
    missing: list[str] = []
    for key, digest in (record.get("context_refs") or {}).items():
        found, value = store.read_context_value(scan_id, digest)
        if found:
            snapshot[key] = value
        else:
            missing.append(key)
    return snapshot, sorted(missing)


# ─── the scan-time write ────────────────────────────────────────


def capture_enabled(context: dict[str, Any]) -> bool:
    """Is this scan capturing? The scan's own posture wins over the process
    default, exactly as it does for the writer."""
    from app.capture.settings import CaptureSettings, get_settings

    settings = context.get("capture_settings")
    if not isinstance(settings, CaptureSettings):
        settings = get_settings()
    return settings.enabled


def record_grading(
    scan_id: str,
    check_name: str,
    candidates: list[Candidate],
    context: dict[str, Any],
    store: EvidenceStore | None = None,
) -> Path | None:
    """Write one check's grading record, if this scan has a corpus to pair it
    with. Returns the path written, or None. Never raises."""
    if not scan_id or not candidates or not capture_enabled(context):
        return None
    try:
        from app.capture.store import EvidenceStore

        store = store or EvidenceStore()
        record, values = build_record(scan_id, check_name, candidates, context)
        # Values first: a record must never reference something not yet written.
        for digest, encoded in values.items():
            store.write_context_value(scan_id, digest, encoded)
        return store.write_grading_record(scan_id, check_name, record)
    except Exception:
        logger.warning("Grading record failed for %s/%s", scan_id, check_name, exc_info=True)
        return None
