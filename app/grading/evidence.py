"""
app/grading/evidence.py - Getting bytes to a grader.

A grader reads exchanges and nothing else (D-11). There are two places those
exchanges can come from, and which one was used is recorded on the `Evidence`:

  **corpus** — the scan ran with `--capture`, the exchange is on disk, and the
  verdict is reproducible from the stored bytes six months later.

  **memory** — capture is off, which is the default posture (§0.4). The probe
  still hands the grader the exchange it made; it simply was not written down.
  The seam is identical, the reproducibility is not, and `Evidence.source` says
  so rather than letting a reader assume.

That second path is what lets 57.4 migrate ~120 checks without forcing capture
on for everyone. A migrated check behaves the same either way.

The corpus copy wins when both exist, because only it carries the store's
exchange id — and the id is what the candidate binding stamps (D-22). The two
are matched by `content_hash`: same request, same response, same bytes. That is
precisely the question the hash exists to answer.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from app.capture.hashing import apply_hashes
from app.capture.models import MAX_BODY_BYTES, Exchange
from app.capture.store import EvidenceStore, apply_size_cap
from app.grading.models import Candidate, Evidence

if TYPE_CHECKING:
    from app.lib.http import HttpResponse

logger = logging.getLogger(__name__)


def load_scan_evidence(scan_id: str, check_name: str) -> list[Exchange]:
    """
    Every exchange the corpus holds for one check in one scan.

    Read from the store rather than the index: a scan whose index write failed
    still has its documents, and the phase-47 read surface already falls back
    the same way. Returns an empty list when capture was off, when the scan has
    no evidence directory, or when anything at all goes wrong — a grader missing
    its corpus grades from memory instead, and never fails for this.
    """
    if not scan_id:
        return []
    try:
        return [e for e in EvidenceStore().read_scan(scan_id) if e.check_name == check_name]
    except Exception:
        logger.debug("Could not read evidence for %s/%s", scan_id, check_name, exc_info=True)
        return []


def evidence_for(candidate: Candidate, stored: list[Exchange]) -> Evidence:
    """
    Resolve one candidate's grading input from what the probe attached and what
    the corpus holds.

    Order: the corpus copy of the probe's own exchanges, then those exchanges as
    the probe made them, then whatever the corpus holds for this candidate's
    host.
    """
    if candidate.exchanges:
        by_hash = {e.content_hash: e for e in stored if e.content_hash}
        resolved: list[Exchange] = []
        from_corpus = 0
        for exchange in candidate.exchanges:
            match = by_hash.get(exchange.content_hash)
            if match is not None:
                resolved.append(match)
                from_corpus += 1
            else:
                resolved.append(exchange)
        return Evidence(resolved, "corpus" if from_corpus == len(resolved) else "memory")

    scoped = [e for e in stored if not candidate.host or e.host == candidate.host]
    return Evidence(scoped, "corpus") if scoped else Evidence([], "empty")


def exchange_from_response(
    response: HttpResponse,
    *,
    check_name: str,
    scan_id: str = "",
    host: str = "",
    method: str = "GET",
    request_headers: dict[str, str] | None = None,
    request_body: str = "",
    request_json: Any | None = None,
    request_data: Any | None = None,
) -> Exchange:
    """
    Build an in-memory `Exchange` from an HTTP response a probe already holds.

    The same shape `app/lib/http.py`'s interceptor records — capped and hashed
    identically, so `content_hash` matches the stored copy and `evidence_for`
    can pair them. Nothing here writes to the store: when capture is on the
    interceptor has already written this exchange.

    That pairing is why `request_json` exists (57.4 wave 3). Both hashes cover
    the normalised *request* — method, url, headers and body — so a probe that
    POSTs a JSON payload and records it with an empty `request_body` builds an
    exchange the corpus copy can never match, and every verdict derived from it
    silently degrades from `corpus` to `memory`. Pass the payload object here
    and it is serialised exactly as the interceptor serialises it, rather than
    leaving each of the five LLM-facing suites to re-derive that detail and one
    of them to get it wrong. `request_headers` matters for the same reason:
    hand over what was passed to the client, not the merged set.

    `request_data` is the same idea for a `data=` body (B-8): pass exactly what
    was handed to the client, bytes included, and it is turned into text by the
    interceptor's own rule (`app.lib.http.request_body_text`).
    """
    from urllib.parse import urlparse

    from app.lib.http import request_body_text

    if request_json is not None or request_data is not None:
        request_body = request_body_text(request_json, request_data)

    url = response.url or ""
    exchange = Exchange(
        id=uuid.uuid4().hex,
        scan_id=scan_id,
        check_name=check_name,
        host=host or urlparse(url).hostname or url,
        protocol="http",
        request_method=method,
        request_url=url,
        request_headers=dict(request_headers or {}),
        request_body=request_body,
        response_status=response.status_code or None,
        response_headers=dict(response.headers or {}),
        response_body=response.body or "",
        elapsed_ms=response.elapsed_ms,
        error=response.error,
    )
    apply_size_cap(exchange, MAX_BODY_BYTES)
    return apply_hashes(exchange)


def exchange_from_payload(
    protocol: str,
    host: str,
    *,
    check_name: str,
    scan_id: str = "",
    request_body: str = "",
    response_body: str = "",
    elapsed_ms: float | None = None,
    error: str | None = None,
    **fields: Any,
) -> Exchange:
    """The non-HTTP equivalent: a resolver answer, a banner, a command's output."""
    exchange = Exchange(
        id=uuid.uuid4().hex,
        scan_id=scan_id,
        check_name=check_name,
        host=host,
        protocol=protocol,
        request_body=request_body,
        response_body=response_body,
        elapsed_ms=elapsed_ms,
        error=error,
        **fields,
    )
    apply_size_cap(exchange, MAX_BODY_BYTES)
    return apply_hashes(exchange)
