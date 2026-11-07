"""
app/capture/hashing.py - Normalisation and the two hashes.

Two hashes, because one input cannot do both jobs:

  `probe_hash`    SHA-256 over the normalised **request alone**.
                  Answers *"is this the same question?"* — groups the sampling
                  iterations of one probe and lets two runs be
                  diffed probe-by-probe. It must exclude the response, or
                  sampling cannot group the iterations it exists to compare.

  `content_hash`  SHA-256 over the normalised **pair**.
                  Answers *"is this the same evidence?"* — integrity, dedup, and
                  the grade-cache key. It must cover the response,
                  or a cached verdict could be reused against a different answer.

Against a stochastic target `content_hash` will not repeat across live scans.
That is correct and not a cache failure: the evidence genuinely is new and
genuinely needs grading. The grade cache's real workload is re-grading a
**stored** corpus, where the bytes on disk are fixed and it hits every time.

**Normalisation** removes what varies per run without changing meaning:
timestamps, `Date` headers, session ids, and the per-run markers checks mint —
the `uuid4()` markers of `cag_cache_poisoning`, `cag_cross_user_leakage` and
`cag_cache_quota`, and the short-hex `chainsmith-canary-…` / `chainsmith-probe-…`
markers of `rag_corpus_poisoning` and `web_error_page`. Those markers are
correct behaviour and stay in the record — they are substituted with a stable
placeholder *for hashing only*. (D-21 found the short-hex ones: two scans of an
unchanged fakobanko hashed differently until they were covered.)
"""

from __future__ import annotations

import hashlib
import json
import re

from app.capture.models import Exchange
from app.capture.protocols import volatile_headers

#: Substituted for any UUID before hashing. The markers the CAG checks mint per
#: run are correct behaviour; they just must not make every run hash differently.
UUID_PLACEHOLDER = "<uuid>"

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

#: Chainsmith's own short-hex per-run markers (`chainsmith-canary-eaf024a5`,
#: `/chainsmith-probe-56a2e9ba`). The hex suffix is required, so the fixed
#: `chainsmith-probe` string MCP payloads echo is left alone.
MARKER_PLACEHOLDER = "chainsmith-<marker>"
_MARKER_RE = re.compile(r"chainsmith-(?:canary|probe)-[0-9a-fA-F]{6,}")

#: ISO-8601-ish timestamps embedded in bodies (JSON `created_at`, log lines).
_TIMESTAMP_PLACEHOLDER = "<ts>"
_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)

#: Unix epoch seconds/millis appearing as bare integers in JSON.
_EPOCH_PLACEHOLDER = "<epoch>"
_EPOCH_RE = re.compile(r"\b1[0-9]{9}(?:[0-9]{3})?\b")


def normalise_text(text: str) -> str:
    """Replace per-run values in a body with stable placeholders."""
    if not text:
        return ""
    text = _UUID_RE.sub(UUID_PLACEHOLDER, text)
    text = _MARKER_RE.sub(MARKER_PLACEHOLDER, text)
    text = _TIMESTAMP_RE.sub(_TIMESTAMP_PLACEHOLDER, text)
    text = _EPOCH_RE.sub(_EPOCH_PLACEHOLDER, text)
    return text


def normalise_headers(headers: dict[str, str], protocol: str) -> dict[str, str]:
    """
    Drop volatile headers and lowercase the names.

    Names are lowercased because HTTP header names are case-insensitive and
    servers are inconsistent about casing; two runs that differ only in `Server`
    vs `server` are the same evidence.
    """
    volatile = volatile_headers(protocol)
    return {
        name.lower(): normalise_text(value)
        for name, value in sorted(headers.items(), key=lambda kv: kv[0].lower())
        if name.lower() not in volatile
    }


def normalise_url(url: str | None) -> str:
    """Normalise a URL for hashing — currently the same placeholder substitution."""
    return normalise_text(url or "")


def _canonical(payload: dict) -> str:
    """Stable JSON encoding: sorted keys, no incidental whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_fingerprint(exchange: Exchange) -> dict:
    """The normalised request, as the structure both hashes are built from."""
    return {
        "protocol": exchange.protocol,
        "method": exchange.request_method,
        "url": normalise_url(exchange.request_url),
        "headers": normalise_headers(exchange.request_headers, exchange.protocol),
        "body": normalise_text(exchange.request_body),
    }


def response_fingerprint(exchange: Exchange) -> dict:
    """
    The normalised response.

    `elapsed_ms` is deliberately absent: timing varies every run and is recorded
    on the row for the operator, not for identity.
    """
    return {
        "status": exchange.response_status,
        "headers": normalise_headers(exchange.response_headers, exchange.protocol),
        "body": normalise_text(exchange.response_body),
        # A probe that failed is different evidence from one that returned an
        # empty response — the distinction the `error` column exists to keep.
        "error": normalise_text(exchange.error) if exchange.error else None,
    }


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def probe_hash(exchange: Exchange) -> str:
    """Hash the normalised request alone. Same question -> same hash."""
    return _sha256(_canonical(request_fingerprint(exchange)))


def content_hash(exchange: Exchange) -> str:
    """Hash the normalised pair. Same evidence -> same hash."""
    return _sha256(
        _canonical(
            {
                "request": request_fingerprint(exchange),
                "response": response_fingerprint(exchange),
            }
        )
    )


def apply_hashes(exchange: Exchange) -> Exchange:
    """Stamp both hashes onto the exchange, in place, and return it."""
    exchange.probe_hash = probe_hash(exchange)
    exchange.content_hash = content_hash(exchange)
    return exchange
