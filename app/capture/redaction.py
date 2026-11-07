"""
app/capture/redaction.py - Redact on read, never on write.

Captured evidence contains extracted system prompts, whatever a RAG returns
(potentially customer PII), and credentials in headers. Redact-on-write destroys
evidence you may later need; redact-on-read leaves client secrets in the
database. The posture takes both halves:

  1. Full fidelity at rest. Nothing is destroyed at capture time. (Encrypted
     once 57.5 lands; until then the workspace directory is the boundary.)
  2. **Redacted by default on read** — this module. Every default view: UI,
     reports, exports, and whatever a future grader is shown.
  3. Unredacted access is an explicit privileged action, and is itself logged.

`llm` rows are the sharpest case: an agent exchange carries Chainsmith's own
system prompts, the target's extracted prompts, and whatever the target
returned — the highest-value content in the store, in the rows most likely to be
pasted into a chat while debugging a bad verdict. They are covered from the day
they are captured, not as a follow-up.
"""

from __future__ import annotations

import re
from dataclasses import replace

from app.capture.models import Exchange

MASK = "<redacted>"

#: Header names (lowercased) whose values never appear in a default view.
SECRET_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-session-token",
        "x-csrf-token",
        "openai-api-key",
        "anthropic-api-key",
        "x-goog-api-key",
    }
)

# ── Token shapes ─────────────────────────────────────────────────
#
# Deliberately shape-based rather than exhaustive. A missed secret is the
# expensive error, so these err toward over-masking; the unredacted view exists
# for when that gets in the way.

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Bearer / token / key preceded by its keyword, in a header or a body.
    (re.compile(r"(?i)\b(bearer|token|apikey|api_key)\b[\s:=\"']+([^\s\"',}]{8,})"), r"\1 " + MASK),
    # Provider key prefixes.
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), MASK),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}"), MASK),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), MASK),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), MASK),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), MASK),
    # JWTs.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),
    # JSON fields named like a secret.
    (
        re.compile(
            r"(?i)(\"(?:password|passwd|secret|client_secret|access_token|refresh_token"
            r"|private_key|api_key)\"\s*:\s*)\"[^\"]*\""
        ),
        r"\1\"" + MASK + '"',
    ),
)


def redact_text(text: str) -> str:
    """Mask known secret shapes in a body or header value."""
    if not text:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Mask secret headers entirely; scrub token shapes from the rest."""
    return {
        name: MASK if name.lower() in SECRET_HEADERS else redact_text(value)
        for name, value in headers.items()
    }


def redact(exchange: Exchange) -> Exchange:
    """
    Return a redacted copy of an exchange, for any default view.

    A copy, not a mutation: the stored row keeps full fidelity, and the caller
    that legitimately needs the original still has it. The hashes are those of
    the *unredacted* evidence and are carried through unchanged — they identify
    what was captured, and recomputing them here would silently fork identity
    between what a viewer sees and what a grader graded.
    """
    return replace(
        exchange,
        request_headers=redact_headers(exchange.request_headers),
        request_body=redact_text(exchange.request_body),
        response_headers=redact_headers(exchange.response_headers),
        response_body=redact_text(exchange.response_body),
        error=redact_text(exchange.error) if exchange.error else None,
    )
