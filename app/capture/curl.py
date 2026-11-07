"""
app/capture/curl.py - Reproducing one captured exchange.

Phase 47 asked for a "copy as curl" button per request, and this is the half of
it that belongs on the server. The command is built from the **exchange the
viewer was shown**, not from the stored one, so a redacted view yields a command
carrying `<redacted>` rather than the operator's real bearer token. Building it
in the browser instead would have meant either shipping the unredacted headers
to the page or re-implementing the quoting rules in JavaScript.

Non-HTTP protocols have no curl equivalent and return None; the UI omits the
button rather than offering a command that would not run.
"""

from __future__ import annotations

from app.capture.models import Exchange


def _quote(value: str) -> str:
    """Single-quote for a POSIX shell, the way curl's own docs do it."""
    return "'" + value.replace("'", "'\\''") + "'"


def to_curl(exchange: Exchange) -> str | None:
    """
    Render one exchange as a `curl` command, or None if it is not HTTP-shaped.

    `llm` exchanges are deliberately excluded even though they travel over
    HTTP: what was captured is the prompt and the completion, not the wire
    request, so a command built from them would not reproduce the call.
    """
    if exchange.protocol != "http" or not exchange.request_url:
        return None

    parts = ["curl", "-i"]

    method = (exchange.request_method or "GET").upper()
    if method != "GET":
        parts += ["-X", method]

    for name, value in exchange.request_headers.items():
        parts += ["-H", _quote(f"{name}: {value}")]

    if exchange.request_body:
        parts += ["--data-raw", _quote(exchange.request_body)]

    parts.append(_quote(exchange.request_url))
    return " ".join(parts)
