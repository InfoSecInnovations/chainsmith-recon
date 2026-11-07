"""
app/capture - Evidence capture.

Everything below the capture line: what was sent, what came back, recorded
verbatim, with no model involved and no judgment attached. What a grader later
makes of it is the grader's business (`app/grading`).

    from app import capture

    capture.record("dns", host, request_body=query, response_body=answer)

The pieces:

    protocols.py   the `protocol` discriminator and its volatile fields
    models.py      `Exchange` — one request/response pair
    context.py     which check an exchange belongs to (set in BaseCheck.execute)
    hashing.py     normalisation, `probe_hash`, `content_hash`
    redaction.py   redact on read, never on write
    store.py       the on-disk corpus under the workspace's `evidence/`
    probes.py      `probe()` — the chokepoint for socket and resolver checks
    settings.py    what gets captured; off by default while this is scaffolding
    writer.py      the shared writer every producer calls

Capture never breaks a scan: failures here are logged and swallowed.
"""

from app.capture.context import CaptureContext, candidate, capture_context, iteration
from app.capture.models import Exchange
from app.capture.probes import Probe, probe, record_exchange
from app.capture.protocols import PROTOCOLS, Protocol
from app.capture.redaction import redact
from app.capture.settings import CaptureSettings, get_settings, set_settings
from app.capture.store import EvidenceStore
from app.capture.writer import (
    EvidenceWriter,
    bind_candidate,
    commit_check,
    flush_index,
    get_writer,
    record,
    set_writer,
)

__all__ = [
    "PROTOCOLS",
    "CaptureContext",
    "CaptureSettings",
    "EvidenceStore",
    "EvidenceWriter",
    "Exchange",
    "Probe",
    "Protocol",
    "bind_candidate",
    "candidate",
    "capture_context",
    "commit_check",
    "flush_index",
    "get_settings",
    "get_writer",
    "iteration",
    "probe",
    "record",
    "record_exchange",
    "redact",
    "set_settings",
    "set_writer",
]
