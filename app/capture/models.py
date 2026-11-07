"""
app/capture/models.py - The captured exchange.

One `Exchange` is one request/response pair, recorded verbatim, in whatever
protocol the check speaks. Below the capture line: no severity, no verdict, no
interpretation of any kind. What a grader later makes of it is its own
business and never reaches back into this object.

The bodies live on disk under the workspace's `evidence/`; the database holds
this row's scalar fields plus pointers. See `store.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.lib.timeutils import now_utc

#: Bodies larger than this are truncated and flagged (§5.1).
MAX_BODY_BYTES: int = 256 * 1024


@dataclass
class Exchange:
    """One captured request/response pair.

    `request_method` / `request_url` / `response_status` are nullable because
    they are HTTP-shaped: a `dns` or `local` exchange has no method and no URL,
    and `request_body` carries the protocol-native payload instead (the query
    name and type, the bytes written to the socket, the argv).
    """

    # ─── identity + linkage ─────────────────────────────────────
    id: str
    scan_id: str
    check_name: str
    host: str
    protocol: str

    #: Nullable: capture may precede the candidate it will support.
    candidate_id: str | None = None
    #: Sample index; 0 for single-shot.
    iteration: int = 0

    # ─── request ────────────────────────────────────────────────
    request_method: str | None = None
    request_url: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    # ─── response ───────────────────────────────────────────────
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float | None = None

    #: Transport/timeout failure text for a probe that never completed. Written
    #: only when `capture_failures` is on; the grader is then told the probe
    #: *failed* rather than being shown an empty response and left to infer.
    error: str | None = None

    # ─── derived ────────────────────────────────────────────────
    probe_hash: str = ""
    content_hash: str = ""
    truncated: bool = False
    captured_at: datetime = field(default_factory=now_utc)

    @property
    def completed(self) -> bool:
        """True when the exchange actually produced a response."""
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "check_name": self.check_name,
            "host": self.host,
            "protocol": self.protocol,
            "candidate_id": self.candidate_id,
            "iteration": self.iteration,
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "probe_hash": self.probe_hash,
            "content_hash": self.content_hash,
            "truncated": self.truncated,
            "captured_at": self.captured_at.isoformat(),
        }
