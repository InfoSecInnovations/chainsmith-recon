"""
app/capture/probes.py - Recording a non-HTTP exchange.

`app/lib/http.py` has an interceptor, so the 231 check modules that route
through it are captured without being touched. The socket and resolver checks
have no such chokepoint: each opens its own socket, and each already wraps that
work in the same shape — an async method that runs a blocking call in an
executor, times out, and swallows its own errors.

`probe()` is the chokepoint for those. It times the block, records what came
back, and records a failure as a failure rather than as an empty response:

    async with capture.probe("dns", hostname, request_body="A") as probe:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, ...)
        probe.responded(infos[0][4][0])

Attribution is ambient. `BaseCheck.execute()` sets it and every one of these
sites is awaited from inside `run()`, so the `ContextVar` is still in scope —
the executor boundary is crossed *below* the recording, never across it, which
is exactly the guardrail in `context.py`.

**Recording never changes control flow.** An exception raised inside the block
is recorded and then re-raised untouched, so the check's own `except` clause
sees precisely what it saw before.

**Every probe hands its exchange back** (57.4 wave 2). `handle.exchange` is set
when the block exits: the stored row when capture wrote one, an equivalent
unstored `Exchange` when it did not. A migrated socket check attaches it to its
candidate and the grader reads it either way, which is what keeps probe/grade
working with capture off — the default posture (§0.4). Without this a migrated
resolver check would have had to build the exchange a second time, by hand,
beside the one `record()` already built.
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from app.capture import context as capture_context
from app.capture.hashing import apply_hashes
from app.capture.models import Exchange
from app.capture.store import apply_size_cap
from app.capture.writer import record

logger = logging.getLogger(__name__)


@dataclass
class Probe:
    """What came back. Filled in by the block; read by `probe()` on exit."""

    response_body: str = ""
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)

    #: The exchange this probe produced, available once the block has exited
    #: (57.4 wave 2). The stored row when capture wrote one, an unstored
    #: equivalent when it did not, so a migrated check can always do
    #: `candidate.attach(prb.exchange)` without asking whether capture is on.
    exchange: Exchange | None = None

    def responded(
        self,
        body: str = "",
        *,
        status: int | None = None,
        **headers: str,
    ) -> None:
        """
        Record what the peer answered.

        `body` carries the protocol-native answer — the resolved address, the
        banner bytes, the WHOIS record. `status` is the protocol's equivalent of
        an HTTP status where one exists (a DNS rcode, an exit code) and is left
        null where none does. Keyword arguments become protocol metadata on
        `response_headers`.
        """
        self.response_body = body
        self.response_status = status
        self.response_headers.update({k: str(v) for k, v in headers.items()})


@asynccontextmanager
async def probe(
    protocol: str,
    host: str,
    *,
    request_body: str = "",
    **request_headers: str,
):
    """
    Record one non-HTTP exchange with `host`, timing the block.

    A block that never calls `responded()` records an empty response, which is
    the honest record of a query that completed and returned nothing — an
    NXDOMAIN, a port that accepted the connection and said nothing. A block that
    raises records `error` instead, and the exception is re-raised unchanged.
    """
    handle = Probe()
    started = time.perf_counter()
    headers = {k: str(v) for k, v in request_headers.items()}
    try:
        yield handle
    except BaseException as exc:
        fields = {
            "request_body": request_body,
            "request_headers": headers,
            "elapsed_ms": (time.perf_counter() - started) * 1000,
            "error": f"{type(exc).__name__}: {exc}",
        }
        handle.exchange = record_exchange(protocol, host, **fields)
        raise
    else:
        fields = {
            "request_body": request_body,
            "request_headers": headers,
            "response_status": handle.response_status,
            "response_headers": handle.response_headers,
            "response_body": handle.response_body,
            "elapsed_ms": (time.perf_counter() - started) * 1000,
        }
        handle.exchange = record_exchange(protocol, host, **fields)


def record_exchange(protocol: str, host: str, **fields) -> Exchange:
    """Record one exchange and hand it back, stored or not (57.4 wave 2).

    `probe()`'s timing context manager is the right shape for a blocking call
    whose duration is part of the record. A probe that already holds its result —
    a TCP connect that either completed or raised, a library call that returns a
    parsed object — wants only this: one exchange for the grader, written to the
    corpus if capture wants it.

    Always returns an exchange, so a migrated check never branches on whether
    capture is on — including when building one fails, which is the same rule
    `record()` follows: capture never breaks a scan. A caller that hands in an
    unserialisable header value gets an attribution-only exchange and a warning,
    not an exception in the middle of its probe.
    """
    stored = record(protocol, host, **fields)
    if stored is not None:
        return stored
    try:
        return _handoff(protocol, host, **fields)
    except Exception:
        logger.warning("Could not build hand-off exchange for %s %s", protocol, host, exc_info=True)
        return _handoff(protocol, host)


def _handoff(protocol: str, host: str, **fields) -> Exchange:
    """One exchange for the grader, built but never stored.

    `record()` returns None whenever capture declined the row — it is off, the
    protocol is not captured, the policy is `none`, there is no scan to attribute
    to. The grader still needs the bytes (§0.9: "grading works with capture
    off"), so the same exchange is built here and handed over in memory. It is
    capped and hashed exactly as the writer would, so a probe cannot tell which
    path produced its exchange and `evidence_for` can still pair it with a
    stored copy by `content_hash` when one turns up.
    """
    active = capture_context.current()
    exchange = Exchange(
        id=uuid.uuid4().hex,
        scan_id=(active.scan_id if active else ""),
        check_name=(active.check_name if active else ""),
        host=host,
        protocol=protocol,
        candidate_id=(active.candidate_id if active else None),
        iteration=(active.iteration if active else 0),
        **fields,
    )
    apply_size_cap(exchange)
    return apply_hashes(exchange)
