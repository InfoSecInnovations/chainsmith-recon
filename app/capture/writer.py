"""
app/capture/writer.py - The shared evidence writer.

One writer, several producers. `app/lib/http.py` is the largest — an interceptor
there covers the 231 check modules that route through it without touching any of
them — but it is deliberately *not* the only one. The socket and resolver checks,
the agent LLM path, and any future local check call `record()` directly with
their own `protocol`.

An HTTP-only interceptor would have been cheaper and would have permanently
excluded agents and local checks from the corpus. Keeping them capturable is a
requirement, not an extension.

**Capture never breaks a scan.** Every failure here is swallowed and logged. A
check that cannot record its evidence still runs, still reports, still returns
observations; the gap shows up as a missing row rather than a failed scan.
Recording is important, but it is not more important than the scan.

**How much gets recorded is the check's own declaration** (57.2, decision D-20).
`config.yaml` carries `capture: all | observations_only | none`, resolved like
`on_critical` and carried to here on the capture context. The volume case the
knob exists for is HTTP path-probing — `web_path_probe` and friends fire many
requests each, mostly 404s, and HTTP captures by default — and the check author
is the one who knows that. `observations_only` is the only policy that defers a
write, so the buffering the design rejected as a global mechanism applies to
exactly the checks that ask for it.
"""

from __future__ import annotations

import logging
import uuid

from app.capture import context as capture_context
from app.capture.hashing import apply_hashes
from app.capture.models import MAX_BODY_BYTES, Exchange
from app.capture.settings import CaptureSettings, get_settings
from app.capture.store import EvidenceStore, apply_size_cap

logger = logging.getLogger(__name__)


class EvidenceWriter:
    """Builds, hashes, caps, and persists exchanges."""

    def __init__(
        self,
        store: EvidenceStore | None = None,
        settings: CaptureSettings | None = None,
        index_writer=None,
    ):
        self._store = store or EvidenceStore()
        self._explicit_settings = settings
        self._explicit_index_writer = index_writer
        # `observations_only` exchanges, held until the check finishes and it is
        # known whether the run produced anything. Keyed by (scan, check) rather
        # than kept as one list: concurrent scans and concurrent checks drain
        # through this one writer.
        self._deferred: dict[tuple[str, str], list[Exchange]] = {}
        # Exchanges already on disk and awaiting their index row. `record()` is
        # synchronous — it is called from inside an HTTP interceptor and from
        # socket checks — so it cannot await the database. It buffers instead,
        # and `flush_index()` drains the buffer at the next async boundary.
        self._pending: list[Exchange] = []

    @property
    def settings(self) -> CaptureSettings:
        """The posture in force: an explicitly injected one (tests, embedding),
        else the running scan's, else the process-wide default."""
        if self._explicit_settings is not None:
            return self._explicit_settings
        active = capture_context.current()
        if active is not None and isinstance(active.settings, CaptureSettings):
            return active.settings
        return get_settings()

    # ─── the one entry point ────────────────────────────────────
    def record(
        self,
        protocol: str,
        host: str,
        *,
        request_method: str | None = None,
        request_url: str | None = None,
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        response_status: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str = "",
        elapsed_ms: float | None = None,
        error: str | None = None,
        scan_id: str | None = None,
        check_name: str | None = None,
    ) -> Exchange | None:
        """
        Record one exchange. Returns the stored `Exchange`, or None if not captured.

        `scan_id` and `check_name` are read from the ambient capture context when
        not passed. Producers that run outside a check — the agent LLM path, a
        future local runner — pass them explicitly.
        """
        try:
            return self._record(
                protocol=protocol,
                host=host,
                request_method=request_method,
                request_url=request_url,
                request_headers=request_headers or {},
                request_body=request_body,
                response_status=response_status,
                response_headers=response_headers or {},
                response_body=response_body,
                elapsed_ms=elapsed_ms,
                error=error,
                scan_id=scan_id,
                check_name=check_name,
            )
        except Exception:
            # See the module docstring: capture never breaks a scan.
            logger.warning("Evidence capture failed for %s %s", protocol, host, exc_info=True)
            return None

    def _record(
        self,
        *,
        protocol: str,
        host: str,
        request_method: str | None,
        request_url: str | None,
        request_headers: dict[str, str],
        request_body: str,
        response_status: int | None,
        response_headers: dict[str, str],
        response_body: str,
        elapsed_ms: float | None,
        error: str | None,
        scan_id: str | None,
        check_name: str | None,
    ) -> Exchange | None:
        settings = self.settings

        if not settings.enabled:
            return None
        if not settings.captures(protocol):
            return None
        # A failed probe is usually target flakiness rather than signal, and the
        # corpus stays cleaner without it. But a refused connection, or a timeout
        # that appears consistently under one specific payload, is occasionally
        # the whole finding — hence a toggle rather than a hard rule.
        if error is not None and not settings.capture_failures:
            return None

        active = capture_context.current()

        # How much this check records is its own declaration (D-20), unless the
        # scan overrides it or its suite is exempt. Checked before the row is
        # built: a `none` check should cost nothing at all.
        policy = settings.effective_policy(
            active.policy if active else "all",
            active.suite if active else "",
        )
        if policy == "none":
            return None

        # Attribution: explicit argument, else the ambient context. A row with no
        # scan cannot be linked to anything, so it is not worth writing — but the
        # check being unknown is fine, and the row is attributed to the scan
        # alone rather than guessing.
        resolved_scan_id = scan_id or (active.scan_id if active else None)
        if not resolved_scan_id:
            logger.debug("Skipping capture with no scan attribution: %s %s", protocol, host)
            return None

        exchange = Exchange(
            id=uuid.uuid4().hex,
            scan_id=resolved_scan_id,
            check_name=check_name or (active.check_name if active else ""),
            host=host,
            protocol=protocol,
            candidate_id=active.candidate_id if active else None,
            iteration=active.iteration if active else 0,
            request_method=request_method,
            request_url=request_url,
            request_headers=dict(request_headers),
            request_body=request_body,
            response_status=response_status,
            response_headers=dict(response_headers),
            response_body=response_body,
            elapsed_ms=elapsed_ms,
            error=error,
        )

        # Cap before hashing, so the hash covers exactly what was stored. Hashing
        # the full body and storing a truncated one would make `content_hash`
        # unverifiable from the corpus — the one property it exists to provide.
        apply_size_cap(exchange, settings.max_body_bytes or MAX_BODY_BYTES)
        apply_hashes(exchange)

        if policy == "observations_only":
            # Held, not written. `commit_check()` decides at the end of the run.
            self._deferred.setdefault((resolved_scan_id, exchange.check_name), []).append(exchange)
            return exchange

        self._store.write(exchange)
        # The document is the evidence and it is now durable. The index row is
        # queued rather than written here, and its loss would cost queryability
        # rather than the corpus — see `EvidenceIndexWriter`.
        self._pending.append(exchange)
        return exchange

    # ─── deferred writes (`capture: observations_only`) ─────────
    def commit_check(self, scan_id: str, check_name: str, *, keep: bool) -> int:
        """
        Resolve one check's held exchanges. Returns how many were written.

        Called by `BaseCheck.execute()` once the run is over, which is the first
        moment "did this produce anything" can be answered. `keep=False` drops
        the buffer — that is the whole point of the policy, and it is what turns
        200 fruitless 404s into no corpus at all.

        **The rule is run-scoped, not exchange-scoped.** A check that found
        something keeps every exchange of that run, including the ones that
        found nothing, because they are the context the finding sits in.
        Per-exchange linkage needs the candidate binding that arrives with 57.3;
        until then this is the honest approximation, and it solves the volume
        case the policy was added for.
        """
        held = self._deferred.pop((scan_id, check_name), [])
        if not held or not keep:
            return 0
        written = 0
        for exchange in held:
            try:
                self._store.write(exchange)
            except Exception:
                logger.warning("Evidence capture failed for %s", exchange.id, exc_info=True)
                continue
            self._pending.append(exchange)
            written += 1
        return written

    # ─── candidate binding (57.3, D-22) ─────────────────────────
    async def bind_candidate(self, scan_id: str, exchange_ids: list[str], candidate_id: str) -> int:
        """
        Link stored exchanges to the observation a grader derived from them.

        Called by the grading stage once a verdict names what it read. Touches
        the documents first and the index second, in that order for the same
        reason `record()` does: the document is the evidence, the index is a
        convenience over it. Returns how many documents were stamped.

        Best-effort throughout. An unbound row costs a join, not a corpus.
        """
        if not exchange_ids or not scan_id:
            return 0

        # Exchanges still held by `observations_only` are in memory, not on
        # disk; stamp those in place so the binding survives `commit_check`.
        wanted = set(exchange_ids)
        for held in self._deferred.values():
            for exchange in held:
                if exchange.id in wanted:
                    exchange.candidate_id = candidate_id

        bound = 0
        for exchange_id in exchange_ids:
            try:
                if self._store.bind_candidate(scan_id, exchange_id, candidate_id):
                    bound += 1
            except Exception:
                logger.debug("Candidate binding failed for %s", exchange_id, exc_info=True)

        try:
            from app.db.repositories import EvidenceRepository

            await EvidenceRepository().bind_candidate(scan_id, exchange_ids, candidate_id)
        except Exception:
            logger.debug("Candidate binding index update failed", exc_info=True)

        return bound

    # ─── the database half ──────────────────────────────────────
    @property
    def pending(self) -> list[Exchange]:
        """Exchanges on disk that have not been indexed yet."""
        return list(self._pending)

    async def flush_index(self) -> int:
        """
        Index everything written since the last drain. Returns rows indexed.

        Cheap when capture is off: nothing is ever queued, so this returns on
        the first line without importing the database layer at all. Awaited by
        `BaseCheck.execute()` once per check, which is the natural async
        boundary — one batch per check, and never inside the request path.

        The buffer is process-wide rather than per-scan. Two concurrent scans
        drain through it together and that is fine: every exchange carries its
        own `scan_id`, so the batch does not have to be homogeneous.
        """
        if not self._pending:
            return 0

        batch = self._pending
        self._pending = []

        try:
            return await self._index_writer().write(batch)
        except Exception:
            # See the module docstring: capture never breaks a scan. The
            # documents are already on disk, so this loses the index, not the
            # evidence.
            logger.warning("Evidence indexing failed for %d exchanges", len(batch), exc_info=True)
            return 0

    def _index_writer(self):
        """Resolved lazily so `app.capture` does not import `app.db` at all
        unless something is actually captured."""
        if self._explicit_index_writer is None:
            from app.db.writers import EvidenceIndexWriter

            self._explicit_index_writer = EvidenceIndexWriter()
        return self._explicit_index_writer


# ── Process-wide writer ──────────────────────────────────────────
#
# One instance, resolved lazily so the store picks up whichever workspace the
# entry point installed.

_writer: EvidenceWriter | None = None


def get_writer() -> EvidenceWriter:
    global _writer
    if _writer is None:
        _writer = EvidenceWriter()
    return _writer


def set_writer(writer: EvidenceWriter) -> EvidenceWriter:
    """Install a writer. For tests and for embedding."""
    global _writer
    _writer = writer
    return writer


def reset_writer() -> None:
    """Drop the process-wide writer. For tests."""
    global _writer
    _writer = None


def record(protocol: str, host: str, **kwargs) -> Exchange | None:
    """Module-level convenience for producers: `capture.record("dns", host, ...)`."""
    return get_writer().record(protocol, host, **kwargs)


def commit_check(scan_id: str, check_name: str, *, keep: bool) -> int:
    """Resolve a check's deferred exchanges on the process-wide writer."""
    return get_writer().commit_check(scan_id, check_name, keep=keep)


async def flush_index() -> int:
    """Drain the process-wide writer's pending index rows."""
    return await get_writer().flush_index()


async def bind_candidate(scan_id: str, exchange_ids: list[str], candidate_id: str) -> int:
    """Bind exchanges to the observation graded from them (57.3, D-22)."""
    return await get_writer().bind_candidate(scan_id, exchange_ids, candidate_id)
