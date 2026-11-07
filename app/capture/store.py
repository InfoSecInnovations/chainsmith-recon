"""
app/capture/store.py - The on-disk evidence store.

Bodies live as files under the workspace's `evidence/`; the database holds the
scalar row plus pointers and both hashes. Files rather than blobs keeps the
database portable and makes a corpus `rsync`-able for offline re-grading — which
is the whole point of capturing it.

Layout:

    <workspace>/evidence/<scan_id>/<exchange_id>.json
    <workspace>/evidence/<scan_id>/grading/<check_name>.json

One JSON document per exchange, holding the full record. Sharding by scan keeps
directories navigable and makes "delete this scan's evidence" a directory
removal rather than a query.

`grading/` holds what an offline re-grade needs besides the bytes — each
check's candidates and the scan context it was graded against (57.4, see
`app/grading/record.py`). It is a subdirectory so that `read_scan` never
mistakes a record for an exchange.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.capture.models import MAX_BODY_BYTES, Exchange

logger = logging.getLogger(__name__)

#: Appended to a body that hit the size cap, so a reader can tell a truncated
#: body from one that genuinely ended there.
TRUNCATION_MARKER = "\n...[truncated by Chainsmith at {cap} bytes]"


def truncate_body(body: str, cap: int = MAX_BODY_BYTES) -> tuple[str, bool]:
    """
    Cap a body at `cap` bytes, returning `(body, was_truncated)`.

    Measured in UTF-8 bytes, not characters, because the cap is about storage.
    The cut is made on a character boundary so the result stays decodable.
    """
    encoded = body.encode("utf-8")
    if len(encoded) <= cap:
        return body, False
    clipped = encoded[:cap].decode("utf-8", errors="ignore")
    return clipped + TRUNCATION_MARKER.format(cap=cap), True


def apply_size_cap(exchange: Exchange, cap: int = MAX_BODY_BYTES) -> Exchange:
    """Truncate both bodies in place and set `truncated` if either was cut."""
    exchange.request_body, request_cut = truncate_body(exchange.request_body, cap)
    exchange.response_body, response_cut = truncate_body(exchange.response_body, cap)
    exchange.truncated = request_cut or response_cut
    return exchange


class EvidenceStore:
    """Reads and writes exchange documents under one evidence root."""

    def __init__(self, root: Path | None = None):
        self._explicit_root = root

    @property
    def root(self) -> Path:
        """Resolved lazily — the store may be constructed before launch."""
        if self._explicit_root is not None:
            return self._explicit_root
        from app.workspace import get_workspace

        return get_workspace().evidence_dir

    def path_for(self, scan_id: str, exchange_id: str) -> Path:
        return self.root / scan_id / f"{exchange_id}.json"

    def scan_dir(self, scan_id: str) -> Path:
        return self.root / scan_id

    # ─── write ──────────────────────────────────────────────────
    def write(self, exchange: Exchange) -> Path:
        """Persist one exchange. Returns the path written."""
        path = self.path_for(exchange.scan_id, exchange.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Compact, like the grading records: an exchange document is read by
        # `json.loads`, never by eye (`dev` tooling and the API pretty-print), and
        # `indent=2` was a measurable share of the ~4.8 MB of exchange documents
        # per full fakobanko scan (D-21). Hashes cover fields, not file text, so
        # older indented documents still read and pair the same.
        path.write_text(
            json.dumps(exchange.to_dict(), separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    # ─── read ───────────────────────────────────────────────────
    def read(self, scan_id: str, exchange_id: str) -> Exchange | None:
        """
        Load one exchange, or None if it is not in the store.

        Returns the **unredacted** record. Callers rendering a default view pass
        it through `redaction.redact()`; see that module for why the split lives
        at read time rather than write time.
        """
        path = self.path_for(scan_id, exchange_id)
        if not path.exists():
            return None
        return self._load(path)

    def read_scan(self, scan_id: str) -> list[Exchange]:
        """Every exchange captured for one scan, ordered by capture time."""
        directory = self.scan_dir(scan_id)
        if not directory.is_dir():
            return []
        exchanges = [
            loaded
            for path in sorted(directory.glob("*.json"))
            if (loaded := self._load(path)) is not None
        ]
        exchanges.sort(key=lambda e: e.captured_at)
        return exchanges

    @staticmethod
    def _load(path: Path) -> Exchange | None:
        from datetime import datetime

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A corpus with one unreadable file is still a corpus. Losing the
            # rest because of it would be the worse outcome.
            logger.warning("Unreadable evidence document, skipping: %s", path)
            return None

        raw["captured_at"] = datetime.fromisoformat(raw["captured_at"])
        return Exchange(**raw)

    # ─── candidate binding (57.3, D-22) ─────────────────────────
    def bind_candidate(self, scan_id: str, exchange_id: str, candidate_id: str) -> bool:
        """
        Record which observation one stored exchange was graded into.

        Written to the document as well as the index because the document is the
        evidence: a corpus copied to another machine, or one whose index write
        failed, still has to answer "which verdict came from these bytes".

        The hashes are left alone. They identify what was *captured*, and the
        binding is something a grader decided afterwards — recomputing them here
        would make the stored bytes fail their own verification.
        """
        path = self.path_for(scan_id, exchange_id)
        exchange = self._load(path) if path.exists() else None
        if exchange is None:
            return False
        exchange.candidate_id = candidate_id
        self.write(exchange)
        return True

    # ─── grading records (57.4, offline re-grade) ───────────────
    def grading_dir(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "grading"

    def context_dir(self, scan_id: str) -> Path:
        return self.grading_dir(scan_id) / "context"

    def write_grading_record(self, scan_id: str, check_name: str, record: dict) -> Path:
        """Persist one check's grading record, compact. Returns the path written."""
        path = self.grading_dir(scan_id) / f"{check_name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(record, separators=(",", ":"), ensure_ascii=False), encoding="utf-8"
        )
        return path

    def write_context_value(self, scan_id: str, digest: str, encoded: str) -> Path:
        """Store one context value under its content hash. A value already
        stored is not rewritten — the name is its content."""
        path = self.context_dir(scan_id) / f"{digest}.json"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(encoded, encoding="utf-8")
        return path

    def read_context_value(self, scan_id: str, digest: str) -> tuple[bool, object]:
        """`(found, value)` for one stored context value."""
        path = self.context_dir(scan_id) / f"{digest}.json"
        try:
            return True, json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return False, None
        except (OSError, json.JSONDecodeError):
            logger.warning("Unreadable context value, skipping: %s", path)
            return False, None

    def read_grading_records(self, scan_id: str) -> list[dict]:
        """Every grading record for one scan, ordered by check name."""
        directory = self.grading_dir(scan_id)
        if not directory.is_dir():
            return []
        records = []
        for path in sorted(directory.glob("*.json")):
            try:
                records.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                logger.warning("Unreadable grading record, skipping: %s", path)
        return records

    # ─── retention ──────────────────────────────────────────────
    def delete_scan(self, scan_id: str) -> int:
        """Remove one scan's evidence. Returns how many exchange documents were
        deleted; its grading records go with them."""
        directory = self.scan_dir(scan_id)
        if not directory.is_dir():
            return 0
        removed = 0
        for path in directory.glob("*.json"):
            path.unlink()
            removed += 1
        grading = self.grading_dir(scan_id)
        if grading.is_dir():
            context = self.context_dir(scan_id)
            if context.is_dir():
                for path in context.glob("*.json"):
                    path.unlink()
                context.rmdir()
            for path in grading.glob("*.json"):
                path.unlink()
            grading.rmdir()
        directory.rmdir()
        return removed
