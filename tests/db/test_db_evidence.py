"""
Tests for the evidence index — Phase 57.2, design §5.1.

The document on disk is the evidence; the ``evidence`` table is an index over
it. These tests are about that split: that the index points at a document that
exists, that both hashes are queryable because phase 58 needs them as lookup
keys, and that losing the database costs queryability rather than the corpus.
"""

import pytest

import app.db.engine as _engine_module
from app.capture.models import Exchange
from app.capture.settings import CaptureSettings
from app.capture.store import EvidenceStore
from app.capture.writer import EvidenceWriter
from app.db.engine import Database
from app.db.repositories import EvidenceRepository, ScanRepository
from app.db.writers import EvidenceIndexWriter

pytestmark = pytest.mark.integration


@pytest.fixture
async def db(tmp_path):
    database = Database()
    await database.init(backend="sqlite", db_path=tmp_path / "test.db")
    old_default = _engine_module._default_db
    _engine_module._default_db = database
    yield database
    _engine_module._default_db = old_default
    await database.close()


@pytest.fixture
def evidence_repo(db):
    return EvidenceRepository(db)


@pytest.fixture
async def scan(db):
    """A persisted scan for the evidence rows to hang off."""
    await ScanRepository(db).create_scan(
        scan_id="scan-1", session_id="sess-1", target_domain="acme.test"
    )
    return "scan-1"


def make_exchange(exchange_id: str = "ex1", **overrides) -> Exchange:
    base = {
        "id": exchange_id,
        "scan_id": "scan-1",
        "check_name": "web_header_analysis",
        "host": "acme.test",
        "protocol": "http",
        "request_method": "GET",
        "request_url": "https://acme.test/",
        "response_status": 200,
        "elapsed_ms": 12.0,
        "probe_hash": "p" * 64,
        "content_hash": "c" * 64,
    }
    base.update(overrides)
    return Exchange(**base)


class TestEvidenceRepository:
    async def test_indexes_an_exchange(self, evidence_repo, scan):
        assert await evidence_repo.bulk_create([make_exchange()]) == 1

        rows = await evidence_repo.get_for_scan(scan)
        assert len(rows) == 1
        assert rows[0]["id"] == "ex1"
        assert rows[0]["protocol"] == "http"
        assert rows[0]["probe_hash"] == "p" * 64

    async def test_the_row_points_at_the_document(self, evidence_repo, scan, tmp_path):
        """The pointer must resolve against a store root, or the index is a dead end."""
        store = EvidenceStore(root=tmp_path / "evidence")
        exchange = make_exchange()
        store.write(exchange)
        await evidence_repo.bulk_create([exchange])

        row = await evidence_repo.get("ex1")
        assert (store.root / row["document_path"]).exists()

    async def test_bodies_are_not_in_the_database(self, db, evidence_repo, scan):
        """Files rather than blobs is what keeps a corpus rsync-able."""
        from app.db.models import EvidenceRecord

        columns = {c.name for c in EvidenceRecord.__table__.columns}
        assert "request_body" not in columns
        assert "response_body" not in columns
        assert "response_headers" not in columns

    async def test_empty_batch_is_a_no_op(self, evidence_repo):
        assert await evidence_repo.bulk_create([]) == 0

    async def test_a_batch_may_span_scans(self, db, evidence_repo):
        """Concurrent scans drain through one writer; the batch is not homogeneous."""
        scan_repo = ScanRepository(db)
        await scan_repo.create_scan(scan_id="scan-1", session_id="s", target_domain="a.test")
        await scan_repo.create_scan(scan_id="scan-2", session_id="s", target_domain="b.test")

        await evidence_repo.bulk_create(
            [make_exchange("ex1"), make_exchange("ex2", scan_id="scan-2")]
        )

        assert len(await evidence_repo.get_for_scan("scan-1")) == 1
        assert len(await evidence_repo.get_for_scan("scan-2")) == 1

    async def test_narrows_by_check_and_protocol(self, evidence_repo, scan):
        await evidence_repo.bulk_create(
            [
                make_exchange("ex1", check_name="web_header_analysis"),
                make_exchange("ex2", check_name="network_dns_enumeration", protocol="dns"),
            ]
        )

        by_check = await evidence_repo.get_for_scan(scan, check_name="network_dns_enumeration")
        assert [r["id"] for r in by_check] == ["ex2"]

        by_protocol = await evidence_repo.get_for_scan(scan, protocol="http")
        assert [r["id"] for r in by_protocol] == ["ex1"]

    async def test_probe_hash_groups_sampling_iterations(self, evidence_repo, scan):
        """Phase 58 §4: the same question asked N times, grouped by probe_hash."""
        await evidence_repo.bulk_create(
            [
                make_exchange("ex1", iteration=0, content_hash="a" * 64),
                make_exchange("ex2", iteration=1, content_hash="b" * 64),
                make_exchange("ex3", probe_hash="z" * 64),
            ]
        )

        grouped = await evidence_repo.get_by_probe_hash("p" * 64)
        assert [r["iteration"] for r in grouped] == [0, 1]

    async def test_content_hash_is_the_grade_cache_key(self, evidence_repo, scan):
        """Phase 58 §5: identical evidence must be findable as identical."""
        await evidence_repo.bulk_create(
            [make_exchange("ex1"), make_exchange("ex2", probe_hash="z" * 64)]
        )

        assert len(await evidence_repo.get_by_content_hash("c" * 64)) == 2

    async def test_counts_for_a_scan(self, evidence_repo, scan):
        """The §9 growth number is read off this."""
        await evidence_repo.bulk_create([make_exchange("ex1"), make_exchange("ex2")])
        assert await evidence_repo.count_for_scan(scan) == 2

    async def test_deletes_the_index_for_one_scan(self, evidence_repo, scan):
        await evidence_repo.bulk_create([make_exchange("ex1"), make_exchange("ex2")])
        assert await evidence_repo.delete_scan(scan) == 2
        assert await evidence_repo.get_for_scan(scan) == []

    async def test_get_returns_none_for_an_unknown_exchange(self, evidence_repo):
        assert await evidence_repo.get("nope") is None


class TestEvidenceIndexWriter:
    async def test_writes_a_batch(self, db, scan):
        writer = EvidenceIndexWriter(db=db)
        assert await writer.write([make_exchange()]) == 1

    async def test_empty_batch_is_a_no_op(self, db):
        assert await EvidenceIndexWriter(db=db).write([]) == 0

    async def test_a_dead_database_costs_the_index_not_the_corpus(self, tmp_path):
        """No scratch fallback: the document is already durable on disk."""
        store = EvidenceStore(root=tmp_path / "evidence")
        writer = EvidenceWriter(
            store=store,
            settings=CaptureSettings(enabled=True),
            # No database has been initialized in this test.
            index_writer=EvidenceIndexWriter(),
        )

        exchange = writer.record("http", "acme.test", scan_id="s1")
        assert exchange is not None
        assert await writer.flush_index() == 0
        # The evidence survived; only its index row did not.
        assert store.read("s1", exchange.id) is not None


class TestWriterBuffering:
    async def test_records_queue_until_flushed(self, tmp_path):
        store = EvidenceStore(root=tmp_path / "evidence")
        writer = EvidenceWriter(store=store, settings=CaptureSettings(enabled=True))

        writer.record("http", "acme.test", scan_id="s1")
        assert len(writer.pending) == 1

    async def test_flush_drains_the_buffer(self, db, scan, tmp_path):
        store = EvidenceStore(root=tmp_path / "evidence")
        writer = EvidenceWriter(
            store=store,
            settings=CaptureSettings(enabled=True),
            index_writer=EvidenceIndexWriter(db=db),
        )

        writer.record("http", "acme.test", scan_id=scan)
        assert await writer.flush_index() == 1
        assert writer.pending == []

    async def test_flush_is_free_when_capture_is_off(self, tmp_path):
        """Nothing is queued, so the database layer is never even reached."""
        store = EvidenceStore(root=tmp_path / "evidence")
        writer = EvidenceWriter(store=store, settings=CaptureSettings(enabled=False))

        writer.record("http", "acme.test", scan_id="s1")
        assert writer.pending == []
        assert await writer.flush_index() == 0


class TestCandidateBinding:
    """Phase 57.3, D-22 — the join from a verdict back to its bytes.

    Bound from the grade side: the grader names the exchanges it read, and the
    stage stamps the observation id onto them. The document is updated first and
    the index second, because the document is the evidence.
    """

    async def test_binding_stamps_the_index(self, db, scan, evidence_repo):
        await EvidenceIndexWriter(db=db).write([make_exchange("ex1"), make_exchange("ex2")])

        bound = await evidence_repo.bind_candidate(scan, ["ex1"], "web_headers-acme.test-csp-weak")

        assert bound == 1
        rows = {row["id"]: row["candidate_id"] for row in await evidence_repo.get_for_scan(scan)}
        assert rows["ex1"] == "web_headers-acme.test-csp-weak"
        assert rows["ex2"] is None

    async def test_bound_rows_are_queryable_by_candidate(self, db, scan, evidence_repo):
        await EvidenceIndexWriter(db=db).write([make_exchange("ex1"), make_exchange("ex2")])
        await evidence_repo.bind_candidate(scan, ["ex1", "ex2"], "obs-1")

        rows = await evidence_repo.get_for_candidate(scan, "obs-1")

        assert {row["id"] for row in rows} == {"ex1", "ex2"}

    async def test_binding_is_scoped_to_one_scan(self, db, scan, evidence_repo):
        """Exchange ids are minted per process; the scan is what makes them
        unambiguous across a shared corpus."""
        await EvidenceIndexWriter(db=db).write([make_exchange("ex1")])

        assert await evidence_repo.bind_candidate("other-scan", ["ex1"], "obs-1") == 0

    async def test_binding_nothing_is_a_no_op(self, db, scan, evidence_repo):
        assert await evidence_repo.bind_candidate(scan, [], "obs-1") == 0

    async def test_the_writer_binds_document_and_index_together(self, db, scan, tmp_path):
        store = EvidenceStore(root=tmp_path / "evidence")
        writer = EvidenceWriter(
            store=store,
            settings=CaptureSettings(enabled=True),
            index_writer=EvidenceIndexWriter(db=db),
        )
        exchange = writer.record("http", "acme.test", scan_id=scan)
        await writer.flush_index()

        bound = await writer.bind_candidate(scan, [exchange.id], "obs-1")

        assert bound == 1
        assert store.read(scan, exchange.id).candidate_id == "obs-1"
        rows = await EvidenceRepository(db).get_for_candidate(scan, "obs-1")
        assert [row["id"] for row in rows] == [exchange.id]

    async def test_deferred_exchanges_are_bound_in_place(self, db, scan, tmp_path):
        """`observations_only` holds its exchanges until the check finishes, so
        a binding made during grading has to reach the buffer, not just disk."""
        from app.capture import context as capture_context

        store = EvidenceStore(root=tmp_path / "evidence")
        writer = EvidenceWriter(
            store=store,
            settings=CaptureSettings(enabled=True),
            index_writer=EvidenceIndexWriter(db=db),
        )
        with capture_context.capture_context(
            scan_id=scan, check_name="web_path_probe", policy="observations_only"
        ):
            exchange = writer.record("http", "acme.test", scan_id=scan)

        await writer.bind_candidate(scan, [exchange.id], "obs-1")
        writer.commit_check(scan, "web_path_probe", keep=True)

        assert store.read(scan, exchange.id).candidate_id == "obs-1"
