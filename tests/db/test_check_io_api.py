"""
Tests for GET /api/v1/scans/{scan_id}/check-io — the phase-47 read surface,
delivered on phase-57 data (design §5.3, doc §0.5 item 3).

This is the first place captured evidence reaches a human, so it is the first
place redaction has to earn its keep. The properties under test are that the
default view masks secrets, that the unredacted view is reachable but explicit,
that a curl command reproduces what the *viewer* was shown rather than what is
on disk, and that a corpus whose index write failed is still readable.
"""

from __future__ import annotations

import pytest

import app.db.engine as _engine_module
from app import workspace as ws
from app.capture.models import Exchange
from app.db.engine import Database
from app.db.repositories import EvidenceRepository, ScanRepository
from app.routes.scan_history import router

pytestmark = pytest.mark.integration


@pytest.fixture
async def client(db):
    """An ASGI client over the scan-history router alone.

    Driven through HTTP rather than by calling the route function directly, so
    the `Query(...)` defaults — `limit`, `unredacted` — resolve the way they do
    in production instead of arriving as FastAPI marker objects. Same event
    loop as the `db` fixture, which a sync `TestClient` would not share.
    """
    import httpx
    from fastapi import FastAPI

    api = FastAPI()
    api.include_router(router)
    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


async def get_check_io(client, scan_id: str, **params):
    """Call the endpoint and return its JSON, or raise on a non-200."""
    response = await client.get(f"/api/v1/scans/{scan_id}/check-io", params=params)
    response.raise_for_status()
    return response.json()


@pytest.fixture
def workspace(tmp_path):
    installed = ws.set_workspace(ws.Workspace(root=tmp_path / "acme"))
    installed.ensure()
    yield installed
    ws.reset_workspace()


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
async def scan(db):
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
        "request_url": "https://acme.test/admin",
        "request_headers": {"Authorization": "Bearer sk-abcdefghijklmnopqrst"},
        "response_status": 200,
        "response_body": "hello",
        "elapsed_ms": 12.0,
        "probe_hash": "p" * 64,
        "content_hash": "c" * 64,
    }
    base.update(overrides)
    return Exchange(**base)


async def store_and_index(workspace, db, *exchanges: Exchange, index: bool = True) -> None:
    from app.capture.store import EvidenceStore

    store = EvidenceStore()
    for exchange in exchanges:
        store.write(exchange)
    if index:
        await EvidenceRepository(db).bulk_create(list(exchanges))


class TestCheckIOEndpoint:
    async def test_unknown_scan_is_a_404(self, workspace, client):
        response = await client.get("/api/v1/scans/nope/check-io")
        assert response.status_code == 404

    async def test_a_scan_with_no_evidence_returns_an_empty_list(self, workspace, db, client, scan):
        """Capture is off by default, so this is the normal case."""
        result = await get_check_io(client, scan)
        assert result["count"] == 0
        assert result["exchanges"] == []

    async def test_returns_the_captured_exchange(self, workspace, db, client, scan):
        await store_and_index(workspace, db, make_exchange())

        result = await get_check_io(client, scan)

        assert result["count"] == 1
        assert result["exchanges"][0]["request_url"] == "https://acme.test/admin"
        assert result["exchanges"][0]["response_body"] == "hello"

    async def test_secrets_are_masked_by_default(self, workspace, db, client, scan):
        from app.capture.redaction import MASK

        await store_and_index(workspace, db, make_exchange())

        result = await get_check_io(client, scan)

        assert result["redacted"] is True
        assert result["exchanges"][0]["request_headers"]["Authorization"] == MASK

    async def test_unredacted_is_reachable_but_explicit(self, workspace, db, client, scan, caplog):
        """§5.3(3): a privileged action, and logged as one."""
        await store_and_index(workspace, db, make_exchange())

        with caplog.at_level("WARNING"):
            result = await get_check_io(client, scan, unredacted=True)

        assert result["redacted"] is False
        assert (
            "sk-abcdefghijklmnopqrst" in result["exchanges"][0]["request_headers"]["Authorization"]
        )
        assert "Unredacted evidence read" in caplog.text

    async def test_the_curl_command_reproduces_what_the_viewer_saw(
        self, workspace, db, client, scan
    ):
        """A redacted view must not hand out the operator's real token."""
        from app.capture.redaction import MASK

        await store_and_index(workspace, db, make_exchange())

        redacted = await get_check_io(client, scan)
        assert MASK in redacted["exchanges"][0]["curl"]
        assert "sk-abcdefghijklmnopqrst" not in redacted["exchanges"][0]["curl"]

        clear = await get_check_io(client, scan, unredacted=True)
        assert "sk-abcdefghijklmnopqrst" in clear["exchanges"][0]["curl"]

    async def test_non_http_exchanges_offer_no_curl(self, workspace, db, client, scan):
        """A command that would not run is worse than no button."""
        await store_and_index(
            workspace,
            db,
            make_exchange(
                protocol="dns",
                request_method=None,
                request_url=None,
                request_headers={},
                request_body="A acme.test",
            ),
        )

        result = await get_check_io(client, scan)
        assert result["exchanges"][0]["curl"] is None

    async def test_narrows_by_check_and_protocol(self, workspace, db, client, scan):
        await store_and_index(
            workspace,
            db,
            make_exchange("ex1"),
            make_exchange("ex2", check_name="network_wildcard_dns", protocol="dns"),
        )

        by_check = await get_check_io(client, scan, check="network_wildcard_dns")
        assert [e["id"] for e in by_check["exchanges"]] == ["ex2"]

        by_protocol = await get_check_io(client, scan, protocol="http")
        assert [e["id"] for e in by_protocol["exchanges"]] == ["ex1"]

    async def test_a_files_only_corpus_is_still_readable(self, workspace, db, client, scan):
        """The documents are the evidence; the table is an index over them. An
        index write that failed must not hide the corpus."""
        await store_and_index(workspace, db, make_exchange(), index=False)

        result = await get_check_io(client, scan)

        assert result["count"] == 1
        assert result["exchanges"][0]["id"] == "ex1"

    async def test_a_files_only_corpus_still_filters(self, workspace, db, client, scan):
        await store_and_index(
            workspace,
            db,
            make_exchange("ex1"),
            make_exchange("ex2", protocol="dns"),
            index=False,
        )

        result = await get_check_io(client, scan, protocol="dns")
        assert [e["id"] for e in result["exchanges"]] == ["ex2"]
