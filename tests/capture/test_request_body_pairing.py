"""
B-8: a probe's in-memory exchange hashes the same as the interceptor's copy.

`evidence_for` pairs a candidate's in-memory exchanges with the corpus by
`content_hash`, and the hash covers the request body and headers. The interceptor
used to store a bytes body as `str(data)`, which is the literal `"b'--...'"`,
while probes recorded decoded text. Multipart probes also recorded no headers.
So `rag_corpus_poisoning`, `rag_multimodal_injection` and `cag_serialization`
could never be re-graded from the corpus.

The reference here is the real interceptor (`AsyncHttpClient._capture`), with
the writer's `record()` captured. The tests do not restate the rule.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.capture.hashing import apply_hashes
from app.capture.models import MAX_BODY_BYTES, Exchange
from app.capture.store import apply_size_cap
from app.grading import exchange_from_response
from app.lib.http import AsyncHttpClient, HttpResponse, request_body_text

pytestmark = pytest.mark.unit

URL = "http://vector.test:8087/documents"
RESPONSE = HttpResponse(url=URL, status_code=201, headers={}, body="ok", elapsed_ms=5.0)


def _interceptor_copy(method, headers, json_body=None, data=None) -> Exchange:
    """What the capture interceptor would store for this request."""
    captured: dict = {}

    def fake_record(protocol, host, **kwargs):
        captured.update(kwargs, protocol=protocol, host=host)

    with patch("app.capture.writer.record", fake_record):
        AsyncHttpClient._capture(method, URL, headers, json_body, data, RESPONSE)

    exchange = Exchange(
        id=uuid.uuid4().hex,
        scan_id="s",
        check_name="c",
        host=captured["host"],
        protocol=captured["protocol"],
        request_method=captured["request_method"],
        request_url=captured["request_url"],
        request_headers=dict(captured["request_headers"]),
        request_body=captured["request_body"],
        response_status=captured["response_status"],
        response_headers=dict(captured["response_headers"]),
        response_body=captured["response_body"],
        elapsed_ms=captured["elapsed_ms"],
        error=captured["error"],
    )
    apply_size_cap(exchange, MAX_BODY_BYTES)
    return apply_hashes(exchange)


MULTIPART = (
    b"--chainsmith-abc\r\n"
    b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n'
    b"hello\r\n--chainsmith-abc--\r\n"
)
BINARY = b"--b\r\n\r\n%PDF-1.4\n\xe2\xe3\xcf\xd3 binary \xff\xfe\r\n--b--\r\n"
HEADERS = {"Content-Type": "multipart/form-data; boundary=chainsmith-abc"}


@pytest.mark.parametrize(
    "data",
    [MULTIPART, BINARY, b"", bytearray(b"abc"), "plain text", {"a": "1", "b": ["2", "3"]}],
    ids=["multipart", "binary", "empty-bytes", "bytearray", "text", "form-dict"],
)
def test_in_memory_copy_pairs_with_the_interceptor_copy(data):
    stored = _interceptor_copy("POST", HEADERS, data=data)
    memory = exchange_from_response(
        RESPONSE,
        check_name="c",
        host="vector.test",
        method="POST",
        request_headers=HEADERS,
        request_data=data,
    )
    assert memory.request_body == stored.request_body
    assert memory.content_hash == stored.content_hash


def test_json_bodies_still_pair():
    payload = {"text": "café", "n": 1}
    stored = _interceptor_copy("POST", {"Content-Type": "application/json"}, json_body=payload)
    memory = exchange_from_response(
        RESPONSE,
        check_name="c",
        host="vector.test",
        method="POST",
        request_headers={"Content-Type": "application/json"},
        request_json=payload,
    )
    assert memory.content_hash == stored.content_hash


class TestTheRule:
    def test_bytes_are_stored_as_text_not_their_repr(self):
        assert request_body_text(data=MULTIPART).startswith("--chainsmith-abc")
        assert request_body_text(data=b"") == ""

    def test_undecodable_bytes_round_trip_through_latin1(self):
        text = request_body_text(data=BINARY)
        assert text.encode("latin-1") == BINARY

    def test_json_wins_over_data_and_nothing_is_empty(self):
        assert request_body_text({"a": 1}, b"ignored") == json.dumps({"a": 1})
        assert request_body_text() == ""


async def test_rag_corpus_poisoning_records_the_multipart_request_it_sent():
    """End to end through the check: the multipart attempt it records matches
    the request it actually sent, headers included, so the corpus copy pairs."""
    from app.checks.base import Service
    from app.checks.rag.rag_corpus_poisoning import RAGCorpusPoisoningCheck

    sent: list[dict] = []

    async def post(url=None, **kw):
        sent.append({"url": url, **kw})
        # Reject JSON so the probe falls through to its multipart attempt.
        status = 415 if "json" in kw else 201
        return HttpResponse(url=url, status_code=status, headers={}, body="", elapsed_ms=1.0)

    client = AsyncMock()
    client.post = AsyncMock(side_effect=post)
    client.get = AsyncMock(
        side_effect=lambda url=None, **kw: HttpResponse(
            url=url, status_code=404, headers={}, body="", elapsed_ms=1.0
        )
    )
    client.delete = client.get
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    service = Service(url="http://vector.test:8087", host="vector.test", port=8087, scheme="http")
    context = {
        "rag_endpoints": [{"url": "http://vector.test:8087/query", "service": service.to_dict()}]
    }
    with patch("app.checks.rag.rag_corpus_poisoning.check.AsyncHttpClient", return_value=client):
        result = await RAGCorpusPoisoningCheck().check_service(service, context)

    multipart_sent = [s for s in sent if "data" in s]
    assert multipart_sent, "the probe never reached its multipart attempt"
    first = multipart_sent[0]

    recorded = [
        e
        for c in result.candidates
        for e in c.exchanges
        if (e.request_body or "").startswith("--chainsmith-")
    ]
    assert recorded
    stored = _interceptor_copy("POST", first["headers"], data=first["data"])
    assert recorded[0].request_headers == first["headers"]
    assert recorded[0].request_body == stored.request_body


def test_exchange_documents_are_compact_and_old_indented_ones_still_read(tmp_path):
    """Phase 57 size item: exchange documents are written without indentation;
    a document written the old way (indent=2) still loads identically."""
    import json as _json

    from app.capture.store import EvidenceStore

    store = EvidenceStore(root=tmp_path)
    exchange = exchange_from_response(RESPONSE, check_name="c", scan_id="s1", host="vector.test")
    path = store.write(exchange)
    text = path.read_text(encoding="utf-8")
    assert "\n" not in text and ": " not in text.split('"response_body"')[0]

    path.write_text(_json.dumps(exchange.to_dict(), indent=2), encoding="utf-8")
    again = store.read("s1", exchange.id)
    assert again is not None and again.content_hash == exchange.content_hash
