"""Tests for rag_corpus_poisoning.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_corpus_poisoning import RAGCorpusPoisoningCheck
from app.lib.http import HttpResponse


@pytest.fixture
def sample_service():
    return Service(
        url="http://rag.example.com:8080",
        host="rag.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def rag_context(sample_service):
    """Context with RAG endpoints and vector stores discovered."""
    return {
        "rag_endpoints": [
            {
                "url": "http://rag.example.com:8080/query",
                "path": "/query",
                "method": "POST",
                "indicators": ["field:sources"],
                "auth_required": False,
                "service": sample_service.to_dict(),
                "endpoint_type": "rag_query",
            },
            {
                "url": "http://rag.example.com:8080/api/v1/collections",
                "path": "/api/v1/collections",
                "store_type": "chroma",
                "status_code": 200,
                "auth_required": False,
                "service": sample_service.to_dict(),
                "endpoint_type": "vector_store",
            },
        ],
        "vector_stores": ["chroma"],
    }


@pytest.fixture
def accessible_store_context(rag_context):
    """Context with accessible vector stores."""
    ctx = dict(rag_context)
    ctx["accessible_stores"] = [
        {
            "store_type": "chroma",
            "accessible_ops": [
                {"operation": "list_collections", "path": "/api/v1/collections", "status": 200},
                {
                    "operation": "dump_documents",
                    "path": "/api/v1/collections/docs/get",
                    "status": 200,
                },
            ],
            "collections": ["docs", "hr_policies", "faq"],
            "doc_count": 150,
        },
    ]
    return ctx


@pytest.fixture
def kb_structure_context(accessible_store_context):
    """Context with knowledge base structure."""
    ctx = dict(accessible_store_context)
    ctx["knowledge_base_structure"] = [
        {
            "store_type": "chroma",
            "collection_count": 3,
            "total_documents": 150,
            "collections": [
                {
                    "name": "docs",
                    "doc_count": 80,
                    "dimensions": 1536,
                    "metadata_fields": ["source", "author"],
                },
                {
                    "name": "hr_policies",
                    "doc_count": 50,
                    "dimensions": 1536,
                    "metadata_fields": ["source"],
                },
                {"name": "faq", "doc_count": 20, "dimensions": 1536, "metadata_fields": []},
            ],
        },
    ]
    return ctx


@pytest.fixture
def ingestion_context(rag_context):
    """Context with writable ingestion endpoints."""
    ctx = dict(rag_context)
    ctx["ingestion_endpoints"] = [
        {
            "path": "/api/documents",
            "format": "json",
            "status": 201,
            "writable": True,
            "auth_required": False,
            "canary_id": "chainsmith-canary-test",
        },
    ]
    return ctx


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
    url: str = "http://rag.example.com:8080",
) -> HttpResponse:
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        error=error,
        elapsed_ms=50.0,
    )


def _stamp(response: HttpResponse, url: str | None) -> HttpResponse:
    """Report the response as coming from the URL it was requested from.

    A probe records `HttpResponse.url` as the exchange's `request_url`, and a
    grader attributes each exchange back to its path from there. A mock that
    stamps one fixed url onto every response makes every exchange look like the
    same request (§0.13).
    """
    return replace(response, url=url) if url else response


def _mock_client(get_fn=None, post_fn=None, delete_fn=None, options_fn=None):
    """Create mock async HTTP client.

    `__aexit__` returns False: a bare `AsyncMock()` returns a truthy MagicMock,
    which suppresses every exception raised inside the `async with` and makes a
    probe that blew up mid-flight look like one that completed (§0.14).
    """
    client = AsyncMock()

    def _dispatch(fn, fallback_status):
        async def _call(url=None, **kw):
            resp = await fn(url, **kw) if fn else make_response(status_code=fallback_status)
            return _stamp(resp, url)

        return AsyncMock(side_effect=_call)

    client.get = _dispatch(get_fn, 404)
    client.post = _dispatch(post_fn, 404)
    client.delete = _dispatch(delete_fn, 204)
    client.options = _dispatch(options_fn, 404)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestCorpusPoisoning:
    def test_metadata(self):
        check = RAGCorpusPoisoningCheck()
        assert check.name == "rag_corpus_poisoning"
        assert check.intrusive is True
        assert "ingestion_endpoints" in check.produces

    @pytest.mark.asyncio
    async def test_detects_writable_endpoint(self, sample_service, rag_context):
        check = RAGCorpusPoisoningCheck()

        async def mock_post(url, **kw):
            if "/documents" in url or "/ingest" in url:
                return make_response(
                    status_code=201,
                    body=json.dumps({"id": "doc-abc123", "status": "indexed"}),
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_corpus_poisoning.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert "ingestion_endpoints" in result.outputs
        writable = [ep for ep in result.outputs["ingestion_endpoints"] if ep.get("writable")]
        assert len(writable) >= 1
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "unauthenticated" in critical[0].title.lower()
        assert "ingestion" in critical[0].title.lower()
        assert "Path:" in critical[0].evidence
        assert "Auth required: False" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_auth_required_on_ingestion(self, sample_service, rag_context):
        """Ingestion endpoint exists but requires auth -- medium severity, no critical."""
        check = RAGCorpusPoisoningCheck()

        async def mock_post(url, **kw):
            if "/documents" in url or "/ingest" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_corpus_poisoning.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        # Endpoint found but auth required -- produces medium observation, no critical
        assert all(f.severity != "critical" for f in result.observations)
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert "writes rejected" in medium[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_ingestion_endpoints_found(self, sample_service, rag_context):
        """All probed paths return 404 -- info observation, no ingestion_endpoints output."""
        check = RAGCorpusPoisoningCheck()
        client = _mock_client()

        with patch(
            "app.checks.rag.rag_corpus_poisoning.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert "ingestion_endpoints" not in result.outputs
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "no writable ingestion" in info[0].title.lower()
        assert "Probed" in info[0].evidence
