"""Tests for rag_vector_store_access.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_vector_store_access import RAGVectorStoreAccessCheck
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
    """Context with accessible vector stores including a sensitive collection name."""
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


CHROMA_COLLECTIONS_RESPONSE = json.dumps(
    [
        {"name": "docs", "id": "abc123", "metadata": None},
        {"name": "faq", "id": "def456", "metadata": None},
    ]
)
CHROMA_COUNT_RESPONSE = "42"
CHROMA_DOCUMENTS_RESPONSE = json.dumps(
    {
        "ids": ["doc-001", "doc-002", "doc-003"],
        "embeddings": None,
        "documents": [
            "Quarterly revenue increased 12% year-over-year driven by cloud services.",
            "Employee onboarding procedure requires badge activation within 48 hours.",
            "The default API rate limit is 1000 requests per minute per tenant.",
        ],
        "metadatas": [
            {"source": "finance/q3_report.pdf", "author": "cfo@corp.example.com", "page": 4},
            {"source": "hr/onboarding.docx", "author": "admin", "page": 1},
            {"source": "engineering/api_docs.md", "author": "platform-team", "page": 12},
        ],
    }
)
CHROMA_QUERY_RESPONSE = json.dumps(
    {
        "ids": [["doc-001"]],
        "distances": [[0.087]],
        "documents": [["Quarterly revenue increased 12% year-over-year."]],
        "metadatas": [[{"source": "finance/q3_report.pdf"}]],
    }
)


class TestVectorStoreAccess:
    def test_metadata(self):
        check = RAGVectorStoreAccessCheck()
        assert check.name == "rag_vector_store_access"
        assert "accessible_stores" in check.produces

    @pytest.mark.asyncio
    async def test_detects_accessible_chroma(self, sample_service, rag_context):
        """Full Chroma response flow: collections, count, documents, query."""
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(body=CHROMA_COLLECTIONS_RESPONSE)
            if "/count" in url:
                return make_response(body=CHROMA_COUNT_RESPONSE)
            if "/get" in url:
                return make_response(body=CHROMA_DOCUMENTS_RESPONSE)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/query" in url and "collections" in url:
                return make_response(body=CHROMA_QUERY_RESPONSE)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_vector_store_access.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert "accessible_stores" in result.outputs

        stores = result.outputs["accessible_stores"]
        assert len(stores) >= 1
        store = stores[0]
        assert store["store_type"] == "chroma"
        assert store["collections"] == ["docs", "faq"]
        op_names = {op["operation"] for op in store["accessible_ops"]}
        assert "list_collections" in op_names
        assert "dump_documents" in op_names

        # Document dump produces a critical observation
        assert len(result.observations) >= 1
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert critical[0].title == "Vector store directly accessible: chroma"
        assert "chroma" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_all_401_records_auth_required_ops(self, sample_service, rag_context):
        """When every probe returns 401, accessible_ops should contain auth_required entries."""
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.rag.rag_vector_store_access.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        # The collections listing itself returned 401, so accessible_stores
        # should reflect auth-required ops (the check records 401 as an op).
        stores = result.outputs.get("accessible_stores", [])
        if stores:
            auth_ops = [o for o in stores[0]["accessible_ops"] if o.get("auth_required")]
            assert len(auth_ops) >= 1
            assert auth_ops[0]["status"] == 401

    @pytest.mark.asyncio
    async def test_collections_endpoint_returns_401(self, sample_service, rag_context):
        """Negative: collections endpoint returns 401 -- no critical observations."""
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            # Collections listing is auth-gated; everything else 404
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.rag.rag_vector_store_access.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0, "No critical finding expected when collections listing is 401"

    @pytest.mark.asyncio
    async def test_non_vector_store_json_at_collections_path(self, sample_service, rag_context):
        """Negative: collections path returns JSON that is NOT a Chroma collections list."""
        check = RAGVectorStoreAccessCheck()

        # Return a generic REST API response (not a list of dicts with 'name')
        non_vector_body = json.dumps(
            {
                "status": "ok",
                "version": "2.1.0",
                "endpoints": ["/health", "/metrics"],
            }
        )

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(body=non_vector_body)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.rag.rag_vector_store_access.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        # A non-list response should not produce collections or critical findings
        stores = result.outputs.get("accessible_stores", [])
        if stores:
            assert stores[0]["collections"] == [], (
                "Non-vector-store JSON should not yield collection names"
            )
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0
