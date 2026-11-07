"""Tests for rag_auth_bypass.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_auth_bypass import RAGAuthBypassCheck
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


class TestAuthBypass:
    def test_metadata(self):
        check = RAGAuthBypassCheck()
        assert check.name == "rag_auth_bypass"
        assert check.intrusive is True
        assert "auth_bypass_results" in check.produces

    @pytest.mark.asyncio
    async def test_detects_no_auth(self, sample_service, rag_context):
        check = RAGAuthBypassCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url:
                return make_response(body=json.dumps([{"name": "test"}]))
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_auth_bypass.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "no authentication" in critical[0].title.lower()
        assert "chroma" in critical[0].title.lower()
        assert critical[0].evidence is not None

    @pytest.mark.asyncio
    async def test_detects_default_key_bypass(self, sample_service, rag_context):
        check = RAGAuthBypassCheck()
        rag_context["vector_stores"] = ["qdrant"]
        rag_context["rag_endpoints"][1]["store_type"] = "qdrant"

        async def mock_get(url, **kw):
            headers = kw.get("headers", {})
            # No auth returns 401
            if not headers or not headers.get("api-key"):
                return make_response(status_code=401)
            # Default key "qdrant" works
            if headers.get("api-key") == "qdrant":
                return make_response(body=json.dumps({"result": {"collections": []}}))
            return make_response(status_code=401)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_auth_bypass.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 1
        assert "default" in high[0].title.lower()
        assert "qdrant" in high[0].title.lower()
        assert "default_key" in high[0].evidence

    @pytest.mark.asyncio
    async def test_auth_enforced(self, sample_service, rag_context):
        check = RAGAuthBypassCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_auth_bypass.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "enforced" in info[0].title.lower()
        assert "chroma" in info[0].title.lower()
