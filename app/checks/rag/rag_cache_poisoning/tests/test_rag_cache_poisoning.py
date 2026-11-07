"""Tests for rag_cache_poisoning.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_cache_poisoning import RAGCachePoisoningCheck
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


class TestCachePoisoning:
    def test_metadata(self):
        check = RAGCachePoisoningCheck()
        assert check.name == "rag_cache_poisoning"
        assert "rag_cache_behavior" in check.produces

    @pytest.mark.asyncio
    async def test_detects_caching_with_headers_and_identical_bodies(
        self, sample_service, rag_context
    ):
        """Cache detected via cache-control header and identical response bodies."""
        check = RAGCachePoisoningCheck()

        # Realistic RAG response with cache headers embedded naturally
        rag_body = json.dumps(
            {
                "answer": "The knowledge base covers HR policies, IT procedures, and FAQs.",
                "sources": [
                    {"title": "HR Onboarding Guide", "score": 0.92},
                    {"title": "IT Security Policy", "score": 0.87},
                ],
            }
        )

        async def mock_post(url, **kw):
            return make_response(
                body=rag_body,
                headers={"cache-control": "max-age=300", "content-type": "application/json"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_cache_poisoning.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert result.outputs["rag_cache_behavior"]["identical_responses"]
        assert "cache-control" in result.outputs["rag_cache_behavior"]["cache_headers"]
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert "identical responses" in medium[0].title.lower()
        assert "Identical responses: True" in medium[0].evidence

    @pytest.mark.asyncio
    async def test_no_caching_unique_responses(self, sample_service, rag_context):
        """No caching when each response body is different and no cache headers present."""
        check = RAGCachePoisoningCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = json.dumps(
                {
                    "answer": f"Response variation {call_count} with slightly different wording.",
                    "sources": [{"title": "Doc A", "score": 0.85 + call_count * 0.01}],
                }
            )
            return make_response(body=body, headers={"content-type": "application/json"})

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_cache_poisoning.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert not result.outputs["rag_cache_behavior"]["caching_detected"]
        assert not result.outputs["rag_cache_behavior"]["identical_responses"]
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "no rag-level caching detected" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_cache_poisoning_with_vulnerable_endpoints(self, sample_service, rag_context):
        """When caching + prior injection detected, severity escalates to high."""
        check = RAGCachePoisoningCheck()
        rag_context["vulnerable_rag_endpoints"] = [
            {"endpoint": "/query", "vulnerability": "indirect_injection"}
        ]

        # Same realistic body returned twice triggers identical_responses
        rag_body = json.dumps(
            {
                "answer": "According to company policy, all employees must complete training.",
                "sources": [{"title": "Training Policy v2.1", "score": 0.94}],
            }
        )

        async def mock_post(url, **kw):
            return make_response(
                body=rag_body,
                headers={"content-type": "application/json"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_cache_poisoning.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert result.outputs["rag_cache_behavior"]["identical_responses"]
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 1
        assert "cache poisoning" in high[0].title.lower()
        assert "injected response" in high[0].title.lower()
        assert "Identical responses: True" in high[0].evidence

    @pytest.mark.asyncio
    async def test_cache_headers_but_different_bodies(self, sample_service, rag_context):
        """Cache headers present but responses differ -- low severity."""
        check = RAGCachePoisoningCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = json.dumps({"answer": f"Unique response text number {call_count}."})
            return make_response(
                body=body,
                headers={"age": "42", "content-type": "application/json"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_cache_poisoning.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert not result.outputs["rag_cache_behavior"]["identical_responses"]
        low = [f for f in result.observations if f.severity == "low"]
        assert len(low) == 1
        assert "responses vary" in low[0].title.lower()
