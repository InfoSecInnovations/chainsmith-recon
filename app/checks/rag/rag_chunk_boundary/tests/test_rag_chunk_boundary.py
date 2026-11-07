"""Tests for rag_chunk_boundary.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_chunk_boundary import RAGChunkBoundaryCheck
from app.checks.rag.rag_chunk_boundary.check import CANARY
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


class TestChunkBoundary:
    @pytest.mark.asyncio
    async def test_bypass_confirmed_produces_high_observation(
        self, sample_service, ingestion_context
    ):
        """When the canary appears in a realistic response body, a high-severity
        observation with the correct title pattern is emitted."""
        check = RAGChunkBoundaryCheck()
        ingestion_context["rag_endpoints"][0]["endpoint_type"] = "rag_query"

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            if "/api/documents" in url:
                return make_response(
                    status_code=201,
                    body='{"status":"ok","ids":["chainsmith-chunk-256tok"]}',
                )
            if body.get("query") and "boundary" in body["query"].lower():
                # Realistic RAG response with the canary embedded in LLM output
                return make_response(
                    body=json.dumps(
                        {
                            "answer": (
                                "Based on the retrieved documents, the system says: "
                                f"{CANARY}. This appears in the context window."
                            ),
                            "sources": [{"id": "chainsmith-chunk-256tok", "score": 0.92}],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_chunk_boundary.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, ingestion_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) >= 1
        assert "chunk boundary bypass" in high[0].title.lower()
        assert "reassembled" in high[0].title.lower()
        assert CANARY in high[0].evidence

    @pytest.mark.asyncio
    async def test_no_canary_means_not_effective(self, sample_service, ingestion_context):
        """When the canary does NOT appear in query responses, an info observation
        is produced and no high/medium observations exist."""
        check = RAGChunkBoundaryCheck()
        ingestion_context["rag_endpoints"][0]["endpoint_type"] = "rag_query"

        async def mock_post(url, **kw):
            if "/api/documents" in url:
                return make_response(
                    status_code=201,
                    body='{"status":"ok","ids":["chainsmith-chunk-256tok"]}',
                )
            # Response that contains the topic but NOT the canary
            return make_response(
                body=json.dumps(
                    {
                        "answer": "Here is some general information about the topic.",
                        "sources": [{"id": "unrelated-doc", "score": 0.4}],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_chunk_boundary.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, ingestion_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) == 0
        info = [o for o in result.observations if o.severity == "info"]
        assert len(info) >= 1
        assert "not effective" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_ingestion_failure_skips_quietly(self, sample_service, ingestion_context):
        """If the ingestion endpoint rejects the document (e.g. 403), no bypass
        observation is created."""
        check = RAGChunkBoundaryCheck()
        ingestion_context["rag_endpoints"][0]["endpoint_type"] = "rag_query"

        async def mock_post(url, **kw):
            if "/api/documents" in url:
                return make_response(status_code=403, body='{"error":"forbidden"}')
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.rag_chunk_boundary.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, ingestion_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) == 0
