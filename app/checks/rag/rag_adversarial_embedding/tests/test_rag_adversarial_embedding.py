"""Tests for rag_adversarial_embedding.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_adversarial_embedding import RAGAdversarialEmbeddingCheck
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


class TestAdversarialEmbedding:
    @pytest.mark.asyncio
    async def test_retrieval_steered_produces_observation(self, sample_service, rag_context):
        """When adversarial queries retrieve different docs than the baseline,
        a medium or high observation with 'adversarial embedding' in the title is produced."""
        check = RAGAdversarialEmbeddingCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            query = body.get("query", "")
            if "weather" in query.lower() or "public company" in query.lower():
                # Baseline query returns public docs
                return make_response(
                    body=json.dumps(
                        {
                            "results": [
                                {"id": "public-weather-1", "title": "Weather FAQ"},
                                {"id": "public-news-2", "title": "Daily News"},
                            ],
                        }
                    )
                )
            elif (
                "password" in query.lower()
                or "secret" in query.lower()
                or "restricted" in query.lower()
            ):
                # Adversarial queries pull back sensitive docs
                return make_response(
                    body=json.dumps(
                        {
                            "results": [
                                {"id": "private-creds-1", "title": "Credentials Store"},
                                {"id": "internal-config-2", "title": "Internal Config"},
                            ],
                        }
                    )
                )
            elif "NOT public" in query or "{{system}}" in query:
                return make_response(
                    body=json.dumps(
                        {
                            "results": [
                                {"id": "classified-doc-1", "title": "Classified"},
                            ],
                        }
                    )
                )
            else:
                return make_response(
                    body=json.dumps(
                        {
                            "results": [
                                {"id": "general-doc", "title": "General Info"},
                            ],
                        }
                    )
                )

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_adversarial_embedding.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        steered = [o for o in result.observations if "adversarial embedding" in o.title.lower()]
        assert len(steered) >= 1
        assert steered[0].severity in ("medium", "high")
        assert "technique" in steered[0].evidence.lower()

    @pytest.mark.asyncio
    async def test_same_results_means_not_effective(self, sample_service, rag_context):
        """When adversarial queries return the same docs as baseline, only an
        info observation is produced."""
        check = RAGAdversarialEmbeddingCheck()

        async def mock_post(url, **kw):
            # Always return identical results regardless of query
            return make_response(
                body=json.dumps(
                    {
                        "results": [
                            {"id": "doc-1", "title": "Common Doc"},
                            {"id": "doc-2", "title": "Another Doc"},
                        ],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_adversarial_embedding.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        steered = [o for o in result.observations if "adversarial embedding" in o.title.lower()]
        assert len(steered) == 0
        info = [o for o in result.observations if o.severity == "info"]
        assert len(info) == 1
        assert "not" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_query_failure_does_not_crash(self, sample_service, rag_context):
        """If every query returns an error status, the check still succeeds
        without crashing and produces an info observation."""
        check = RAGAdversarialEmbeddingCheck()

        async def mock_post(url, **kw):
            return make_response(status_code=500, body="Internal Server Error")

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_adversarial_embedding.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        high = [o for o in result.observations if o.severity in ("high", "medium")]
        assert len(high) == 0
