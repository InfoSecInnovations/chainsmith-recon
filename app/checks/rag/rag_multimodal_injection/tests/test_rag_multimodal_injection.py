"""Tests for rag_multimodal_injection.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_multimodal_injection import RAGMultimodalInjectionCheck
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


class TestMultimodalInjection:
    @pytest.mark.asyncio
    async def test_upload_accepted_produces_medium_observation(self, sample_service, rag_context):
        """When an upload endpoint accepts a file (201), a medium observation
        with 'accepts file uploads' in the title is produced."""
        check = RAGMultimodalInjectionCheck()

        async def mock_options(url, **kw):
            if "/upload" in url:
                return make_response(status_code=200)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/upload" in url:
                # Realistic upload response with document id and processing status
                return make_response(
                    status_code=201,
                    body=json.dumps(
                        {
                            "id": "doc-8f3a2b",
                            "status": "processing",
                            "filename": "test_document.pdf",
                            "size_bytes": 1024,
                        }
                    ),
                )
            # Query endpoint returns normal text (no injection indicator)
            return make_response(
                body=json.dumps(
                    {
                        "answer": "The uploaded document discusses quarterly results.",
                        "sources": [{"id": "doc-8f3a2b", "score": 0.85}],
                    }
                )
            )

        client = _mock_client(options_fn=mock_options, post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_multimodal_injection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        upload_obs = [o for o in result.observations if "accepts file uploads" in o.title.lower()]
        assert len(upload_obs) >= 1
        assert upload_obs[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_upload_rejected_403_no_upload_observation(self, sample_service, rag_context):
        """If the upload endpoint returns 403 (forbidden), no upload-accepted
        observation should be produced."""
        check = RAGMultimodalInjectionCheck()

        # All upload discovery paths return 404 or 403
        async def mock_options(url, **kw):
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/upload" in url or "/ingest" in url:
                return make_response(status_code=403, body='{"error":"forbidden"}')
            return make_response(status_code=404)

        client = _mock_client(options_fn=mock_options, post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_multimodal_injection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        upload_obs = [o for o in result.observations if "accepts file uploads" in o.title.lower()]
        assert len(upload_obs) == 0

    @pytest.mark.asyncio
    async def test_no_upload_endpoint_produces_info(self, sample_service, rag_context):
        """When no upload endpoint is found, an info observation is produced."""
        check = RAGMultimodalInjectionCheck()
        client = _mock_client()

        with patch(
            "app.checks.rag.rag_multimodal_injection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        info = [o for o in result.observations if o.severity == "info"]
        assert len(info) == 1
        assert "not accept" in info[0].title.lower() or "no" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_injection_followed_produces_high_observation(self, sample_service, rag_context):
        """When the injection indicator appears in query response, a high-severity
        observation with 'multimodal injection' in the title is created."""
        check = RAGMultimodalInjectionCheck()

        async def mock_options(url, **kw):
            if "/upload" in url:
                return make_response(status_code=200)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/upload" in url:
                return make_response(
                    status_code=201,
                    body=json.dumps({"id": "doc-injected", "status": "ready"}),
                )
            # Query response that contains one of the injection indicators
            return make_response(
                body=json.dumps(
                    {
                        "answer": (
                            "According to the document, MULTIMODAL_PDF_INJECTED is "
                            "the key finding from the analysis."
                        ),
                        "sources": [{"id": "doc-injected", "score": 0.95}],
                    }
                )
            )

        client = _mock_client(options_fn=mock_options, post_fn=mock_post)

        with patch(
            "app.checks.rag.rag_multimodal_injection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, rag_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) >= 1
        assert "multimodal injection" in high[0].title.lower()
