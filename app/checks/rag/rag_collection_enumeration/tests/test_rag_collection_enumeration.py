"""Tests for rag_collection_enumeration.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_collection_enumeration import RAGCollectionEnumerationCheck
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


class TestCollectionEnumeration:
    def test_metadata(self):
        check = RAGCollectionEnumerationCheck()
        assert check.name == "rag_collection_enumeration"
        assert "knowledge_base_structure" in check.produces

    @pytest.mark.asyncio
    async def test_enumerates_collections(self, sample_service, accessible_store_context):
        """Enumeration with realistic Chroma count and metadata responses."""
        check = RAGCollectionEnumerationCheck()

        async def mock_get(url, **kw):
            if "/count" in url:
                return make_response(body="42")
            if "/get" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "ids": ["doc-001"],
                            "documents": [
                                "Employee onboarding procedure requires badge activation."
                            ],
                            "metadatas": [{"source": "hr/onboarding.docx", "author": "admin"}],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.rag.rag_collection_enumeration.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, accessible_store_context)

        assert result.success
        assert "knowledge_base_structure" in result.outputs

        kb = result.outputs["knowledge_base_structure"]
        assert len(kb) >= 1
        assert kb[0]["store_type"] == "chroma"
        assert kb[0]["collection_count"] == 3  # docs, hr_policies, faq

        assert len(result.observations) >= 1
        obs = result.observations[0]
        assert obs.title == "Knowledge base structure exposed: chroma"
        assert obs.severity in ("medium", "high")
        # hr_policies is sensitive, so description should mention it
        assert "hr_policies" in obs.description

    @pytest.mark.asyncio
    async def test_flags_sensitive_names(self, sample_service, accessible_store_context):
        """hr_policies must be flagged as sensitive in the observation."""
        check = RAGCollectionEnumerationCheck()

        async def mock_get(url, **kw):
            if "/count" in url:
                return make_response(body="10")
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.rag.rag_collection_enumeration.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, accessible_store_context)

        assert result.success
        assert len(result.observations) >= 1

        # The observation description or evidence must reference hr_policies as sensitive
        obs = result.observations[0]
        sensitive_hits = [
            o
            for o in result.observations
            if "sensitive" in o.description.lower() or "hr_policies" in o.evidence.lower()
        ]
        assert len(sensitive_hits) >= 1, (
            f"Expected sensitive flag for hr_policies, got description={obs.description!r}"
        )
