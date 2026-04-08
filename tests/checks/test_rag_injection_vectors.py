"""Tests for RAG chunk boundary bypass, multimodal injection, and adversarial embedding checks."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.adversarial_embedding import RAGAdversarialEmbeddingCheck
from app.checks.rag.chunk_boundary import CANARY, RAGChunkBoundaryCheck
from app.checks.rag.multimodal_injection import RAGMultimodalInjectionCheck
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
) -> HttpResponse:
    return HttpResponse(
        url="http://rag.example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        error=error,
        elapsed_ms=50.0,
    )


def _mock_client(get_fn=None, post_fn=None, delete_fn=None, options_fn=None):
    """Create mock async HTTP client."""
    client = AsyncMock()
    client.get = get_fn or AsyncMock(return_value=make_response(status_code=404))
    client.post = post_fn or AsyncMock(return_value=make_response(status_code=404))
    client.delete = delete_fn or AsyncMock(return_value=make_response(status_code=204))
    client.options = options_fn or AsyncMock(return_value=make_response(status_code=404))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# Chunk Boundary
# ---------------------------------------------------------------------------


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

        with patch("app.checks.rag.chunk_boundary.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

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

        with patch("app.checks.rag.chunk_boundary.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

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

        with patch("app.checks.rag.chunk_boundary.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) == 0


# ---------------------------------------------------------------------------
# Multimodal Injection
# ---------------------------------------------------------------------------


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
            "app.checks.rag.multimodal_injection.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

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
            "app.checks.rag.multimodal_injection.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        upload_obs = [o for o in result.observations if "accepts file uploads" in o.title.lower()]
        assert len(upload_obs) == 0

    @pytest.mark.asyncio
    async def test_no_upload_endpoint_produces_info(self, sample_service, rag_context):
        """When no upload endpoint is found, an info observation is produced."""
        check = RAGMultimodalInjectionCheck()
        client = _mock_client()

        with patch(
            "app.checks.rag.multimodal_injection.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

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
            "app.checks.rag.multimodal_injection.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) >= 1
        assert "multimodal injection" in high[0].title.lower()


# ---------------------------------------------------------------------------
# Adversarial Embedding
# ---------------------------------------------------------------------------


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
            "app.checks.rag.adversarial_embedding.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

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
            "app.checks.rag.adversarial_embedding.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

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
            "app.checks.rag.adversarial_embedding.AsyncHttpClient",
            return_value=client,
        ):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        high = [o for o in result.observations if o.severity in ("high", "medium")]
        assert len(high) == 0


# ---------------------------------------------------------------------------
# Registration (behavioral: resolve_checks actually filters correctly)
# ---------------------------------------------------------------------------


class TestCheckResolverRegistration:
    def test_all_rag_checks_registered(self):
        """Every expected RAG check name appears in the resolver output."""
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        check_names = {c.name for c in checks}

        expected_rag_checks = [
            "rag_discovery",
            "rag_vector_store_access",
            "rag_auth_bypass",
            "rag_collection_enumeration",
            "rag_embedding_fingerprint",
            "rag_indirect_injection",
            "rag_document_exfiltration",
            "rag_retrieval_manipulation",
            "rag_source_attribution",
            "rag_cache_poisoning",
            "rag_corpus_poisoning",
            "rag_metadata_injection",
            "rag_chunk_boundary",
            "rag_multimodal_injection",
            "rag_fusion_reranker",
            "rag_cross_collection",
            "rag_adversarial_embedding",
        ]

        for name in expected_rag_checks:
            assert name in check_names, f"RAG check '{name}' not registered"

    def test_rag_suite_filter_returns_only_rag_checks(self):
        """resolve_checks(suites=['rag']) returns checks whose names all
        start with 'rag_' and includes the three checks under test."""
        from app.check_resolver import resolve_checks

        checks = resolve_checks(suites=["rag"])
        assert len(checks) > 0
        assert all(c.name.startswith("rag_") for c in checks)
        names = {c.name for c in checks}
        assert "rag_chunk_boundary" in names
        assert "rag_multimodal_injection" in names
        assert "rag_adversarial_embedding" in names
