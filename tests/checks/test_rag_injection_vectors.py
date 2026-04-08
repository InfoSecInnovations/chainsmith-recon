"""Tests for RAG chunk boundary bypass, multimodal injection, adversarial embedding, and check registration."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.adversarial_embedding import RAGAdversarialEmbeddingCheck
from app.checks.rag.auth_bypass import RAGAuthBypassCheck
from app.checks.rag.cache_poisoning import RAGCachePoisoningCheck
from app.checks.rag.chunk_boundary import RAGChunkBoundaryCheck
from app.checks.rag.collection_enumeration import RAGCollectionEnumerationCheck
from app.checks.rag.corpus_poisoning import RAGCorpusPoisoningCheck
from app.checks.rag.cross_collection import RAGCrossCollectionCheck
from app.checks.rag.document_exfiltration import RAGDocumentExfiltrationCheck
from app.checks.rag.embedding_fingerprint import RAGEmbeddingFingerprintCheck
from app.checks.rag.fusion_reranker import RAGFusionRerankerCheck
from app.checks.rag.metadata_injection import RAGMetadataInjectionCheck
from app.checks.rag.multimodal_injection import RAGMultimodalInjectionCheck
from app.checks.rag.retrieval_manipulation import RAGRetrievalManipulationCheck
from app.checks.rag.source_attribution import RAGSourceAttributionCheck
from app.checks.rag.vector_store_access import RAGVectorStoreAccessCheck
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


class TestChunkBoundary:
    def test_metadata(self):
        check = RAGChunkBoundaryCheck()
        assert check.name == "rag_chunk_boundary"
        assert check.intrusive is True
        assert "chunk_boundary_results" in check.produces

    @pytest.mark.asyncio
    async def test_bypass_confirmed(self, sample_service, ingestion_context):
        check = RAGChunkBoundaryCheck()
        ingestion_context["rag_endpoints"][0]["endpoint_type"] = "rag_query"

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            if "/api/documents" in url:
                return make_response(status_code=201)
            if body.get("query") and "boundary" in body["query"]:
                return make_response(body="CHUNK_BOUNDARY_BYPASSED detected in context")
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.chunk_boundary.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) >= 1

    @pytest.mark.asyncio
    async def test_not_effective(self, sample_service, ingestion_context):
        check = RAGChunkBoundaryCheck()
        ingestion_context["rag_endpoints"][0]["endpoint_type"] = "rag_query"

        async def mock_post(url, **kw):
            if "/api/documents" in url:
                return make_response(status_code=201)
            return make_response(body="Normal response without any canary")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.chunk_boundary.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1


class TestMultimodalInjection:
    def test_metadata(self):
        check = RAGMultimodalInjectionCheck()
        assert check.name == "rag_multimodal_injection"
        assert check.intrusive is True
        assert "multimodal_injection_results" in check.produces

    @pytest.mark.asyncio
    async def test_upload_accepted(self, sample_service, rag_context):
        check = RAGMultimodalInjectionCheck()

        async def mock_options(url, **kw):
            if "/upload" in url:
                return make_response(status_code=200)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/upload" in url:
                return make_response(status_code=201, body='{"id": "test"}')
            return make_response(body="Normal response")

        client = _mock_client(options_fn=mock_options, post_fn=mock_post)

        with patch("app.checks.rag.multimodal_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # Should detect file upload capability
        upload_observations = [
            f
            for f in result.observations
            if "upload" in f.title.lower() or "multimodal" in f.title.lower()
        ]
        assert len(upload_observations) >= 1

    @pytest.mark.asyncio
    async def test_no_upload(self, sample_service, rag_context):
        check = RAGMultimodalInjectionCheck()
        client = _mock_client()

        with patch("app.checks.rag.multimodal_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1
        assert "not accept" in info[0].title.lower() or "no" in info[0].title.lower()


class TestAdversarialEmbedding:
    def test_metadata(self):
        check = RAGAdversarialEmbeddingCheck()
        assert check.name == "rag_adversarial_embedding"
        assert check.intrusive is True
        assert "adversarial_embedding_results" in check.produces

    @pytest.mark.asyncio
    async def test_retrieval_steered(self, sample_service, rag_context):
        check = RAGAdversarialEmbeddingCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = kw.get("json", {})
            query = body.get("query", "")
            if "weather" in query.lower():
                return make_response(
                    body=json.dumps(
                        {
                            "results": [{"id": "public-1"}, {"id": "public-2"}],
                        }
                    )
                )
            elif "password" in query.lower() or "secret" in query.lower():
                return make_response(
                    body=json.dumps(
                        {
                            "results": [{"id": "private-1"}, {"id": "sensitive-2"}],
                        }
                    )
                )
            else:
                return make_response(
                    body=json.dumps(
                        {
                            "results": [{"id": f"doc-{call_count}"}],
                        }
                    )
                )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.adversarial_embedding.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # Should detect some form of retrieval steering
        assert len(result.observations) >= 1

    @pytest.mark.asyncio
    async def test_not_effective(self, sample_service, rag_context):
        check = RAGAdversarialEmbeddingCheck()

        async def mock_post(url, **kw):
            # Same results regardless of query
            return make_response(
                body=json.dumps(
                    {
                        "results": [{"id": "doc-1"}, {"id": "doc-2"}],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.adversarial_embedding.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1


class TestCheckResolverRegistration:
    def test_all_rag_checks_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        check_names = [c.name for c in checks]

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
            assert name in check_names, f"RAG check '{name}' not registered in check_resolver"

    def test_rag_check_count(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        rag_checks = [c for c in checks if c.name.startswith("rag_")]
        assert len(rag_checks) == 17, f"Expected 17 RAG checks, got {len(rag_checks)}"

    def test_rag_suite_filtering(self):
        from app.check_resolver import resolve_checks

        checks = resolve_checks(suites=["rag"])
        assert len(checks) == 17
        assert all(c.name.startswith("rag_") for c in checks)


class TestCheckDependencies:
    def test_phase2_conditions(self):
        assert RAGVectorStoreAccessCheck().conditions[0].output_name == "vector_stores"
        assert RAGAuthBypassCheck().conditions[0].output_name == "vector_stores"
        assert RAGCollectionEnumerationCheck().conditions[0].output_name == "accessible_stores"

    def test_phase3_conditions(self):
        assert RAGDocumentExfiltrationCheck().conditions[0].output_name == "rag_endpoints"
        assert RAGRetrievalManipulationCheck().conditions[0].output_name == "rag_endpoints"
        assert RAGSourceAttributionCheck().conditions[0].output_name == "rag_endpoints"
        assert RAGCachePoisoningCheck().conditions[0].output_name == "rag_endpoints"

    def test_phase4_conditions(self):
        assert RAGCorpusPoisoningCheck().conditions[0].output_name == "rag_endpoints"
        assert RAGMetadataInjectionCheck().conditions[0].output_name == "rag_endpoints"
        chunk = RAGChunkBoundaryCheck()
        cond_names = [c.output_name for c in chunk.conditions]
        assert "rag_endpoints" in cond_names
        assert "ingestion_endpoints" in cond_names

    def test_phase5_conditions(self):
        assert RAGFusionRerankerCheck().conditions[0].output_name == "rag_endpoints"
        assert RAGCrossCollectionCheck().conditions[0].output_name == "knowledge_base_structure"
        assert RAGAdversarialEmbeddingCheck().conditions[0].output_name == "rag_endpoints"

    def test_intrusive_flags(self):
        """Intrusive checks must be flagged."""
        intrusive_checks = [
            RAGAuthBypassCheck,
            RAGDocumentExfiltrationCheck,
            RAGRetrievalManipulationCheck,
            RAGCorpusPoisoningCheck,
            RAGMetadataInjectionCheck,
            RAGChunkBoundaryCheck,
            RAGMultimodalInjectionCheck,
            RAGAdversarialEmbeddingCheck,
        ]
        for cls in intrusive_checks:
            assert cls().intrusive is True, f"{cls.__name__} should be intrusive"

        non_intrusive = [
            RAGVectorStoreAccessCheck,
            RAGCollectionEnumerationCheck,
            RAGEmbeddingFingerprintCheck,
            RAGSourceAttributionCheck,
            RAGCachePoisoningCheck,
            RAGFusionRerankerCheck,
            RAGCrossCollectionCheck,
        ]
        for cls in non_intrusive:
            assert not cls().intrusive, f"{cls.__name__} should not be intrusive"
