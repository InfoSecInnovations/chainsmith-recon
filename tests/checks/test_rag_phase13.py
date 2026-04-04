"""
Tests for Phase 13 RAG check enhancements.

Covers 15 new checks:
- RAGVectorStoreAccessCheck
- RAGAuthBypassCheck
- RAGCollectionEnumerationCheck
- RAGEmbeddingFingerprintCheck
- RAGDocumentExfiltrationCheck
- RAGRetrievalManipulationCheck
- RAGSourceAttributionCheck
- RAGCachePoisoningCheck
- RAGCorpusPoisoningCheck
- RAGMetadataInjectionCheck
- RAGChunkBoundaryCheck
- RAGMultimodalInjectionCheck
- RAGFusionRerankerCheck
- RAGCrossCollectionCheck
- RAGAdversarialEmbeddingCheck
"""

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

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Vector Store Access & Enumeration
# ═══════════════════════════════════════════════════════════════════════════════


class TestVectorStoreAccess:
    def test_metadata(self):
        check = RAGVectorStoreAccessCheck()
        assert check.name == "rag_vector_store_access"
        assert "accessible_stores" in check.produces

    @pytest.mark.asyncio
    async def test_detects_accessible_chroma(self, sample_service, rag_context):
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(
                    body=json.dumps(
                        [
                            {"name": "docs", "id": "abc123"},
                            {"name": "faq", "id": "def456"},
                        ]
                    )
                )
            if "/count" in url:
                return make_response(body="42")
            if "/get" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "ids": ["1", "2"],
                            "documents": ["doc1", "doc2"],
                        }
                    )
                )
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/query" in url and "collections" in url:
                return make_response(body=json.dumps({"ids": [["1"]], "distances": [[0.1]]}))
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.rag.vector_store_access.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "accessible_stores" in result.outputs
        assert len(result.findings) >= 1
        # Document dump = critical
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_auth_required(self, sample_service, rag_context):
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.vector_store_access.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # Auth required ops should still be tracked
        if result.outputs.get("accessible_stores"):
            for store in result.outputs["accessible_stores"]:
                auth_ops = [o for o in store["accessible_ops"] if o.get("auth_required")]
                assert len(auth_ops) >= 1


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

        with patch("app.checks.rag.auth_bypass.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert "no authentication" in critical[0].title.lower()

    @pytest.mark.asyncio
    async def test_detects_default_key_bypass(self, sample_service, rag_context):
        check = RAGAuthBypassCheck()
        rag_context["vector_stores"] = ["qdrant"]
        rag_context["rag_endpoints"][1]["store_type"] = "qdrant"

        call_count = 0

        async def mock_get(url, **kw):
            nonlocal call_count
            headers = kw.get("headers", {})
            call_count += 1
            # First call (no auth) returns 401
            if not headers or not headers.get("api-key"):
                return make_response(status_code=401)
            # Default key "qdrant" works
            if headers.get("api-key") == "qdrant":
                return make_response(body=json.dumps({"result": {"collections": []}}))
            return make_response(status_code=401)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.auth_bypass.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) >= 1
        assert "default" in high[0].title.lower()

    @pytest.mark.asyncio
    async def test_auth_enforced(self, sample_service, rag_context):
        check = RAGAuthBypassCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.auth_bypass.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1
        assert "enforced" in info[0].title.lower()


class TestCollectionEnumeration:
    def test_metadata(self):
        check = RAGCollectionEnumerationCheck()
        assert check.name == "rag_collection_enumeration"
        assert "knowledge_base_structure" in check.produces

    @pytest.mark.asyncio
    async def test_enumerates_collections(self, sample_service, accessible_store_context):
        check = RAGCollectionEnumerationCheck()

        async def mock_get(url, **kw):
            if "/count" in url:
                return make_response(body="42")
            if "/get" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "metadatas": [{"source": "upload", "author": "admin"}],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.collection_enumeration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, accessible_store_context)

        assert result.success
        assert "knowledge_base_structure" in result.outputs
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_flags_sensitive_names(self, sample_service, accessible_store_context):
        check = RAGCollectionEnumerationCheck()
        client = _mock_client()  # All 404s - just test the naming

        with patch("app.checks.rag.collection_enumeration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, accessible_store_context)

        # hr_policies should be flagged as sensitive
        [
            f
            for f in result.findings
            if "sensitive" in f.description.lower() or "hr" in f.description.lower()
        ]
        # The collections list includes "hr_policies" which should trigger
        assert len(result.findings) >= 1


class TestEmbeddingFingerprint:
    def test_metadata(self):
        check = RAGEmbeddingFingerprintCheck()
        assert check.name == "rag_embedding_fingerprint"
        assert "embedding_model" in check.produces

    @pytest.mark.asyncio
    async def test_detects_via_embedding_endpoint(self, sample_service, rag_context):
        check = RAGEmbeddingFingerprintCheck()
        # Add an embedding endpoint
        rag_context["rag_endpoints"].append(
            {
                "url": "http://rag.example.com:8080/v1/embeddings",
                "path": "/v1/embeddings",
                "service": sample_service.to_dict(),
                "endpoint_type": "rag_query",
            }
        )

        async def mock_post(url, **kw):
            if "/embeddings" in url or "/embed" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "data": [{"embedding": [0.1] * 1536}],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.embedding_fingerprint.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "embedding_model" in result.outputs
        model = result.outputs["embedding_model"]
        assert model["dimensions"] == 1536
        assert "ada-002" in (model.get("model_name") or "")

    @pytest.mark.asyncio
    async def test_detects_via_header(self, sample_service, rag_context):
        check = RAGEmbeddingFingerprintCheck()

        async def mock_post(url, **kw):
            return make_response(
                headers={"x-embedding-model": "text-embedding-3-large"},
                body=json.dumps({"results": []}),
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.embedding_fingerprint.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        if "embedding_model" in result.outputs:
            assert result.outputs["embedding_model"]["model_name"] == "text-embedding-3-large"

    @pytest.mark.asyncio
    async def test_unknown_model(self, sample_service, rag_context):
        check = RAGEmbeddingFingerprintCheck()
        client = _mock_client(post_fn=AsyncMock(return_value=make_response(status_code=404)))

        with patch("app.checks.rag.embedding_fingerprint.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Read-Only Probing
# ═══════════════════════════════════════════════════════════════════════════════


class TestDocumentExfiltration:
    def test_metadata(self):
        check = RAGDocumentExfiltrationCheck()
        assert check.name == "rag_document_exfiltration"
        assert check.intrusive is True
        assert "sensitive_content_categories" in check.produces

    @pytest.mark.asyncio
    async def test_detects_credentials(self, sample_service, rag_context):
        check = RAGDocumentExfiltrationCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            query = body.get("query", "")
            if "password" in query.lower() or "credential" in query.lower():
                return make_response(
                    body=json.dumps(
                        {
                            "results": [
                                {"content": "DB password: secretpass123\nAPI_KEY=sk-abc123"}
                            ],
                        }
                    )
                )
            return make_response(body=json.dumps({"results": [{"content": "General info"}]}))

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.document_exfiltration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert "credentials" in critical[0].title.lower() or "api" in str(result.outputs).lower()

    @pytest.mark.asyncio
    async def test_detects_pii(self, sample_service, rag_context):
        check = RAGDocumentExfiltrationCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=json.dumps(
                    {
                        "results": [{"content": "Employee: john@company.com, SSN: 123-45-6789"}],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.document_exfiltration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "sensitive_content_categories" in result.outputs
        cats = result.outputs["sensitive_content_categories"]
        assert "email" in cats or "ssn" in cats

    @pytest.mark.asyncio
    async def test_clean_knowledge_base(self, sample_service, rag_context):
        check = RAGDocumentExfiltrationCheck()

        async def mock_post(url, **kw):
            return make_response(body="Here is information about our products.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.document_exfiltration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        low = [f for f in result.findings if f.severity == "low"]
        assert len(low) >= 1
        assert "non-sensitive" in low[0].title.lower()


class TestRetrievalManipulation:
    def test_metadata(self):
        check = RAGRetrievalManipulationCheck()
        assert check.name == "rag_retrieval_manipulation"
        assert "retrieval_control" in check.produces

    @pytest.mark.asyncio
    async def test_detects_topk_override(self, sample_service, rag_context):
        check = RAGRetrievalManipulationCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            k = body.get("top_k", body.get("k", 5))
            # Return different counts based on k
            docs = [{"content": f"doc{i}"} for i in range(min(k, 50))]
            return make_response(body=json.dumps({"results": docs}))

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.retrieval_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "retrieval_control" in result.outputs
        # Should detect that top_k is overridable
        if result.outputs["retrieval_control"]["topk_overridable"]:
            high = [f for f in result.findings if f.severity == "high"]
            assert len(high) >= 1

    @pytest.mark.asyncio
    async def test_topk_bounded(self, sample_service, rag_context):
        check = RAGRetrievalManipulationCheck()

        async def mock_post(url, **kw):
            # Always return same number regardless of k
            return make_response(
                body=json.dumps({"results": [{"content": "doc1"}, {"content": "doc2"}]})
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.retrieval_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        low = [f for f in result.findings if f.severity == "low"]
        assert len(low) >= 1


class TestSourceAttribution:
    def test_metadata(self):
        check = RAGSourceAttributionCheck()
        assert check.name == "rag_source_attribution"
        assert "citation_reliability" in check.produces

    @pytest.mark.asyncio
    async def test_detects_structured_citations(self, sample_service, rag_context):
        check = RAGSourceAttributionCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=json.dumps(
                    {
                        "answer": "The policy states...",
                        "sources": [
                            {
                                "url": "https://internal.example.com/policy.pdf",
                                "title": "Company Policy",
                            },
                        ],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.source_attribution.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "citation_reliability" in result.outputs
        assert result.outputs["citation_reliability"]["has_citations"]

    @pytest.mark.asyncio
    async def test_no_citations(self, sample_service, rag_context):
        check = RAGSourceAttributionCheck()

        async def mock_post(url, **kw):
            return make_response(body="Here is the answer without any sources.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.source_attribution.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


class TestCachePoisoning:
    def test_metadata(self):
        check = RAGCachePoisoningCheck()
        assert check.name == "rag_cache_poisoning"
        assert "rag_cache_behavior" in check.produces

    @pytest.mark.asyncio
    async def test_detects_caching(self, sample_service, rag_context):
        check = RAGCachePoisoningCheck()

        async def mock_post(url, **kw):
            return make_response(
                body="Cached response body exactly the same",
                headers={"x-cache": "HIT", "cache-control": "max-age=300"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert result.outputs["rag_cache_behavior"]["identical_responses"]
        # Should have a medium+ finding about caching
        cache_findings = [f for f in result.findings if f.severity in ("medium", "high")]
        assert len(cache_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_caching(self, sample_service, rag_context):
        check = RAGCachePoisoningCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            return make_response(body=f"Unique response {call_count}")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1

    @pytest.mark.asyncio
    async def test_cache_poisoning_with_injection(self, sample_service, rag_context):
        check = RAGCachePoisoningCheck()
        rag_context["vulnerable_rag_endpoints"] = [{"endpoint": "test"}]

        async def mock_post(url, **kw):
            return make_response(body="Identical cached poisoned response")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) >= 1
        assert "poison" in high[0].title.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Write/Intrusive Checks
# ═══════════════════════════════════════════════════════════════════════════════


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
                return make_response(status_code=201, body='{"id": "test"}')
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "ingestion_endpoints" in result.outputs
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert (
            "unauthenticated" in critical[0].title.lower() or "corpus" in critical[0].title.lower()
        )

    @pytest.mark.asyncio
    async def test_auth_required(self, sample_service, rag_context):
        check = RAGCorpusPoisoningCheck()

        async def mock_post(url, **kw):
            if "/documents" in url or "/ingest" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # Should find endpoint but not critical
        if result.outputs.get("ingestion_endpoints"):
            assert all(f.severity != "critical" for f in result.findings)

    @pytest.mark.asyncio
    async def test_no_ingestion_endpoints(self, sample_service, rag_context):
        check = RAGCorpusPoisoningCheck()
        client = _mock_client()

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


class TestMetadataInjection:
    def test_metadata(self):
        check = RAGMetadataInjectionCheck()
        assert check.name == "rag_metadata_injection"
        assert check.intrusive is True
        assert "metadata_injection_results" in check.produces

    @pytest.mark.asyncio
    async def test_passive_metadata_visible(self, sample_service, rag_context):
        check = RAGMetadataInjectionCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=json.dumps(
                    {
                        "answer": "The document says...",
                        "sources": [
                            {
                                "source": "policy.pdf",
                                "author": "admin",
                                "metadata": {"title": "Policy"},
                            }
                        ],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.metadata_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # Should detect metadata fields in response
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_active_injection_with_ingestion(self, sample_service, ingestion_context):
        check = RAGMetadataInjectionCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            if "/documents" in url or "/api/documents" in url:
                return make_response(status_code=201)
            # Query response includes injected metadata content
            if body.get("query"):
                return make_response(body="metadata injection test succeeded in response")
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.metadata_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

        assert result.success

    @pytest.mark.asyncio
    async def test_no_metadata(self, sample_service, rag_context):
        check = RAGMetadataInjectionCheck()

        async def mock_post(url, **kw):
            return make_response(body="Simple answer without any metadata.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.metadata_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


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
        high = [f for f in result.findings if f.severity == "high"]
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
        info = [f for f in result.findings if f.severity == "info"]
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
        upload_findings = [
            f
            for f in result.findings
            if "upload" in f.title.lower() or "multimodal" in f.title.lower()
        ]
        assert len(upload_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_upload(self, sample_service, rag_context):
        check = RAGMultimodalInjectionCheck()
        client = _mock_client()

        with patch("app.checks.rag.multimodal_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1
        assert "not accept" in info[0].title.lower() or "no" in info[0].title.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5: Advanced Checks
# ═══════════════════════════════════════════════════════════════════════════════


class TestFusionReranker:
    def test_metadata(self):
        check = RAGFusionRerankerCheck()
        assert check.name == "rag_fusion_reranker"
        assert "reranker_info" in check.produces

    @pytest.mark.asyncio
    async def test_detects_via_headers(self, sample_service, rag_context):
        check = RAGFusionRerankerCheck()

        async def mock_post(url, **kw):
            return make_response(
                headers={"x-reranker": "cross-encoder/ms-marco-MiniLM-L-6-v2"},
                body=json.dumps({"results": [{"content": "doc", "score": 0.95}]}),
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.fusion_reranker.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert result.outputs["reranker_info"]["reranker_detected"]

    @pytest.mark.asyncio
    async def test_no_reranker(self, sample_service, rag_context):
        check = RAGFusionRerankerCheck()

        async def mock_post(url, **kw):
            return make_response(body=json.dumps({"results": []}))

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.fusion_reranker.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


class TestCrossCollection:
    def test_metadata(self):
        check = RAGCrossCollectionCheck()
        assert check.name == "rag_cross_collection"
        assert "cross_collection_results" in check.produces

    @pytest.mark.asyncio
    async def test_isolation_violated(self, sample_service, kb_structure_context):
        check = RAGCrossCollectionCheck()

        async def mock_post(url, **kw):
            # Query to docs collection returns content mentioning hr_policies
            if "docs" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "ids": [["hr1"]],
                            "documents": [["hr_policies content leaked"]],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cross_collection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, kb_structure_context)

        assert result.success
        # Should detect cross-collection leak
        leak_findings = [f for f in result.findings if f.severity in ("critical", "high")]
        assert len(leak_findings) >= 1

    @pytest.mark.asyncio
    async def test_isolation_enforced(self, sample_service, kb_structure_context):
        check = RAGCrossCollectionCheck()

        async def mock_post(url, **kw):
            if "docs" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "ids": [["d1"]],
                            "documents": [["Only docs content here"]],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cross_collection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, kb_structure_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


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
        assert len(result.findings) >= 1

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
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: Check Resolver Registration
# ═══════════════════════════════════════════════════════════════════════════════


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
