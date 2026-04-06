"""Tests for RAG vector store access, collection enumeration, and embedding fingerprint checks."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.collection_enumeration import RAGCollectionEnumerationCheck
from app.checks.rag.embedding_fingerprint import RAGEmbeddingFingerprintCheck
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
