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
# Full Chroma mock responses with realistic surrounding content
# ---------------------------------------------------------------------------

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


class TestVectorStoreAccess:
    def test_metadata(self):
        check = RAGVectorStoreAccessCheck()
        assert check.name == "rag_vector_store_access"
        assert "accessible_stores" in check.produces

    @pytest.mark.asyncio
    async def test_detects_accessible_chroma(self, sample_service, rag_context):
        """Full Chroma response flow: collections, count, documents, query."""
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(body=CHROMA_COLLECTIONS_RESPONSE)
            if "/count" in url:
                return make_response(body=CHROMA_COUNT_RESPONSE)
            if "/get" in url:
                return make_response(body=CHROMA_DOCUMENTS_RESPONSE)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/query" in url and "collections" in url:
                return make_response(body=CHROMA_QUERY_RESPONSE)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.rag.vector_store_access.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "accessible_stores" in result.outputs

        stores = result.outputs["accessible_stores"]
        assert len(stores) >= 1
        store = stores[0]
        assert store["store_type"] == "chroma"
        assert store["collections"] == ["docs", "faq"]
        op_names = {op["operation"] for op in store["accessible_ops"]}
        assert "list_collections" in op_names
        assert "dump_documents" in op_names

        # Document dump produces a critical observation
        assert len(result.observations) >= 1
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert critical[0].title == "Vector store directly accessible: chroma"
        assert "chroma" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_all_401_records_auth_required_ops(self, sample_service, rag_context):
        """When every probe returns 401, accessible_ops should contain auth_required entries."""
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.vector_store_access.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # The collections listing itself returned 401, so accessible_stores
        # should reflect auth-required ops (the check records 401 as an op).
        stores = result.outputs.get("accessible_stores", [])
        if stores:
            auth_ops = [o for o in stores[0]["accessible_ops"] if o.get("auth_required")]
            assert len(auth_ops) >= 1
            assert auth_ops[0]["status"] == 401

    @pytest.mark.asyncio
    async def test_collections_endpoint_returns_401(self, sample_service, rag_context):
        """Negative: collections endpoint returns 401 -- no critical observations."""
        check = RAGVectorStoreAccessCheck()

        async def mock_get(url, **kw):
            # Collections listing is auth-gated; everything else 404
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.vector_store_access.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0, "No critical finding expected when collections listing is 401"

    @pytest.mark.asyncio
    async def test_non_vector_store_json_at_collections_path(self, sample_service, rag_context):
        """Negative: collections path returns JSON that is NOT a Chroma collections list."""
        check = RAGVectorStoreAccessCheck()

        # Return a generic REST API response (not a list of dicts with 'name')
        non_vector_body = json.dumps(
            {
                "status": "ok",
                "version": "2.1.0",
                "endpoints": ["/health", "/metrics"],
            }
        )

        async def mock_get(url, **kw):
            if "/api/v1/collections" in url and "/get" not in url and "/count" not in url:
                return make_response(body=non_vector_body)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch("app.checks.rag.vector_store_access.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # A non-list response should not produce collections or critical findings
        stores = result.outputs.get("accessible_stores", [])
        if stores:
            assert stores[0]["collections"] == [], (
                "Non-vector-store JSON should not yield collection names"
            )
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0


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

        with patch("app.checks.rag.collection_enumeration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, accessible_store_context)

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

        with patch("app.checks.rag.collection_enumeration.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, accessible_store_context)

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


class TestEmbeddingFingerprint:
    def test_metadata(self):
        check = RAGEmbeddingFingerprintCheck()
        assert check.name == "rag_embedding_fingerprint"
        assert "embedding_model" in check.produces

    @pytest.mark.asyncio
    async def test_detects_via_embedding_endpoint(self, sample_service, rag_context):
        """1536-dim embedding response should fingerprint as ada-002."""
        check = RAGEmbeddingFingerprintCheck()
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
                            "object": "list",
                            "data": [
                                {
                                    "object": "embedding",
                                    "index": 0,
                                    "embedding": [0.0023] * 1536,
                                }
                            ],
                            "model": "text-embedding-ada-002",
                            "usage": {"prompt_tokens": 1, "total_tokens": 1},
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
        assert "ada-002" in model["model_name"]

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.severity == "low"
        assert "1536" in obs.title
        assert "ada-002" in obs.title

    @pytest.mark.asyncio
    async def test_detects_via_header(self, sample_service, rag_context):
        """x-embedding-model header should be captured as model name."""
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
        assert "embedding_model" in result.outputs
        assert result.outputs["embedding_model"]["model_name"] == "text-embedding-3-large"
        assert len(result.observations) == 1
        assert "text-embedding-3-large" in result.observations[0].title

    @pytest.mark.asyncio
    async def test_unknown_model_produces_info_observation(self, sample_service, rag_context):
        """When no signals are found, an info-severity 'not identified' observation is emitted."""
        check = RAGEmbeddingFingerprintCheck()
        client = _mock_client(post_fn=AsyncMock(return_value=make_response(status_code=404)))

        with patch("app.checks.rag.embedding_fingerprint.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # No model info means no 'embedding_model' output
        assert "embedding_model" not in result.outputs

        # But there should be an info observation about failing to identify
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.severity == "info"
        assert "not identified" in obs.title.lower()
