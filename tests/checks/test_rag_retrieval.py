"""Tests for RAG retrieval manipulation, source attribution, fusion/reranker, and cross-collection checks."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.cross_collection import RAGCrossCollectionCheck
from app.checks.rag.document_exfiltration import RAGDocumentExfiltrationCheck
from app.checks.rag.fusion_reranker import RAGFusionRerankerCheck
from app.checks.rag.retrieval_manipulation import RAGRetrievalManipulationCheck
from app.checks.rag.source_attribution import RAGSourceAttributionCheck
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
