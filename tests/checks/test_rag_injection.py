"""Tests for RAG auth bypass, cache/corpus poisoning, and metadata injection checks."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.auth_bypass import RAGAuthBypassCheck
from app.checks.rag.cache_poisoning import RAGCachePoisoningCheck
from app.checks.rag.corpus_poisoning import RAGCorpusPoisoningCheck
from app.checks.rag.metadata_injection import RAGMetadataInjectionCheck
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
        critical = [f for f in result.observations if f.severity == "critical"]
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
        high = [f for f in result.observations if f.severity == "high"]
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
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1
        assert "enforced" in info[0].title.lower()


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
        # Should have a medium+ observation about caching
        cache_observations = [f for f in result.observations if f.severity in ("medium", "high")]
        assert len(cache_observations) >= 1

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
        info = [f for f in result.observations if f.severity == "info"]
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
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) >= 1
        assert "poison" in high[0].title.lower()


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
        critical = [f for f in result.observations if f.severity == "critical"]
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
            assert all(f.severity != "critical" for f in result.observations)

    @pytest.mark.asyncio
    async def test_no_ingestion_endpoints(self, sample_service, rag_context):
        check = RAGCorpusPoisoningCheck()
        client = _mock_client()

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
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
        assert len(result.observations) >= 1

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
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1
