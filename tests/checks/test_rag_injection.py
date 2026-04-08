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
        assert len(critical) == 1
        assert "no authentication" in critical[0].title.lower()
        assert "chroma" in critical[0].title.lower()
        assert critical[0].evidence is not None

    @pytest.mark.asyncio
    async def test_detects_default_key_bypass(self, sample_service, rag_context):
        check = RAGAuthBypassCheck()
        rag_context["vector_stores"] = ["qdrant"]
        rag_context["rag_endpoints"][1]["store_type"] = "qdrant"

        async def mock_get(url, **kw):
            headers = kw.get("headers", {})
            # No auth returns 401
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
        assert len(high) == 1
        assert "default" in high[0].title.lower()
        assert "qdrant" in high[0].title.lower()
        assert "default_key" in high[0].evidence

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
        assert len(info) == 1
        assert "enforced" in info[0].title.lower()
        assert "chroma" in info[0].title.lower()


class TestCachePoisoning:
    def test_metadata(self):
        check = RAGCachePoisoningCheck()
        assert check.name == "rag_cache_poisoning"
        assert "rag_cache_behavior" in check.produces

    @pytest.mark.asyncio
    async def test_detects_caching_with_headers_and_identical_bodies(
        self, sample_service, rag_context
    ):
        """Cache detected via cache-control header and identical response bodies."""
        check = RAGCachePoisoningCheck()

        # Realistic RAG response with cache headers embedded naturally
        rag_body = json.dumps(
            {
                "answer": "The knowledge base covers HR policies, IT procedures, and FAQs.",
                "sources": [
                    {"title": "HR Onboarding Guide", "score": 0.92},
                    {"title": "IT Security Policy", "score": 0.87},
                ],
            }
        )

        async def mock_post(url, **kw):
            return make_response(
                body=rag_body,
                headers={"cache-control": "max-age=300", "content-type": "application/json"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert result.outputs["rag_cache_behavior"]["identical_responses"]
        assert "cache-control" in result.outputs["rag_cache_behavior"]["cache_headers"]
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert "identical responses" in medium[0].title.lower()
        assert "Identical responses: True" in medium[0].evidence

    @pytest.mark.asyncio
    async def test_no_caching_unique_responses(self, sample_service, rag_context):
        """No caching when each response body is different and no cache headers present."""
        check = RAGCachePoisoningCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = json.dumps(
                {
                    "answer": f"Response variation {call_count} with slightly different wording.",
                    "sources": [{"title": "Doc A", "score": 0.85 + call_count * 0.01}],
                }
            )
            return make_response(body=body, headers={"content-type": "application/json"})

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert not result.outputs["rag_cache_behavior"]["caching_detected"]
        assert not result.outputs["rag_cache_behavior"]["identical_responses"]
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "no rag-level caching detected" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_cache_poisoning_with_vulnerable_endpoints(self, sample_service, rag_context):
        """When caching + prior injection detected, severity escalates to high."""
        check = RAGCachePoisoningCheck()
        rag_context["vulnerable_rag_endpoints"] = [
            {"endpoint": "/query", "vulnerability": "indirect_injection"}
        ]

        # Same realistic body returned twice triggers identical_responses
        rag_body = json.dumps(
            {
                "answer": "According to company policy, all employees must complete training.",
                "sources": [{"title": "Training Policy v2.1", "score": 0.94}],
            }
        )

        async def mock_post(url, **kw):
            return make_response(
                body=rag_body,
                headers={"content-type": "application/json"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert result.outputs["rag_cache_behavior"]["identical_responses"]
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 1
        assert "cache poisoning" in high[0].title.lower()
        assert "injected response" in high[0].title.lower()
        assert "Identical responses: True" in high[0].evidence

    @pytest.mark.asyncio
    async def test_cache_headers_but_different_bodies(self, sample_service, rag_context):
        """Cache headers present but responses differ -- low severity."""
        check = RAGCachePoisoningCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = json.dumps({"answer": f"Unique response text number {call_count}."})
            return make_response(
                body=body,
                headers={"age": "42", "content-type": "application/json"},
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.cache_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert result.outputs["rag_cache_behavior"]["caching_detected"]
        assert not result.outputs["rag_cache_behavior"]["identical_responses"]
        low = [f for f in result.observations if f.severity == "low"]
        assert len(low) == 1
        assert "responses vary" in low[0].title.lower()


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
                return make_response(
                    status_code=201,
                    body=json.dumps({"id": "doc-abc123", "status": "indexed"}),
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "ingestion_endpoints" in result.outputs
        writable = [ep for ep in result.outputs["ingestion_endpoints"] if ep.get("writable")]
        assert len(writable) >= 1
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "unauthenticated" in critical[0].title.lower()
        assert "ingestion" in critical[0].title.lower()
        assert "Path:" in critical[0].evidence
        assert "Auth required: False" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_auth_required_on_ingestion(self, sample_service, rag_context):
        """Ingestion endpoint exists but requires auth -- medium severity, no critical."""
        check = RAGCorpusPoisoningCheck()

        async def mock_post(url, **kw):
            if "/documents" in url or "/ingest" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        # Endpoint found but auth required -- produces medium observation, no critical
        assert all(f.severity != "critical" for f in result.observations)
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert "writes rejected" in medium[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_ingestion_endpoints_found(self, sample_service, rag_context):
        """All probed paths return 404 -- info observation, no ingestion_endpoints output."""
        check = RAGCorpusPoisoningCheck()
        client = _mock_client()

        with patch("app.checks.rag.corpus_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        assert "ingestion_endpoints" not in result.outputs
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "no writable ingestion" in info[0].title.lower()
        assert "Probed" in info[0].evidence


class TestMetadataInjection:
    def test_metadata(self):
        check = RAGMetadataInjectionCheck()
        assert check.name == "rag_metadata_injection"
        assert check.intrusive is True
        assert "metadata_injection_results" in check.produces

    @pytest.mark.asyncio
    async def test_passive_metadata_visible(self, sample_service, rag_context):
        """Passive analysis detects metadata fields in structured RAG response."""
        check = RAGMetadataInjectionCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=json.dumps(
                    {
                        "answer": "The document says all new hires must complete orientation.",
                        "sources": [
                            {
                                "source": "policy.pdf",
                                "author": "admin",
                                "metadata": {"title": "Onboarding Policy"},
                            }
                        ],
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.metadata_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert "metadata included" in medium[0].title.lower()
        assert "source" in medium[0].evidence.lower()

    @pytest.mark.asyncio
    async def test_active_injection_with_ingestion(self, sample_service, ingestion_context):
        """Active test: injected metadata payload is followed by the LLM."""
        check = RAGMetadataInjectionCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            if "/api/documents" in url:
                return make_response(status_code=201)
            # Query response contains the indicator phrase from the source field injection
            if body.get("query") or body.get("question"):
                return make_response(
                    body=json.dumps(
                        {
                            "answer": (
                                "Based on the documents, metadata injection test succeeded "
                                "as requested by the source field."
                            ),
                            "sources": [{"title": "General Topics", "score": 0.91}],
                        }
                    )
                )
            return make_response(status_code=404)

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.metadata_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ingestion_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) >= 1
        assert "metadata injection" in high[0].title.lower()
        assert "source" in high[0].title.lower()
        assert "Field: source" in high[0].evidence

    @pytest.mark.asyncio
    async def test_no_metadata_in_response(self, sample_service, rag_context):
        """No metadata fields detected in plain-text RAG response."""
        check = RAGMetadataInjectionCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=json.dumps(
                    {
                        "answer": "The company was founded in 2019 and operates globally.",
                    }
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.rag.metadata_injection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, rag_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "not accessible" in info[0].title.lower()
        assert "No metadata indicators" in info[0].evidence
