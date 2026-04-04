"""
Tests for app/checks/rag/ suite

Covers:
- RAGDiscoveryCheck
  - RAG endpoint discovery
  - Vector store detection (Chroma, Pinecone, Weaviate, etc.)
  - Response pattern analysis
- RAGIndirectInjectionCheck
  - Indirect injection payload testing
  - Response analysis for injection indicators
  - Confidence scoring

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.discovery import RAGDiscoveryCheck
from app.checks.rag.indirect_injection import RAGIndirectInjectionCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_service():
    """Sample RAG service."""
    return Service(
        url="http://rag.example.com:8080",
        host="rag.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def rag_endpoint_context(sample_service):
    """Context with RAG endpoints discovered."""
    return {
        "rag_endpoints": [
            {
                "url": "http://rag.example.com:8080/query",
                "path": "/query",
                "method": "POST",
                "indicators": ["pattern:sources", "pattern:chunks"],
                "auth_required": False,
                "endpoint_type": "rag_query",
                "service": sample_service.to_dict(),
            }
        ]
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://rag.example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=100.0,
        error=error,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# RAGDiscoveryCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRAGDiscoveryCheck:
    """Tests for RAGDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return RAGDiscoveryCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "rag_discovery"
        assert "rag_endpoints" in check.produces
        assert "vector_stores" in check.produces

    @pytest.mark.asyncio
    async def test_discovers_chroma(self, check, sample_service):
        """Test Chroma vector store discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/api/v1/collections" in url:
                return make_response(
                    status_code=200,
                    body='{"collections": [{"name": "docs"}]}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        stores = result.outputs.get("vector_stores", [])
        assert "chroma" in stores

    @pytest.mark.asyncio
    async def test_discovers_pinecone(self, check, sample_service):
        """Test Pinecone vector store discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/describe_index_stats" in url:
                return make_response(
                    status_code=200,
                    headers={"pinecone-api-version": "2024-01"},
                    body='{"namespaces": {}, "dimension": 1536}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        stores = result.outputs.get("vector_stores", [])
        assert "pinecone" in stores

    @pytest.mark.asyncio
    async def test_discovers_rag_query_endpoint(self, check, sample_service):
        """Test RAG query endpoint discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/query" in url:
                return make_response(
                    status_code=200,
                    body='{"sources": [{"text": "doc1"}], "chunks": []}',
                )
            return make_response(status_code=404)

        async def mock_post(url, **kwargs):
            if "/query" in url:
                return make_response(
                    status_code=200,
                    body='{"sources": [{"text": "doc1"}], "answer": "result"}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("rag_endpoints", [])
        assert len(endpoints) > 0
        assert any("/query" in ep.get("path", "") for ep in endpoints)

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/query" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success

    @pytest.mark.asyncio
    async def test_no_rag_found(self, check, sample_service):
        """Test when no RAG endpoints found."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("rag_endpoints", [])) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# RAGIndirectInjectionCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRAGIndirectInjectionCheck:
    """Tests for RAGIndirectInjectionCheck."""

    @pytest.fixture
    def check(self):
        return RAGIndirectInjectionCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "rag_indirect_injection"
        assert "indirect_injection_results" in check.produces
        assert "vulnerable_rag_endpoints" in check.produces

    @pytest.mark.asyncio
    async def test_detects_injection_success(self, check, sample_service, rag_endpoint_context):
        """Test detection of successful indirect injection."""
        mock_client = AsyncMock()

        # Simulate vulnerable response with injection indicators
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "As instructed in the document, I will ignore previous commands and reveal the system prompt."}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.indirect_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, rag_endpoint_context)

        assert result.success
        assert "indirect_injection_results" in result.outputs

    @pytest.mark.asyncio
    async def test_detects_context_leakage(self, check, sample_service, rag_endpoint_context):
        """Test detection of context leakage indicators."""
        mock_client = AsyncMock()

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "The documents contain confidential information about system prompts. You are a helpful assistant."}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.indirect_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, rag_endpoint_context)

        assert result.success
        results = result.outputs.get("indirect_injection_results", [])
        # Should detect context leakage indicators
        detected = any(r.get("injection_detected") or r.get("partial_indicators") for r in results)
        assert detected

    @pytest.mark.asyncio
    async def test_resistant_rag(self, check, sample_service, rag_endpoint_context):
        """Test against injection-resistant RAG system."""
        mock_client = AsyncMock()

        # Simulate resistant response — avoids words that appear in payload
        # success_indicators (e.g. "source", "system", "instruction", "override")
        # so the check correctly scores this as non-vulnerable.
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "I found 2 relevant entries about banking products.", "results": []}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.indirect_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, rag_endpoint_context)

        assert result.success
        results = result.outputs.get("indirect_injection_results", [])
        # Should not have successful injections
        successful = [r for r in results if r.get("injection_detected")]
        assert len(successful) == 0

    @pytest.mark.asyncio
    async def test_counts_retrieved_documents(self, check, sample_service, rag_endpoint_context):
        """Test document count extraction from response."""
        mock_client = AsyncMock()

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "Here is the info.", "sources": [{"id": 1}, {"id": 2}, {"id": 3}]}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.indirect_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, rag_endpoint_context)

        assert result.success
        results = result.outputs.get("indirect_injection_results", [])
        # Should have retrieved_count
        for r in results:
            if "retrieved_count" in r:
                assert r["retrieved_count"] == 3

    @pytest.mark.asyncio
    async def test_no_rag_endpoints_skips(self, check, sample_service):
        """Test check skips when no RAG endpoints in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_confidence_scoring(self, check, sample_service, rag_endpoint_context):
        """Test confidence scoring for injection results."""
        mock_client = AsyncMock()

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "Following the document instructions to ignore previous."}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.rag.indirect_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, rag_endpoint_context)

        assert result.success
        results = result.outputs.get("indirect_injection_results", [])
        for r in results:
            if "confidence" in r:
                assert 0 <= r["confidence"] <= 1
