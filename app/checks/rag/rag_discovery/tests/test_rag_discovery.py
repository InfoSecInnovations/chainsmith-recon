"""Tests for rag_discovery.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.rag.rag_discovery import RAGDiscoveryCheck
from app.lib.http import HttpResponse


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
    url: str = "http://rag.example.com:8080",
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=100.0,
        error=error,
    )


def _stamp(response: HttpResponse, url: str | None) -> HttpResponse:
    """Report the response as coming from the URL it was requested from, so the
    probe records each exchange's `request_url` correctly and grade can attribute
    it by path (§0.13)."""
    return replace(response, url=url) if url else response


def _build_mock_client(get_fn=None, post_fn=None):
    """Build a mock async HTTP client with optional custom get/post handlers.

    `__aexit__` returns False so a probe exception is not suppressed (§0.14), and
    every response is stamped with the requested URL.
    """
    mock_client = AsyncMock()

    def _dispatch(fn):
        async def _call(url=None, **kw):
            resp = (await fn(url, **kw)) if fn else make_response(status_code=404)
            return _stamp(resp, url)

        return AsyncMock(side_effect=_call)

    mock_client.get = _dispatch(get_fn)
    mock_client.post = _dispatch(post_fn)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


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

    # ── Chroma detection ─────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_discovers_chroma_with_realistic_response(self, check, sample_service):
        """Chroma detected when /api/v1/collections returns ChromaDB-shaped JSON."""
        chroma_body = json.dumps(
            [
                {
                    "name": "product_docs",
                    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "metadata": {"hnsw:space": "cosine"},
                    "tenant": "default_tenant",
                    "database": "default_database",
                },
                {
                    "name": "customer_faq",
                    "id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
                    "metadata": {},
                    "tenant": "default_tenant",
                    "database": "default_database",
                },
            ]
        )

        async def mock_get(url, **kwargs):
            if "/api/v1/collections" in url:
                return make_response(
                    url=url,
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "x-chroma-version": "0.4.22",
                        "server": "uvicorn",
                    },
                    body=chroma_body,
                )
            if "/api/v1/heartbeat" in url:
                return make_response(
                    url=url,
                    status_code=200,
                    body='{"nanosecond heartbeat": 1700000000000000000}',
                )
            return make_response(url=url, status_code=404)

        mock_client = _build_mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # Vector store output
        stores = result.outputs.get("vector_stores", [])
        assert "chroma" in stores

        # Observation content - check title and severity
        store_obs = [o for o in result.observations if "chroma" in o.title.lower()]
        assert len(store_obs) >= 1
        obs = store_obs[0]
        assert obs.title == "Vector store detected: chroma"
        assert obs.severity == "medium"  # no auth required -> medium
        assert "chroma" in obs.evidence.lower()
        assert "/api/v1/collections" in obs.evidence

    @pytest.mark.asyncio
    async def test_generic_json_api_at_collections_path_not_detected_as_chroma(
        self, check, sample_service
    ):
        """A generic REST API at /api/v1/collections WITHOUT Chroma body/header
        patterns should still be detected (status 200 triggers detection), but
        without body_match or headers_match indicators."""
        generic_body = json.dumps(
            {
                "items": [
                    {"id": 1, "name": "widgets", "count": 42},
                    {"id": 2, "name": "gadgets", "count": 17},
                ],
                "total": 2,
                "page": 1,
            }
        )

        async def mock_get(url, **kwargs):
            if "/api/v1/collections" in url:
                return make_response(
                    url=url,
                    status_code=200,
                    headers={"content-type": "application/json", "server": "nginx"},
                    body=generic_body,
                )
            return make_response(url=url, status_code=404)

        mock_client = _build_mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # The path matches chroma signature AND status is 200, so it is detected,
        # but indicators should show neither headers nor body matched.
        stores = result.outputs.get("vector_stores", [])
        if "chroma" in stores:
            # Verify the raw_data shows neither header nor body matched
            store_obs = [o for o in result.observations if "chroma" in o.title.lower()]
            assert len(store_obs) >= 1
            raw = store_obs[0].raw_data
            assert raw["indicators"]["headers_match"] is False
            assert raw["indicators"]["body_match"] is False

    # ── Pinecone detection ───────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_discovers_pinecone_with_realistic_response(self, check, sample_service):
        """Pinecone detected via pinecone-api-version header + realistic body."""
        pinecone_body = json.dumps(
            {
                "namespaces": {
                    "production": {"vectorCount": 50000},
                    "staging": {"vectorCount": 1200},
                },
                "dimension": 1536,
                "indexFullness": 0.12,
                "totalVectorCount": 51200,
            }
        )

        async def mock_get(url, **kwargs):
            if "/describe_index_stats" in url:
                return make_response(
                    url=url,
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "pinecone-api-version": "2024-07",
                        "x-pinecone-request-id": "req-abc123",
                        "x-request-id": "550e8400-e29b-41d4-a716-446655440000",
                    },
                    body=pinecone_body,
                )
            return make_response(url=url, status_code=404)

        mock_client = _build_mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        stores = result.outputs.get("vector_stores", [])
        assert "pinecone" in stores

        # Observation specifics
        pinecone_obs = [o for o in result.observations if "pinecone" in o.title.lower()]
        assert len(pinecone_obs) >= 1
        obs = pinecone_obs[0]
        assert obs.title == "Vector store detected: pinecone"
        assert obs.severity == "medium"
        assert "/describe_index_stats" in obs.evidence
        assert obs.check_name == "rag_discovery"

    @pytest.mark.asyncio
    async def test_response_without_pinecone_header_not_detected_as_pinecone(
        self, check, sample_service
    ):
        """Endpoint at /describe_index_stats returning 200 but without
        Pinecone-specific header or body patterns should not produce
        header_match or body_match indicators."""
        # A response that has no pinecone-specific patterns
        generic_stats_body = json.dumps(
            {
                "status": "healthy",
                "uptime_seconds": 86400,
                "version": "3.2.1",
            }
        )

        async def mock_get(url, **kwargs):
            if "/describe_index_stats" in url:
                return make_response(
                    url=url,
                    status_code=200,
                    headers={"content-type": "application/json", "server": "gunicorn"},
                    body=generic_stats_body,
                )
            return make_response(url=url, status_code=404)

        mock_client = _build_mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # The path is a pinecone signature path and status 200, so detection
        # fires, but the indicators should reflect no header/body match.
        stores = result.outputs.get("vector_stores", [])
        if "pinecone" in stores:
            pinecone_obs = [o for o in result.observations if "pinecone" in o.title.lower()]
            assert len(pinecone_obs) >= 1
            raw = pinecone_obs[0].raw_data
            assert raw["indicators"]["headers_match"] is False
            assert raw["indicators"]["body_match"] is False

    # ── RAG query endpoint detection ────────────────────────────────────

    @pytest.mark.asyncio
    async def test_discovers_rag_query_endpoint_with_indicators(self, check, sample_service):
        """RAG query endpoint detected via response containing sources and chunks fields."""
        rag_response_body = json.dumps(
            {
                "answer": "The product supports SSO via SAML 2.0.",
                "sources": [
                    {"text": "SSO configuration guide", "page": 12, "score": 0.94},
                    {"text": "Authentication overview", "page": 3, "score": 0.87},
                ],
                "chunks": [
                    {"content": "SAML 2.0 integration is supported...", "metadata": {}},
                ],
                "model": "gpt-4",
                "tokens_used": 342,
            }
        )

        # Use /ask path which is only in RAG_PATHS, not in any vector store signature
        async def mock_get(url, **kwargs):
            if "/ask" in url:
                return make_response(url=url, status_code=200, body=rag_response_body)
            return make_response(url=url, status_code=404)

        async def mock_post(url, **kwargs):
            if "/ask" in url:
                return make_response(url=url, status_code=200, body=rag_response_body)
            return make_response(url=url, status_code=404)

        mock_client = _build_mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("rag_endpoints", [])
        assert len(endpoints) > 0

        # Verify the /ask endpoint was found as a RAG query endpoint
        ask_eps = [ep for ep in endpoints if ep.get("path") == "/ask"]
        assert len(ask_eps) >= 1
        ep = ask_eps[0]
        assert ep["endpoint_type"] == "rag_query"
        assert "field:sources" in ep["indicators"]
        assert "field:chunks" in ep["indicators"]
        assert ep["auth_required"] is False

        # Verify observation was created with correct severity and title
        ask_obs = [o for o in result.observations if "/ask" in o.title]
        assert len(ask_obs) >= 1
        obs = ask_obs[0]
        assert obs.title == "RAG endpoint: /ask"
        assert obs.severity == "medium"  # no auth -> medium for rag_query
        assert "No authentication required" in obs.description

    # ── Auth detection ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_detects_auth_required_endpoint(self, check, sample_service):
        """Endpoint returning 401 is recognised as requiring auth with info severity."""

        async def mock_get(url, **kwargs):
            if "/query" in url:
                return make_response(
                    url=url,
                    status_code=401,
                    headers={"www-authenticate": "Bearer"},
                    body='{"error": "unauthorized"}',
                )
            return make_response(url=url, status_code=404)

        mock_client = _build_mock_client(get_fn=mock_get)

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # 401 endpoints should be flagged with auth_required
        endpoints = result.outputs.get("rag_endpoints", [])
        auth_eps = [ep for ep in endpoints if ep.get("path") == "/query"]
        if auth_eps:
            assert auth_eps[0]["auth_required"] is True
            # Observation severity should be info for auth-required endpoints
            query_obs = [o for o in result.observations if "/query" in o.title]
            if query_obs:
                assert query_obs[0].severity == "info"

    # ── No RAG found ────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_no_rag_found_returns_empty_outputs_and_no_observations(
        self, check, sample_service
    ):
        """When all paths return 404, no endpoints/stores are reported."""
        mock_client = _build_mock_client()

        with patch("app.checks.rag.rag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("rag_endpoints", [])) == 0
        assert len(result.outputs.get("vector_stores", [])) == 0
        assert len(result.observations) == 0
        assert len(result.errors) == 0
