"""Tests for CAG detection and behavior checks (Phase 2)."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cache_eviction import CacheEvictionCheck
from app.checks.cag.cache_quota import CacheQuotaCheck
from app.checks.cag.cache_warming import CacheWarmingCheck
from app.checks.cag.multi_layer import MultiLayerCacheCheck
from app.checks.cag.provider_caching import ProviderCachingCheck
from app.checks.cag.ttl_mapping import TTLMappingCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_service():
    """Sample CAG service."""
    return Service(
        url="http://cag.example.com:8080",
        host="cag.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def cag_endpoint_context(sample_service):
    """Context with CAG endpoints discovered."""
    return {
        "cag_endpoints": [
            {
                "url": "http://cag.example.com:8080/cache",
                "path": "/cache",
                "cache_type": "gptcache",
                "status_code": 200,
                "auth_required": False,
                "endpoint_type": "cache_infrastructure",
                "service": sample_service.to_dict(),
            }
        ],
        "cache_infrastructure": ["gptcache"],
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://cag.example.com:8080/test",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def make_mock_client(**overrides):
    """Create a standard mock HTTP client."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=make_response(status_code=404))
    client.post = AsyncMock(return_value=make_response(status_code=200, body='{"answer": "ok"}'))
    client.head = AsyncMock(return_value=make_response(status_code=404))
    client._request = AsyncMock(return_value=make_response(status_code=404))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock()
    for k, v in overrides.items():
        setattr(client, k, v)
    return client


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Cache Eviction Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheEvictionCheck:
    @pytest.fixture
    def check(self):
        return CacheEvictionCheck()

    def test_metadata(self, check):
        assert check.name == "cag_cache_eviction"
        assert "eviction_capability" in check.produces
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_accessible_clear_endpoint(
        self, check, sample_service, cag_endpoint_context
    ):
        async def mock_post(url, **kwargs):
            if "/cache/clear" in url:
                return make_response(status_code=200, body='{"status": "cleared"}')
            return make_response(status_code=404)

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cache_eviction.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        eviction = result.outputs.get("eviction_capability", [])
        assert len(eviction) > 0
        assert any(f.severity == "critical" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service, cag_endpoint_context):
        async def mock_post(url, **kwargs):
            if "/cache/clear" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cache_eviction.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        auth_findings = [f for f in result.findings if f.severity == "medium"]
        assert len(auth_findings) > 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Cache Warming Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheWarmingCheck:
    @pytest.fixture
    def check(self):
        return CacheWarmingCheck()

    def test_metadata(self, check):
        assert check.name == "cag_cache_warming"
        assert "warm_capability" in check.produces

    @pytest.mark.asyncio
    async def test_detects_warming_endpoint(self, check, sample_service, cag_endpoint_context):
        async def mock_post(url, **kwargs):
            if "/cache/warm" in url:
                return make_response(status_code=200, body='{"status": "warmed"}')
            return make_response(status_code=404)

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cache_warming.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: TTL Mapping Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTTLMappingCheck:
    @pytest.fixture
    def check(self):
        return TTLMappingCheck()

    def test_metadata(self, check):
        assert check.name == "cag_ttl_mapping"
        assert "cache_ttl" in check.produces

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Multi-Layer Cache Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestMultiLayerCacheCheck:
    @pytest.fixture
    def check(self):
        return MultiLayerCacheCheck()

    def test_metadata(self, check):
        assert check.name == "cag_multi_layer_cache"
        assert "cache_layers" in check.produces

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Cache Quota Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheQuotaCheck:
    @pytest.fixture
    def check(self):
        return CacheQuotaCheck()

    def test_metadata(self, check):
        assert check.name == "cag_cache_quota"
        assert "cache_size" in check.produces

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Provider Caching Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestProviderCachingCheck:
    @pytest.fixture
    def check(self):
        return ProviderCachingCheck()

    def test_metadata(self, check):
        assert check.name == "cag_provider_caching"
        assert "provider_cache_info" in check.produces
        assert check.intrusive is False

    @pytest.mark.asyncio
    async def test_detects_cached_tokens(self, check, sample_service, cag_endpoint_context):
        async def mock_post(url, **kwargs):
            return make_response(
                status_code=200,
                body='{"usage": {"cached_tokens": 150, "prompt_tokens": 300}, "choices": []}',
            )

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.provider_caching.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        provider_info = result.outputs.get("provider_cache_info", [])
        assert len(provider_info) > 0
        assert provider_info[0]["caching_detected"]

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0
