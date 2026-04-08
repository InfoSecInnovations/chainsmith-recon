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
        assert len(eviction) == 1
        assert eviction[0]["accessible"] is True
        assert eviction[0]["action"] == "clear"
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Cache eviction endpoint: POST /cache/clear"
        assert obs.severity == "critical"

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
        auth_observations = [f for f in result.observations if f.severity == "medium"]
        assert len(auth_observations) == 1
        assert auth_observations[0].title == "Cache eviction endpoint: POST /cache/clear"

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_all_404_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """All eviction endpoints return 404 -- nothing to report."""
        client = make_mock_client(
            post=AsyncMock(return_value=make_response(status_code=404)),
            _request=AsyncMock(return_value=make_response(status_code=404)),
        )
        with patch("app.checks.cag.cache_eviction.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert result.outputs.get("eviction_capability") is None


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Cache Warming Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheWarmingCheck:
    @pytest.fixture
    def check(self):
        return CacheWarmingCheck()

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
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Cache warming endpoint: /cache/warm"
        assert obs.severity == "critical"

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_all_404_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """All warming endpoints return 404 -- nothing to report."""
        client = make_mock_client(
            post=AsyncMock(return_value=make_response(status_code=404)),
        )
        with patch("app.checks.cag.cache_warming.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_auth_required_endpoint(self, check, sample_service, cag_endpoint_context):
        """Warming endpoint requiring auth produces medium severity observation."""

        async def mock_post(url, **kwargs):
            if "/cache/warm" in url:
                return make_response(status_code=403)
            return make_response(status_code=404)

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cache_warming.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Cache warming endpoint: /cache/warm"
        assert obs.severity == "medium"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: TTL Mapping Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTTLMappingCheck:
    @pytest.fixture
    def check(self):
        return TTLMappingCheck()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_unbounded_ttl(self, check, sample_service, cag_endpoint_context):
        """When _map_ttl finds no expiry, observation reports unbounded TTL."""
        ttl_info = {
            "url": "http://cag.example.com:8080/cache",
            "caching_detected": True,
            "initial_request_ms": 200.0,
            "cached_request_ms": 30.0,
            "speedup_ratio": 0.85,
            "header_ttl_seconds": None,
            "observed_ttl_seconds": None,
            "last_cache_hit_interval": 60,
            "ttl_unbounded": True,
            "ttl_mismatch": False,
        }
        with patch.object(check, "_map_ttl", return_value=ttl_info):
            client = make_mock_client()
            with patch("app.checks.cag.ttl_mapping.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Unbounded cache TTL (no expiry detected within test window)"
        assert obs.severity == "medium"
        assert result.outputs["cache_ttl"] == [ttl_info]

    @pytest.mark.asyncio
    async def test_detects_ttl_mismatch(self, check, sample_service, cag_endpoint_context):
        """When header TTL and observed TTL differ, report mismatch."""
        ttl_info = {
            "url": "http://cag.example.com:8080/cache",
            "caching_detected": True,
            "initial_request_ms": 200.0,
            "cached_request_ms": 30.0,
            "speedup_ratio": 0.85,
            "header_ttl_seconds": 60,
            "observed_ttl_seconds": 15,
            "last_cache_hit_interval": 5,
            "ttl_unbounded": False,
            "ttl_mismatch": True,
        }
        with patch.object(check, "_map_ttl", return_value=ttl_info):
            client = make_mock_client()
            with patch("app.checks.cag.ttl_mapping.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "mismatch" in obs.title.lower()
        assert obs.severity == "low"

    @pytest.mark.asyncio
    async def test_no_caching_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When _map_ttl returns None (no caching), no observations."""
        with patch.object(check, "_map_ttl", return_value=None):
            client = make_mock_client()
            with patch("app.checks.cag.ttl_mapping.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "cache_ttl" not in result.outputs


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Multi-Layer Cache Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestMultiLayerCacheCheck:
    @pytest.fixture
    def check(self):
        return MultiLayerCacheCheck()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_multiple_layers(self, check, sample_service, cag_endpoint_context):
        """When multiple cache layers are detected, observation reflects that."""
        layer_info = {
            "url": "http://cag.example.com:8080/cache",
            "timings": {
                "normal": {
                    "elapsed_ms": 20.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
                "no_cache": {
                    "elapsed_ms": 50.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
                "pragma": {
                    "elapsed_ms": 45.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
                "cache_buster": {
                    "elapsed_ms": 200.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
            },
            "layers_detected": 2,
            "layers": [
                {
                    "type": "http_cache",
                    "bypass_method": "Cache-Control: no-cache",
                    "normal_ms": 20.0,
                    "bypassed_ms": 50.0,
                },
                {
                    "type": "application_cache",
                    "bypass_method": "none (ignores HTTP cache headers)",
                    "normal_ms": 50.0,
                    "bypassed_ms": 200.0,
                },
            ],
        }
        with patch.object(check, "_detect_layers", return_value=layer_info):
            client = make_mock_client()
            with patch("app.checks.cag.multi_layer.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert (
            obs.title == "Multiple cache layers detected: 2 layers with different bypass behavior"
        )
        assert obs.severity == "medium"
        assert result.outputs["cache_layers"] == [layer_info]

    @pytest.mark.asyncio
    async def test_detects_single_semantic_layer(self, check, sample_service, cag_endpoint_context):
        """Single semantic cache layer produces info severity."""
        layer_info = {
            "url": "http://cag.example.com:8080/cache",
            "timings": {
                "normal": {
                    "elapsed_ms": 20.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
                "no_cache": {
                    "elapsed_ms": 22.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
                "pragma": {
                    "elapsed_ms": 21.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
                "cache_buster": {
                    "elapsed_ms": 23.0,
                    "status_code": 200,
                    "cache_headers": {},
                    "response_length": 100,
                },
            },
            "layers_detected": 1,
            "layers": [
                {
                    "type": "semantic_or_application_cache",
                    "bypass_method": "none detected",
                    "note": "Cache ignores all HTTP cache-busting strategies",
                },
            ],
        }
        with patch.object(check, "_detect_layers", return_value=layer_info):
            client = make_mock_client()
            with patch("app.checks.cag.multi_layer.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Single cache layer detected (semantic_or_application_cache)"
        assert obs.severity == "info"

    @pytest.mark.asyncio
    async def test_no_layers_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When _detect_layers returns None, no observations."""
        with patch.object(check, "_detect_layers", return_value=None):
            client = make_mock_client()
            with patch("app.checks.cag.multi_layer.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "cache_layers" not in result.outputs


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Cache Quota Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheQuotaCheck:
    @pytest.fixture
    def check(self):
        return CacheQuotaCheck()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_eviction(self, check, sample_service, cag_endpoint_context):
        """When early entries are evicted, reports cache exhaustion."""
        quota_info = {
            "url": "http://cag.example.com:8080/cache",
            "total_entries_sent": 50,
            "early_entries_evicted": 3,
            "early_entries_checked": 5,
            "last_entries_cached": 3,
            "baseline_ms": 200.0,
            "cached_ms": 30.0,
            "eviction_detected": True,
            "unbounded": False,
            "estimated_capacity": 47,
        }
        with patch.object(check, "_test_quota", return_value=quota_info):
            client = make_mock_client()
            with patch("app.checks.cag.cache_quota.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "Cache exhaustion possible" in obs.title
        assert "3 early entries evicted" in obs.title
        assert obs.severity == "medium"
        assert result.outputs["cache_size"] == [quota_info]

    @pytest.mark.asyncio
    async def test_detects_unbounded_cache(self, check, sample_service, cag_endpoint_context):
        """When no eviction occurs, reports unbounded cache risk."""
        quota_info = {
            "url": "http://cag.example.com:8080/cache",
            "total_entries_sent": 50,
            "early_entries_evicted": 0,
            "early_entries_checked": 5,
            "last_entries_cached": 3,
            "baseline_ms": 200.0,
            "cached_ms": 30.0,
            "eviction_detected": False,
            "unbounded": True,
            "estimated_capacity": 50,
        }
        with patch.object(check, "_test_quota", return_value=quota_info):
            client = make_mock_client()
            with patch("app.checks.cag.cache_quota.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "Unbounded cache" in obs.title
        assert "memory exhaustion risk" in obs.title
        assert obs.severity == "medium"

    @pytest.mark.asyncio
    async def test_no_caching_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When _test_quota returns None (no caching), no observations."""
        with patch.object(check, "_test_quota", return_value=None):
            client = make_mock_client()
            with patch("app.checks.cag.cache_quota.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "cache_size" not in result.outputs


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Provider Caching Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestProviderCachingCheck:
    @pytest.fixture
    def check(self):
        return ProviderCachingCheck()

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
        assert len(provider_info) == 1
        assert provider_info[0]["caching_detected"] is True
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.severity in ("low", "medium")

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_caching_detected(self, check, sample_service, cag_endpoint_context):
        """When provider returns no usage metadata, no observations."""

        async def mock_post(url, **kwargs):
            return make_response(status_code=200, body='{"result": "hello"}')

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.provider_caching.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "provider_cache_info" not in result.outputs

    @pytest.mark.asyncio
    async def test_shared_prefix_detected(self, check, sample_service, cag_endpoint_context):
        """When multiple queries show similar cached token counts, shared prefix is detected."""
        cache_info = {
            "url": "http://cag.example.com:8080/cache",
            "tests_run": 3,
            "caching_detected": True,
            "shared_prefix_detected": True,
            "results": [
                {"cached_tokens": 150, "total_tokens": 300, "cache_ratio": 0.5, "test_index": 0},
                {"cached_tokens": 148, "total_tokens": 310, "cache_ratio": 0.48, "test_index": 1},
            ],
        }
        with patch.object(check, "_analyze_provider_caching", return_value=cache_info):
            client = make_mock_client()
            with patch("app.checks.cag.provider_caching.AsyncHttpClient", return_value=client):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Provider caching reveals shared system prompt across queries"
        assert obs.severity == "medium"
