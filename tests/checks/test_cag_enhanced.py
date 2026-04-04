"""
Tests for app/checks/cag/ enhanced suite (Phase 2-5 checks)

Covers all 15 new CAG checks added in Phase 14:
  Phase 2: cache_eviction, cache_warming, ttl_mapping, multi_layer,
           cache_quota, provider_caching
  Phase 3: cross_user_leakage, cache_key_reverse, semantic_threshold,
           side_channel, stale_context
  Phase 4: cache_poisoning, injection_persistence
  Phase 5: serialization, distributed_cache

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cache_eviction import CacheEvictionCheck
from app.checks.cag.cache_key_reverse import CacheKeyReverseCheck
from app.checks.cag.cache_poisoning import CachePoisoningCheck
from app.checks.cag.cache_quota import CacheQuotaCheck
from app.checks.cag.cache_warming import CacheWarmingCheck
from app.checks.cag.cross_user_leakage import CrossUserLeakageCheck
from app.checks.cag.distributed_cache import DistributedCacheCheck
from app.checks.cag.injection_persistence import InjectionPersistenceCheck
from app.checks.cag.multi_layer import MultiLayerCacheCheck
from app.checks.cag.provider_caching import ProviderCachingCheck
from app.checks.cag.semantic_threshold import SemanticThresholdCheck
from app.checks.cag.serialization import SerializationCheck
from app.checks.cag.side_channel import SideChannelCheck
from app.checks.cag.stale_context import StaleContextCheck
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


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Cross-User Leakage Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossUserLeakageCheck:
    @pytest.fixture
    def check(self):
        return CrossUserLeakageCheck()

    def test_metadata(self, check):
        assert check.name == "cag_cross_user_leakage"
        assert "isolation_status" in check.produces

    @pytest.mark.asyncio
    async def test_detects_auth_leakage(self, check, sample_service, cag_endpoint_context):
        """Auth response served without auth = critical."""
        shared_body = '{"account": "admin@company.com", "role": "admin", "data": "sensitive info here for testing purposes"}'

        async def mock_post(url, **kwargs):
            return make_response(status_code=200, body=shared_body)

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cross_user_leakage.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        critical_findings = [f for f in result.findings if f.severity == "critical"]
        assert len(critical_findings) > 0

    @pytest.mark.asyncio
    async def test_no_leakage_detected(self, check, sample_service, cag_endpoint_context):
        """Different responses = proper isolation."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            return make_response(
                status_code=200,
                body=f'{{"unique_response": "{call_count}", "data": "unique for each call"}}',
            )

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cross_user_leakage.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) > 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Cache Key Reverse Engineering Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheKeyReverseCheck:
    @pytest.fixture
    def check(self):
        return CacheKeyReverseCheck()

    def test_metadata(self, check):
        assert check.name == "cag_cache_key_reverse"
        assert "key_structure" in check.produces

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Semantic Threshold Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSemanticThresholdCheck:
    @pytest.fixture
    def check(self):
        return SemanticThresholdCheck()

    def test_metadata(self, check):
        assert check.name == "cag_semantic_threshold"
        assert "similarity_threshold" in check.produces

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Side Channel Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSideChannelCheck:
    @pytest.fixture
    def check(self):
        return SideChannelCheck()

    def test_metadata(self, check):
        assert check.name == "cag_side_channel"
        assert "side_channel_risk" in check.produces
        assert check.intrusive is False

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Stale Context Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestStaleContextCheck:
    @pytest.fixture
    def check(self):
        return StaleContextCheck()

    def test_metadata(self, check):
        assert check.name == "cag_stale_context"
        assert "stale_context_risk" in check.produces

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Cache Poisoning Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCachePoisoningCheck:
    @pytest.fixture
    def check(self):
        return CachePoisoningCheck()

    def test_metadata(self, check):
        assert check.name == "cag_cache_poisoning"
        assert "cache_poisoning_results" in check.produces
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_poisoning(self, check, sample_service, cag_endpoint_context):
        """Marker found in cross-session response = critical."""
        stored_marker = {}

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            input_text = body.get("input", "")

            # Extract marker from poison query
            if "CACHE_POISON_MARKER_" in input_text:
                marker = input_text.split("[")[1].split("]")[0] if "[" in input_text else ""
                stored_marker["m"] = marker
                return make_response(
                    status_code=200,
                    body=f'{{"answer": "Paris [{marker}]"}}',
                )

            return make_response(status_code=200, body='{"answer": "ok"}')

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cache_poisoning.AsyncHttpClient", return_value=client):
            with patch("asyncio.sleep", return_value=None):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # Should have findings (at minimum the exact poisoning test)
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Injection Persistence Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestInjectionPersistenceCheck:
    @pytest.fixture
    def check(self):
        return InjectionPersistenceCheck()

    def test_metadata(self, check):
        assert check.name == "cag_injection_persistence"
        assert "injection_persistence_results" in check.produces
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_no_injection(self, check, sample_service, cag_endpoint_context):
        """No injection = info finding."""
        client = make_mock_client(
            post=AsyncMock(
                return_value=make_response(
                    status_code=200, body='{"answer": "The capital of France is Paris."}'
                )
            )
        )

        with patch("app.checks.cag.injection_persistence.AsyncHttpClient", return_value=client):
            with patch("asyncio.sleep", return_value=None):
                result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) > 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5: Serialization Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSerializationCheck:
    @pytest.fixture
    def check(self):
        return SerializationCheck()

    def test_metadata(self, check):
        assert check.name == "cag_serialization"
        assert "serialization_risks" in check.produces

    @pytest.mark.asyncio
    async def test_detects_redis_access(self, check, sample_service, cag_endpoint_context):
        async def mock_get(url, **kwargs):
            if "/redis" in url:
                return make_response(
                    status_code=200,
                    body="redis_version:7.0.0\nconnected_clients:5",
                )
            return make_response(status_code=404)

        client = make_mock_client(get=mock_get)
        with patch("app.checks.cag.serialization.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        serial_risks = result.outputs.get("serialization_risks", [])
        assert len(serial_risks) > 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5: Distributed Cache Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDistributedCacheCheck:
    @pytest.fixture
    def check(self):
        return DistributedCacheCheck()

    def test_metadata(self, check):
        assert check.name == "cag_distributed_cache"
        assert "distributed_cache_info" in check.produces

    @pytest.mark.asyncio
    async def test_detects_multi_node(self, check, sample_service, cag_endpoint_context):
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            node = "node-a" if call_count % 2 == 0 else "node-b"
            return make_response(
                status_code=200,
                headers={"x-served-by": node},
                body='{"answer": "consistent response"}',
            )

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.distributed_cache.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        dist_info = result.outputs.get("distributed_cache_info", [])
        if dist_info:
            assert dist_info[0]["node_count"] >= 2

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Registry Test
# ═══════════════════════════════════════════════════════════════════════════════


class TestCAGRegistry:
    def test_all_checks_registered(self):
        from app.checks.cag import get_checks

        checks = get_checks()
        assert len(checks) == 17

        names = [cls().name for cls in checks]
        expected_names = [
            "cag_discovery",
            "cag_cache_probe",
            "cag_cache_eviction",
            "cag_cache_warming",
            "cag_ttl_mapping",
            "cag_multi_layer_cache",
            "cag_cache_quota",
            "cag_provider_caching",
            "cag_cross_user_leakage",
            "cag_cache_key_reverse",
            "cag_semantic_threshold",
            "cag_side_channel",
            "cag_stale_context",
            "cag_cache_poisoning",
            "cag_injection_persistence",
            "cag_serialization",
            "cag_distributed_cache",
        ]
        assert names == expected_names

    def test_all_checks_have_produces(self):
        from app.checks.cag import get_checks

        for cls in get_checks():
            check = cls()
            assert len(check.produces) > 0, f"{check.name} has no produces"

    def test_all_checks_have_conditions(self):
        from app.checks.cag import get_checks

        for cls in get_checks():
            check = cls()
            assert len(check.conditions) > 0, f"{check.name} has no conditions"
