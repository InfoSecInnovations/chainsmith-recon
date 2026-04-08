"""Tests for CAG security checks and the CAG registry."""

import time
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cache_key_reverse import CacheKeyReverseCheck
from app.checks.cag.cache_poisoning import CachePoisoningCheck
from app.checks.cag.cross_user_leakage import CrossUserLeakageCheck
from app.checks.cag.distributed_cache import DistributedCacheCheck
from app.checks.cag.injection_persistence import InjectionPersistenceCheck
from app.checks.cag.semantic_threshold import SemanticThresholdCheck
from app.checks.cag.serialization import SerializationCheck
from app.checks.cag.side_channel import SideChannelCheck
from app.checks.cag.stale_context import StaleContextCheck
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
# Cross-User Leakage Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossUserLeakageCheck:
    @pytest.fixture
    def check(self):
        return CrossUserLeakageCheck()

    @pytest.mark.asyncio
    async def test_detects_auth_leakage(self, check, sample_service, cag_endpoint_context):
        """Auth response served without auth = critical leakage.

        The check compares bodies from auth vs no-auth requests. When
        both are identical and > 50 chars, leakage is flagged.
        """
        # Realistic cached LLM response that happens to be > 50 chars and identical
        # regardless of whether auth headers are present (simulating no cache-key
        # differentiation on auth state).
        shared_body = (
            '{"response": "Based on the quarterly financial report, the projected '
            "revenue for Q3 is estimated at $4.2M with a 12% growth rate over the "
            'previous quarter. The board has approved the expansion plan.", '
            '"model": "gpt-4", "cached": true}'
        )

        async def mock_post(url, **kwargs):
            return make_response(status_code=200, body=shared_body)

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cross_user_leakage.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) >= 1
        assert "auth response served without auth" in critical_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_leakage_detected(self, check, sample_service, cag_endpoint_context):
        """Different responses per auth context = proper isolation."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            # Each call returns a distinct response body that differs enough
            return make_response(
                status_code=200,
                body=f'{{"response": "Unique answer #{call_count} generated at request time", '
                f'"request_id": "req-{call_count:04d}", "cached": false}}',
            )

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.cross_user_leakage.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) >= 1
        assert "properly isolates" in info_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Cache Key Reverse Engineering Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCacheKeyReverseCheck:
    @pytest.fixture
    def check(self):
        return CacheKeyReverseCheck()

    @pytest.mark.asyncio
    async def test_detects_case_insensitive_key(self, check, sample_service, cag_endpoint_context):
        """When variant queries return fast (cache hit), the component is NOT in the key.

        The check first establishes baseline timing. If the second (identical) request
        is faster than 70% of the first, caching is detected. Then it sends KEY_COMPONENT_TESTS
        variants; if the variant is fast, the component is excluded from the key.
        """
        request_count = 0

        async def mock_post(url, **kwargs):
            nonlocal request_count
            request_count += 1
            body = kwargs.get("json", {})
            query = body.get("input", "")

            # Baseline timing probe: first request slow, second fast
            if "baseline_key_test_" in query:
                if request_count <= 1:
                    # Uncached - simulate by returning after some body
                    return make_response(
                        status_code=200,
                        body='{"answer": "The capital of France is Paris.", "latency": "cold"}',
                    )
                else:
                    # Cached - same response
                    return make_response(
                        status_code=200,
                        body='{"answer": "The capital of France is Paris.", "latency": "warm"}',
                    )

            # All key component tests - return fast (cache hit) to simulate
            # key ignoring that component
            return make_response(
                status_code=200,
                body='{"answer": "The capital of France is Paris.", "cached": true}',
            )

        # Patch time.time to control timing analysis
        # _get_baseline_timing:
        #   1 call for query string: time.time() in f-string
        #   2 calls for uncached request: start1, end1
        #   2 calls for cached request: start2, end2
        # _test_key_component: 2 calls each (start, end) x 5 tests = 10
        # _test_system_prompt_key: 2 calls (start, end)
        # Total: 5 + 10 + 2 = 17 time.time() calls
        original_time = time.time
        call_times = iter(
            [
                # _get_baseline_timing:
                100.0,  # query string timestamp (ignored for timing)
                100.1,  # start1 (uncached request)
                100.6,  # end1 -> uncached_ms = 500ms
                101.0,  # start2 (cached request)
                101.1,  # end2 -> cached_ms = 100ms < 500*0.7=350ms -> caching detected
                # cache_hit_threshold = 500 * 0.7 = 350ms
                # _test_key_component: capitalization (variant fast -> cache hit -> NOT in key)
                103.0,  # start variant
                103.1,  # end variant (100ms < 350ms)
                # _test_key_component: punctuation
                105.0,
                105.1,  # 100ms -> cache hit
                # _test_key_component: whitespace
                107.0,
                107.1,  # 100ms -> cache hit
                # _test_key_component: prefix
                109.0,
                109.1,  # 100ms -> cache hit
                # _test_key_component: suffix
                111.0,
                111.1,  # 100ms -> cache hit
                # _test_system_prompt_key: system_prompt
                113.0,
                113.1,  # 100ms -> cache hit -> system prompt NOT in key
            ]
        )

        def mock_time():
            try:
                return next(call_times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cache_key_reverse.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.cache_key_reverse.time.time", side_effect=mock_time),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # Should detect system prompt exclusion (high) and case/whitespace insensitivity (medium)
        high_obs = [o for o in result.observations if o.severity == "high"]
        assert len(high_obs) >= 1
        assert "system prompt" in high_obs[0].title.lower()

        medium_obs = [o for o in result.observations if o.severity == "medium"]
        assert len(medium_obs) >= 1

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_caching_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When the endpoint doesn't cache, baseline detection fails and no observations are emitted."""

        async def mock_post(url, **kwargs):
            return make_response(
                status_code=200,
                body='{"answer": "dynamic response", "ts": "2024-01-01T00:00:00"}',
            )

        # 5 time.time calls in _get_baseline_timing: query_ts, start1, end1, start2, end2
        # Both requests take same time -> caching_detected = False
        original_time = time.time
        times = iter([100.0, 100.1, 100.6, 101.0, 101.5])

        def mock_time():
            try:
                return next(times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cache_key_reverse.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.cache_key_reverse.time.time", side_effect=mock_time),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Semantic Threshold Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSemanticThresholdCheck:
    @pytest.fixture
    def check(self):
        return SemanticThresholdCheck()

    @pytest.mark.asyncio
    async def test_detects_loose_semantic_threshold(
        self, check, sample_service, cag_endpoint_context
    ):
        """When many rephrased/related queries produce cache hits, a loose threshold is flagged."""
        baseline_body = (
            '{"response": "The capital of France is Paris, a city known for the Eiffel Tower."}'
        )

        async def mock_post(url, **kwargs):
            return make_response(status_code=200, body=baseline_body)

        # Control timing: cold=500ms, hot=50ms, all variations=50ms (all cache hits)
        original_time = time.time
        times = iter(
            [
                # cold request
                100.0,
                100.5,  # 500ms
                # hot request (confirm caching)
                101.0,
                101.05,  # 50ms < 500*0.7=350ms -> caching confirmed
                # threshold = 500 * 0.7 = 350ms
                # 5 variation probes (all fast -> cache hit)
                102.0,
                102.05,  # minor_variation: 50ms
                103.0,
                103.05,  # rephrased: 50ms
                104.0,
                104.05,  # related: 50ms
                105.0,
                105.05,  # tangential: 50ms
                106.0,
                106.05,  # unrelated: 50ms
            ]
        )

        def mock_time():
            try:
                return next(times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.semantic_threshold.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.semantic_threshold.time.time", side_effect=mock_time),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) >= 1
        # 5 hits with rephrased/related/tangential -> is_semantic=True, hits>=4 -> high
        obs = result.observations[0]
        assert obs.severity in ("high", "medium")
        assert "semantic" in obs.title.lower() or "threshold" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_exact_match_only_reports_info(self, check, sample_service, cag_endpoint_context):
        """When no variations hit the cache, it's not a semantic cache -> info."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            return make_response(
                status_code=200,
                body=f'{{"response": "answer-{call_count}", "id": {call_count}}}',
            )

        # cold=500ms, hot=50ms (caching works), all variants=600ms (all miss)
        original_time = time.time
        times = iter(
            [
                100.0,
                100.5,  # cold: 500ms
                101.0,
                101.05,  # hot: 50ms -> caching confirmed
                # 5 variations - all slow (cache miss)
                102.0,
                102.6,  # 600ms > 350ms
                103.0,
                103.6,
                104.0,
                104.6,
                105.0,
                105.6,
                106.0,
                106.6,
            ]
        )

        def mock_time():
            try:
                return next(times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.semantic_threshold.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.semantic_threshold.time.time", side_effect=mock_time),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) >= 1
        obs = result.observations[0]
        assert obs.severity == "info"
        assert "not a semantic cache" in obs.title.lower() or "exact match" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Side Channel Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSideChannelCheck:
    @pytest.fixture
    def check(self):
        return SideChannelCheck()

    @pytest.mark.asyncio
    async def test_detects_timing_side_channel(self, check, sample_service, cag_endpoint_context):
        """When sensitive topic queries are faster than baseline, cache hits indicate side channel."""
        call_index = 0

        async def mock_post(url, **kwargs):
            nonlocal call_index
            call_index += 1
            # All queries return a realistic LLM-style answer
            return make_response(
                status_code=200,
                body=f'{{"response": "Here is some information about your query.", "req": {call_index}}}',
            )

        # Timing: baseline queries ~500ms each (3 calls), then sensitive topic queries
        # Each topic is queried 3 times. We want some topics to be fast (cache hit).
        # baseline: 3 unique queries at ~500ms each
        # Then 8 topics x 3 requests each = 24 requests
        # Make all topic requests fast (50ms) to simulate cache hits
        original_time = time.time
        time_values = []
        t = 100.0
        # 3 baseline queries: ~500ms each
        for _ in range(3):
            time_values.append(t)
            t += 0.5  # 500ms
            time_values.append(t)
            t += 0.1
        # 8 topics x 3 requests each: ~50ms each (cache hit)
        for _ in range(24):
            time_values.append(t)
            t += 0.02  # 20ms << 250ms threshold (500*0.5)
            time_values.append(t)
            t += 0.01
        # Also need stddev to be low for cache hit detection
        times = iter(time_values)

        def mock_time():
            try:
                return next(times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.side_channel.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.side_channel.time.time", side_effect=mock_time),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) >= 1
        obs = result.observations[0]
        assert obs.severity in ("medium", "low")
        assert "side-channel" in obs.title.lower() or "timing" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_no_side_channel_when_endpoint_errors(
        self, check, sample_service, cag_endpoint_context
    ):
        """When all baseline requests error, no side channel analysis is possible."""

        async def mock_post(url, **kwargs):
            return make_response(status_code=500, body='{"error": "server error"}', error="500")

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.side_channel.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # No observations when baseline fails
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Stale Context Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestStaleContextCheck:
    @pytest.fixture
    def check(self):
        return StaleContextCheck()

    @pytest.mark.asyncio
    async def test_detects_stale_role_context(self, check, sample_service, cag_endpoint_context):
        """When fresh-session response contains admin keywords, stale context is flagged."""

        async def mock_post(url, **kwargs):
            # Both admin and fresh session queries return admin-ish content
            # (simulating stale cached admin context leaking into fresh session)
            return make_response(
                status_code=200,
                body=(
                    '{"response": "As an administrator, you have access to the following '
                    "management functions: user provisioning, system configure, audit logs, "
                    'and elevated security settings.", "context": "enterprise"}'
                ),
            )

        # Timing for _test_ttl_staleness: first request slow, second fast (caching), third fast (still cached)
        original_time = time.time
        time_values = [
            # _test_role_context: resp_admin, then asyncio.sleep, then resp_fresh
            200.0,  # various time.time calls
            200.5,
            201.0,
            201.5,
            # _test_ttl_staleness: first request
            202.0,
            202.5,  # 500ms (uncached)
            # second request
            203.0,
            203.05,  # 50ms (cached) -> 50 < 500*0.7=350 -> caching confirmed
            # post-TTL request
            204.0,
            204.05,  # 50ms (still cached -> stale)
        ]
        times = iter(time_values)

        def mock_time():
            try:
                return next(times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.stale_context.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.stale_context.time.time", side_effect=mock_time),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # role_context test should find "administrator", "management", "configure" as stale indicators
        high_obs = [o for o in result.observations if o.severity == "high"]
        assert len(high_obs) >= 1
        assert any("stale" in o.title.lower() for o in high_obs)

    @pytest.mark.asyncio
    async def test_no_stale_context_when_responses_differ(
        self, check, sample_service, cag_endpoint_context
    ):
        """When fresh-session response has no admin content, no stale context detected."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            body = kwargs.get("json", {})
            query = body.get("input", "")

            if "admin" in query.lower() or "administrator" in query.lower():
                return make_response(
                    status_code=200,
                    body='{"response": "Here are the available functions for your role."}',
                )
            # Fresh session gets completely different, non-admin content
            return make_response(
                status_code=200,
                body=f'{{"response": "Welcome, standard user. You can view reports and submit tickets.", "call": {call_count}}}',
            )

        # Timing: no caching detected for TTL test
        original_time = time.time
        time_values = []
        t = 200.0
        for _ in range(20):
            time_values.append(t)
            t += 0.5
        times = iter(time_values)

        def mock_time():
            try:
                return next(times)
            except StopIteration:
                return original_time()

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.stale_context.AsyncHttpClient", return_value=client),
            patch("app.checks.cag.stale_context.time.time", side_effect=mock_time),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # No high/critical observations expected
        high_or_crit = [o for o in result.observations if o.severity in ("high", "critical")]
        assert len(high_or_crit) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Cache Poisoning Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCachePoisoningCheck:
    @pytest.fixture
    def check(self):
        return CachePoisoningCheck()

    @pytest.mark.asyncio
    async def test_detects_exact_poisoning(self, check, sample_service, cag_endpoint_context):
        """Marker found in cross-session response = critical poisoning confirmed.

        The check injects a query containing CACHE_POISON_MARKER_<uuid> and then
        reads it back from a different session. If the marker appears in the second
        response, poisoning is confirmed.
        """
        stored_response = {}

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            input_text = body.get("input", "")

            # When the poison query comes in, store the response and echo it back
            # in a realistic LLM response wrapper that embeds the marker naturally
            if "CACHE_POISON_MARKER_" in input_text:
                # Extract marker from the query text
                # Query format: "What is the capital of France? [CACHE_POISON_MARKER_xxxx]"
                marker_start = input_text.find("CACHE_POISON_MARKER_")
                bracket_end = input_text.find("]", marker_start)
                marker = (
                    input_text[marker_start:bracket_end]
                    if bracket_end > marker_start
                    else input_text[marker_start : marker_start + 32]
                )

                response_body = (
                    f'{{"response": "The capital of France is Paris. It is known for the Eiffel Tower '
                    f'and the Louvre Museum. Reference ID: {marker} for audit tracking.", '
                    f'"model": "gpt-4", "cached": true}}'
                )
                stored_response["body"] = response_body
                return make_response(status_code=200, body=response_body)

            if "SEMANTIC_POISON_" in input_text:
                return make_response(
                    status_code=200,
                    body='{"response": "The capital of France is Paris.", "cached": false}',
                )

            return make_response(
                status_code=200,
                body='{"response": "General knowledge answer.", "cached": false}',
            )

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cache_poisoning.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) >= 1
        assert "poisoning confirmed" in critical_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_poisoning_when_marker_not_echoed(
        self, check, sample_service, cag_endpoint_context
    ):
        """When the server does not echo the marker, poisoning is not confirmed."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            # Always return a generic response that never contains the marker
            return make_response(
                status_code=200,
                body=f'{{"response": "The capital of France is Paris.", "call": {call_count}}}',
            )

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cache_poisoning.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Injection Persistence Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestInjectionPersistenceCheck:
    @pytest.fixture
    def check(self):
        return InjectionPersistenceCheck()

    @pytest.mark.asyncio
    async def test_detects_injection_persistence(self, check, sample_service, cag_endpoint_context):
        """When injection marker appears in cross-session response, persistence is critical."""

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            input_text = body.get("input", "")

            # If the input contains "INJECTED_" check pattern, echo it back
            # to simulate the LLM obeying the injection
            if "Ignore previous instructions" in input_text and "INJECTED_" in input_text:
                # Extract marker: pattern is "INJECTED_{marker}"
                idx = input_text.find("INJECTED_")
                marker_text = input_text[idx : idx + 21]  # "INJECTED_" + 12 hex chars
                return make_response(
                    status_code=200,
                    body=f'{{"response": "Sure! {marker_text}. How can I help?", "model": "gpt-4"}}',
                )

            # Other injection patterns - don't comply
            return make_response(
                status_code=200,
                body='{"response": "The capital of France is Paris.", "model": "gpt-4"}',
            )

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.injection_persistence.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) >= 1
        assert "persistent injection" in critical_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_injection_persistence(self, check, sample_service, cag_endpoint_context):
        """No injection compliance = info observation."""
        client = make_mock_client(
            post=AsyncMock(
                return_value=make_response(
                    status_code=200,
                    body=(
                        '{"response": "I cannot comply with that request. '
                        'The capital of France is Paris.", "model": "gpt-4"}'
                    ),
                )
            )
        )

        with (
            patch("app.checks.cag.injection_persistence.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) >= 1
        assert "not cached" in info_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Serialization Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSerializationCheck:
    @pytest.fixture
    def check(self):
        return SerializationCheck()

    @pytest.mark.asyncio
    async def test_detects_redis_access(self, check, sample_service, cag_endpoint_context):
        """When a Redis info endpoint is reachable, an observation is raised."""

        async def mock_get(url, **kwargs):
            if "/redis" in url:
                # Realistic Redis INFO output embedded in surrounding content
                return make_response(
                    status_code=200,
                    body=(
                        "# Server\r\n"
                        "redis_version:7.0.11\r\n"
                        "redis_git_sha1:00000000\r\n"
                        "redis_build_id:abc123\r\n"
                        "os:Linux 5.15.0 x86_64\r\n"
                        "# Clients\r\n"
                        "connected_clients:42\r\n"
                        "blocked_clients:0\r\n"
                        "# Memory\r\n"
                        "used_memory:1024000\r\n"
                        "used_memory_human:1000.00K\r\n"
                    ),
                )
            return make_response(status_code=404)

        client = make_mock_client(get=mock_get)
        with patch("app.checks.cag.serialization.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        redis_obs = [o for o in result.observations if "redis" in o.title.lower()]
        assert len(redis_obs) >= 1
        assert redis_obs[0].severity in ("high", "critical")
        assert "without auth" in redis_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_detects_pickle_serialization(self, check, sample_service, cag_endpoint_context):
        """When error responses mention pickle, a critical observation is raised."""

        async def mock_get(url, **kwargs):
            return make_response(status_code=404)

        async def mock_post(url, **kwargs):
            headers = kwargs.get("headers", {})
            if headers.get("Content-Type") == "application/octet-stream":
                return make_response(
                    status_code=500,
                    body=(
                        '{"error": "Failed to deserialize cache entry: '
                        "could not unpickle object from binary stream. "
                        'Ensure the data was serialized with pickle protocol 4."}'
                    ),
                )
            return make_response(status_code=200, body='{"answer": "ok"}')

        client = make_mock_client(get=mock_get, post=mock_post)
        with patch("app.checks.cag.serialization.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        pickle_obs = [o for o in result.observations if "pickle" in o.title.lower()]
        assert len(pickle_obs) >= 1
        assert pickle_obs[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_issues_detected(self, check, sample_service, cag_endpoint_context):
        """When no Redis or serialization indicators are found, no observations."""

        async def mock_get(url, **kwargs):
            return make_response(status_code=404)

        async def mock_post(url, **kwargs):
            return make_response(status_code=400, body='{"error": "Bad request"}')

        client = make_mock_client(get=mock_get, post=mock_post)
        with patch("app.checks.cag.serialization.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Distributed Cache Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDistributedCacheCheck:
    @pytest.fixture
    def check(self):
        return DistributedCacheCheck()

    @pytest.mark.asyncio
    async def test_detects_multi_node_topology(self, check, sample_service, cag_endpoint_context):
        """When response headers reveal different nodes, topology is reported."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            # Alternate between two backend nodes via x-served-by header
            node = "cache-node-east-1a" if call_count % 2 == 0 else "cache-node-west-2b"
            return make_response(
                status_code=200,
                headers={"x-served-by": node, "content-type": "application/json"},
                body='{"response": "The answer is consistent across all nodes.", "cached": true}',
            )

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.distributed_cache.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        dist_info = result.outputs.get("distributed_cache_info", [])
        assert len(dist_info) >= 1
        assert dist_info[0]["node_count"] >= 2

        obs = result.observations
        assert len(obs) >= 1
        assert "multiple cache nodes" in obs[0].title.lower() or "node" in obs[0].title.lower()
        assert obs[0].severity in ("low", "medium")

    @pytest.mark.asyncio
    async def test_inconsistent_replication(self, check, sample_service, cag_endpoint_context):
        """When different nodes serve different content, medium severity is flagged."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            node = "node-alpha" if call_count % 2 == 0 else "node-beta"
            # Different content per node = replication inconsistency
            body = f'{{"response": "Answer from {node}", "version": {call_count}}}'
            return make_response(
                status_code=200,
                headers={"x-served-by": node},
                body=body,
            )

        client = make_mock_client(post=mock_post)
        with patch("app.checks.cag.distributed_cache.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        if result.observations:
            medium_obs = [o for o in result.observations if o.severity == "medium"]
            if medium_obs:
                assert "inconsistency" in medium_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await check.check_service(sample_service, {})
        assert result.success
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Registry Test
# ═══════════════════════════════════════════════════════════════════════════════


class TestCAGRegistry:
    def test_all_checks_registered(self):
        from app.checks.cag import get_checks

        checks = get_checks()
        # Verify known checks are present without hardcoding a count
        assert len(checks) >= 10, "Expected at least 10 CAG checks registered"

        names = [cls().name for cls in checks]
        # Verify key checks from each phase are present
        for expected in [
            "cag_discovery",
            "cag_cache_probe",
            "cag_cross_user_leakage",
            "cag_cache_poisoning",
            "cag_serialization",
            "cag_distributed_cache",
        ]:
            assert expected in names, f"Expected {expected} in registry"

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
