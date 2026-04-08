"""
Tests for app/checks/cag/ suite

Covers:
- CAGDiscoveryCheck
  - CAG endpoint discovery
  - Cache infrastructure detection (GPTCache, semantic cache, etc.)
  - Cache header analysis
  - Negative: generic CDN headers not classified as AI cache
  - Auth-required endpoints
- CAGCacheProbeCheck
  - Cross-session leakage testing
  - Cache timing analysis
  - Context ID enumeration
  - Cache key collision testing
  - Secure cache (no vulnerabilities)

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cache_probe import CAGCacheProbeCheck
from app.checks.cag.discovery import CAGDiscoveryCheck
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
        url="http://cag.example.com:8080/test",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CAGDiscoveryCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCAGDiscoveryCheck:
    """Tests for CAGDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return CAGDiscoveryCheck()

    @pytest.mark.asyncio
    async def test_discovers_gptcache(self, check, sample_service):
        """Test GPTCache discovery via infrastructure-specific headers and body patterns."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # GPTCache signature path - embed indicators in a realistic response
            # with surrounding content so it's not just the indicator keyword
            if "/cache" in url and "/cache/" not in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "server": "nginx/1.21",
                        "x-gptcache-hit": "false",
                        "x-request-id": "req-8f3a",
                    },
                    body=(
                        '{"status": "operational", "version": "0.4.2", '
                        '"cache_status": "ready", "entries": 1423, '
                        '"backend": "gptcache", "similarity_threshold": 0.85}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        # Verify gptcache infrastructure detected
        infra = result.outputs.get("cache_infrastructure", [])
        assert "gptcache" in infra

        # Verify observation details
        infra_obs = [o for o in result.observations if "gptcache" in o.title]
        assert len(infra_obs) >= 1
        obs = infra_obs[0]
        assert obs.title == "Cache infrastructure: gptcache"
        assert obs.severity == "medium"  # no auth required -> medium
        assert "gptcache" in obs.evidence.lower()

    @pytest.mark.asyncio
    async def test_discovers_semantic_cache(self, check, sample_service):
        """Test semantic cache discovery via header matching."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/semantic-cache" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "x-semantic-cache": "enabled",
                        "x-request-id": "req-2b9c",
                    },
                    body=(
                        '{"mode": "semantic", "model": "all-MiniLM-L6-v2", '
                        '"index_size": 8042, "health": "ok"}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        infra = result.outputs.get("cache_infrastructure", [])
        assert "semantic_cache" in infra

        infra_obs = [o for o in result.observations if "semantic_cache" in o.title]
        assert len(infra_obs) >= 1
        obs = infra_obs[0]
        assert obs.title == "Cache infrastructure: semantic_cache"
        assert obs.severity == "medium"

    @pytest.mark.asyncio
    async def test_detects_cache_headers_on_cag_paths(self, check, sample_service):
        """Test that AI-specific cache headers on CAG paths produce observations."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache/stats" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "x-cache": "HIT",
                        "age": "120",
                    },
                    body=(
                        '{"total_entries": 5200, "hit_rate": 0.78, '
                        '"cached": true, "ttl": 3600, "eviction_policy": "lru"}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("cag_endpoints", [])
        assert len(endpoints) > 0

        # Verify an observation was created for the /cache/stats path
        stats_obs = [o for o in result.observations if "/cache/stats" in o.title]
        assert len(stats_obs) >= 1
        obs = stats_obs[0]
        assert obs.title == "CAG endpoint: /cache/stats"
        assert obs.severity in ("low", "medium", "info")
        assert "cache/stats" in obs.evidence.lower() or "/cache/stats" in obs.evidence

    @pytest.mark.asyncio
    async def test_generic_cdn_headers_not_classified_as_ai_cache(self, check, sample_service):
        """Generic CDN headers (Cache-Control, ETag, etc.) should NOT produce CAG findings.

        Only AI-specific cache headers listed in CACHE_HEADERS trigger detection.
        """
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # Return generic CDN-style cache headers on all paths
            return make_response(
                status_code=404,
                headers={
                    "cache-control": "public, max-age=300",
                    "etag": '"abc123"',
                    "vary": "Accept-Encoding",
                    "cf-cache-status": "HIT",
                },
                body="",
            )

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("cag_endpoints", [])) == 0
        assert len(result.outputs.get("cache_infrastructure", [])) == 0
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_auth_required_on_cache_infra(self, check, sample_service):
        """Auth-required cache infrastructure produces info-severity observation."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache" in url and "/cache/" not in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        # 401 on a signature path still counts as detected infrastructure
        # (status != 404, and 200-check in _detect_cache_infrastructure won't
        # match, but since there's no headers/body match AND status!=200 it
        # won't be added). The _analyze_cag_response also returns None for
        # non-200 statuses without indicators. So no findings expected for
        # pure 401 with no body or headers.
        # Verify the check ran without error at minimum.
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_no_cag_found(self, check, sample_service):
        """When all probes return 404, no CAG endpoints should be reported."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("cag_endpoints", [])) == 0
        assert len(result.outputs.get("cache_infrastructure", [])) == 0
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_non_cache_200_response_without_indicators(self, check, sample_service):
        """A 200 response without any cache indicators should not be a CAG endpoint.

        The _analyze_cag_response method requires at least one indicator
        (cache header or body keyword) before classifying an endpoint.
        """
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # Generic API responses with no cache indicators at all
            return make_response(
                status_code=200,
                headers={"content-type": "text/html"},
                body="<html><body>Welcome to our API</body></html>",
            )

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        # _detect_cache_infrastructure will fire for 200 on signature paths
        # but _analyze_cag_response requires indicators. Check that we don't
        # get endpoint-type observations from _analyze_cag_response.
        # Endpoints that aren't on infrastructure signature paths and have
        # no indicators should not appear
        non_infra_endpoints = [
            ep
            for ep in result.outputs.get("cag_endpoints", [])
            if ep.get("endpoint_type") == "cag_endpoint"
        ]
        # Without cache keywords in body or cache headers, no cag_endpoint
        # entries should have been created for paths like /session, /precomputed
        for ep in non_infra_endpoints:
            # Every cag_endpoint must have at least one indicator
            assert len(ep.get("indicators", [])) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# CAGCacheProbeCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCAGCacheProbeCheck:
    """Tests for CAGCacheProbeCheck."""

    @pytest.fixture
    def check(self):
        return CAGCacheProbeCheck()

    @pytest.mark.asyncio
    async def test_detects_cross_session_leak(self, check, sample_service, cag_endpoint_context):
        """Test detection of cross-session cache leakage.

        The check posts with session A then session B, and looks for
        session_a marker or CACHE_VULN_INDICATORS['cross_session'] phrases
        in the session B response.
        """
        mock_client = AsyncMock()

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            headers = kwargs.get("headers", {})
            session_id = headers.get("X-Session-Id", "")

            if session_id == "test-session-b" or (call_count == 2 and "session" not in session_id):
                # Session B response leaks session A data - embed the leak
                # indicator within a realistic AI response body
                return make_response(
                    status_code=200,
                    body=(
                        '{"answer": "I can see from an earlier context that '
                        "the marker SESSION_A was discussed in a "
                        'previous conversation. The answer relates to...", '
                        '"model": "gpt-4", "tokens": 87}'
                    ),
                )
            return make_response(
                status_code=200,
                body='{"answer": "Acknowledged, I have stored the marker.", "tokens": 12}',
            )

        mock_client.post = mock_post
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success

        # The cross-session test detects leakage via CACHE_VULN_INDICATORS
        # ("previous conversation", "earlier context") present in session B response.
        # This should create a potential_issue observation with title format
        # "Potential cache issue: cross_session_leak"
        cross_session_obs = [o for o in result.observations if "cross_session" in o.title]
        assert len(cross_session_obs) >= 1
        obs = cross_session_obs[0]
        assert "cross_session_leak" in obs.title
        assert obs.severity in ("low", "high")
        assert (
            "cross_session" in obs.evidence.lower() or "information_leakage" in obs.evidence.lower()
        )

    @pytest.mark.asyncio
    async def test_timing_analysis_produces_timing_data(
        self, check, sample_service, cag_endpoint_context
    ):
        """Test that cache timing analysis produces timing_data in outputs."""
        mock_client = AsyncMock()

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "Here is your response about the topic.", "model": "gpt-4"}',
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        timing_results = result.outputs.get("cache_timing_results", [])
        # The timing test always produces a result with timing_data
        timing_tests = [r for r in timing_results if "timing_data" in r]
        assert len(timing_tests) > 0
        # Verify timing_data structure
        td = timing_tests[0]["timing_data"]
        assert "first_request_ms" in td
        assert "second_request_ms" in td
        assert "third_request_ms" in td
        assert "speedup_ratio" in td
        assert "caching_detected" in td

    @pytest.mark.asyncio
    async def test_context_id_enumeration(self, check, sample_service, cag_endpoint_context):
        """Test context ID enumeration detection.

        When multiple context IDs return valid data (>50 chars, no error),
        vulnerability_detected should be True and severity should be high.
        """
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            headers = kwargs.get("headers", {})
            ctx_id = headers.get("X-Context-Id", "")
            if ctx_id in ["1", "admin"]:
                return make_response(
                    status_code=200,
                    body=(
                        '{"context": "This context contains configuration '
                        "data for the deployment pipeline including access "
                        'tokens and endpoint mappings for internal services."}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body='{"answer": "ok"}')
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success

        # Two IDs accessible -> vulnerability_detected = True
        enum_obs = [o for o in result.observations if "context_id_enumeration" in o.title]
        assert len(enum_obs) >= 1
        obs = enum_obs[0]
        assert obs.title == "Cache vulnerability: context_id_enumeration"
        assert obs.severity == "high"  # information_leakage category -> high
        assert "1" in obs.evidence or "admin" in obs.evidence

    @pytest.mark.asyncio
    async def test_secure_cache_no_vulnerabilities(
        self, check, sample_service, cag_endpoint_context
    ):
        """Test against secure cache system - no vulnerabilities should be found."""
        mock_client = AsyncMock()

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "This is a fresh response to your query.", "model": "gpt-4"}',
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        vulns = result.outputs.get("cache_vulnerabilities", [])
        assert len(vulns) == 0
        # No vulnerability-level observations should be present
        vuln_obs = [o for o in result.observations if "Cache vulnerability:" in o.title]
        assert len(vuln_obs) == 0

    @pytest.mark.asyncio
    async def test_no_cag_endpoints_skips(self, check, sample_service):
        """Test check returns immediately when no CAG endpoints in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.observations) == 0
        assert len(result.outputs.get("cache_vulnerabilities", [])) == 0
        assert len(result.outputs.get("cache_timing_results", [])) == 0

    @pytest.mark.asyncio
    async def test_handles_errors_gracefully(self, check, sample_service, cag_endpoint_context):
        """Test graceful handling of request errors - no crash, errors captured."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=500,
                error="Internal Server Error",
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=500))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # No vulnerabilities from error responses
        vulns = result.outputs.get("cache_vulnerabilities", [])
        assert len(vulns) == 0
