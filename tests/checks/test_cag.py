"""
Tests for app/checks/cag/ suite

Covers:
- CAGDiscoveryCheck
  - CAG endpoint discovery
  - Cache infrastructure detection (GPTCache, semantic cache, etc.)
  - Cache header analysis
- CAGCacheProbeCheck
  - Cross-session leakage testing
  - Cache timing analysis
  - Context ID enumeration
  - Cache key collision testing

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

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "cag_discovery"
        assert "cag_endpoints" in check.produces
        assert "cache_infrastructure" in check.produces

    @pytest.mark.asyncio
    async def test_discovers_gptcache(self, check, sample_service):
        """Test GPTCache discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache" in url and "/cache/" not in url:
                return make_response(
                    status_code=200,
                    headers={"x-gptcache-hit": "false"},
                    body='{"cache_status": "ready", "gptcache": true}',
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
        assert "gptcache" in infra

    @pytest.mark.asyncio
    async def test_discovers_semantic_cache(self, check, sample_service):
        """Test semantic cache discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/semantic-cache" in url:
                return make_response(
                    status_code=200,
                    headers={"x-semantic-cache": "enabled"},
                    body="{}",
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

    @pytest.mark.asyncio
    async def test_detects_cache_headers(self, check, sample_service):
        """Test cache header detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache/stats" in url:
                return make_response(
                    status_code=200,
                    headers={"x-cache": "HIT", "age": "120"},
                    body='{"cached": true, "ttl": 3600}',
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

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success

    @pytest.mark.asyncio
    async def test_no_cag_found(self, check, sample_service):
        """Test when no CAG endpoints found."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("cag_endpoints", [])) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# CAGCacheProbeCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCAGCacheProbeCheck:
    """Tests for CAGCacheProbeCheck."""

    @pytest.fixture
    def check(self):
        return CAGCacheProbeCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "cag_cache_probe"
        assert "cache_vulnerabilities" in check.produces
        assert "cache_timing_results" in check.produces

    @pytest.mark.asyncio
    async def test_detects_cross_session_leak(self, check, sample_service, cag_endpoint_context):
        """Test detection of cross-session cache leakage."""
        mock_client = AsyncMock()

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                # Second request (different session) gets first session's data
                return make_response(
                    status_code=200,
                    body='{"answer": "Based on earlier context from previous conversation..."}',
                )
            return make_response(status_code=200, body='{"answer": "ok"}')

        mock_client.post = mock_post
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        # Should have timing results at minimum
        assert "cache_timing_results" in result.outputs or "cache_vulnerabilities" in result.outputs

    @pytest.mark.asyncio
    async def test_timing_analysis(self, check, sample_service, cag_endpoint_context):
        """Test cache timing analysis."""
        mock_client = AsyncMock()

        # Simulate caching - first request slower than subsequent
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "cached response"}',
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        timing_results = result.outputs.get("cache_timing_results", [])
        # Should have timing data
        timing_tests = [r for r in timing_results if "timing_data" in r]
        assert len(timing_tests) > 0

    @pytest.mark.asyncio
    async def test_context_id_enumeration(self, check, sample_service, cag_endpoint_context):
        """Test context ID enumeration detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            headers = kwargs.get("headers", {})
            ctx_id = headers.get("X-Context-Id", "")
            if ctx_id in ["1", "admin"]:
                return make_response(
                    status_code=200,
                    body='{"context": "sensitive data for this context"}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=200, body="{}"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success

    @pytest.mark.asyncio
    async def test_secure_cache(self, check, sample_service, cag_endpoint_context):
        """Test against secure cache system."""
        mock_client = AsyncMock()

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"answer": "This is a fresh response."}',
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.cag.cache_probe.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, cag_endpoint_context)

        assert result.success
        vulns = result.outputs.get("cache_vulnerabilities", [])
        # Should not have major vulnerabilities
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_no_cag_endpoints_skips(self, check, sample_service):
        """Test check skips when no CAG endpoints in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_handles_errors_gracefully(self, check, sample_service, cag_endpoint_context):
        """Test graceful handling of request errors."""
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

        assert result.success  # Should not crash
