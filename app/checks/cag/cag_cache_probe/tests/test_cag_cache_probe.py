"""Tests for cag_cache_probe.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions. `__aexit__` returns
False so a probe exception is not suppressed (§0.14). The grader recovers each
sub-test from the request headers/body the probe records, so the mock's fixed
response URL is immaterial here — no URL stamping is needed.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_cache_probe import CAGCacheProbeCheck
from app.lib.http import HttpResponse


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.cag.cag_cache_probe.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.cag.cag_cache_probe.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.cag.cag_cache_probe.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.cag.cag_cache_probe.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        vulns = result.outputs.get("cache_vulnerabilities", [])
        assert len(vulns) == 0
        # No vulnerability-level observations should be present
        vuln_obs = [o for o in result.observations if "Cache vulnerability:" in o.title]
        assert len(vuln_obs) == 0

    @pytest.mark.asyncio
    async def test_no_cag_endpoints_skips(self, check, sample_service):
        """Test check returns immediately when no CAG endpoints in context."""
        result = await probe_and_grade(check, sample_service, {})

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.cag.cag_cache_probe.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        # No vulnerabilities from error responses
        vulns = result.outputs.get("cache_vulnerabilities", [])
        assert len(vulns) == 0
