"""Tests for web_header_analysis."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_header_analysis import HeaderAnalysisCheck
from app.lib.http import HttpResponse


@pytest.fixture
def sample_service():
    """Sample HTTP service."""
    return Service(
        url="http://example.com:8080",
        host="example.com",
        port=8080,
        scheme="http",
        service_type="http",
    )


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client(responses: list[HttpResponse] | HttpResponse):
    """Create a mock AsyncHttpClient context."""
    if not isinstance(responses, list):
        responses = [responses]

    response_iter = iter(responses)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()

    async def get_response(*args, **kwargs):
        try:
            return next(response_iter)
        except StopIteration:
            return responses[-1]  # Repeat last response

    mock.get = AsyncMock(side_effect=get_response)
    mock.options = AsyncMock(side_effect=get_response)
    mock.head = AsyncMock(side_effect=get_response)

    return mock


async def probe_and_grade(check, service, context=None):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `check_service()` now
    returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.check_service(service, context or {})
    return await grade_result(check, result, context or {})


class TestHeaderAnalysisCheckInit:
    """Tests for HeaderAnalysisCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = HeaderAnalysisCheck()

        assert check.name == "web_header_analysis"
        assert len(check.conditions) == 1
        assert "http" in check.service_types
        assert "ai" in check.service_types

    def test_security_headers_defined(self):
        """Security headers to check are defined."""
        check = HeaderAnalysisCheck()

        assert "strict-transport-security" in check.SECURITY_HEADERS
        assert "content-security-policy" in check.SECURITY_HEADERS


class TestHeaderAnalysisCheckService:
    """Tests for HeaderAnalysisCheck.check_service."""

    async def test_missing_security_headers(self, sample_service):
        """Missing security headers create observation."""
        check = HeaderAnalysisCheck()
        response = make_response(headers={"content-type": "text/html"})

        with patch(
            "app.checks.web.web_header_analysis.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        missing_observations = [f for f in result.observations if "Missing security" in f.title]
        assert len(missing_observations) == 1
        assert missing_observations[0].severity == "low"

    async def test_all_security_headers_present(self, sample_service):
        """No missing headers observation when all present."""
        check = HeaderAnalysisCheck()
        response = make_response(
            headers={
                "content-type": "text/html",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "no-referrer",
            }
        )

        with patch(
            "app.checks.web.web_header_analysis.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        missing_observations = [f for f in result.observations if "Missing security" in f.title]
        assert len(missing_observations) == 0

    async def test_cors_wildcard_detection(self, sample_service):
        """CORS wildcard creates observation."""
        check = HeaderAnalysisCheck()
        response = make_response(
            headers={
                "content-type": "text/html",
                "access-control-allow-origin": "*",
            }
        )

        with patch(
            "app.checks.web.web_header_analysis.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        cors_observations = [f for f in result.observations if "CORS" in f.title]
        assert len(cors_observations) == 1
        assert cors_observations[0].severity == "medium"

    async def test_cors_wildcard_with_credentials_high_severity(self, sample_service):
        """CORS wildcard with credentials is high severity."""
        check = HeaderAnalysisCheck()
        response = make_response(
            headers={
                "content-type": "text/html",
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )

        with patch(
            "app.checks.web.web_header_analysis.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        cors_observations = [f for f in result.observations if "CORS" in f.title]
        assert len(cors_observations) == 1
        assert cors_observations[0].severity == "high"

    async def test_server_version_disclosure(self, sample_service):
        """Server version disclosure creates observation."""
        check = HeaderAnalysisCheck()
        response = make_response(
            headers={
                "content-type": "text/html",
                "server": "nginx/1.21.3",
            }
        )

        with patch(
            "app.checks.web.web_header_analysis.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        server_observations = [f for f in result.observations if "Server version" in f.title]
        assert len(server_observations) == 1

    async def test_error_handling(self, sample_service):
        """HTTP errors are captured."""
        check = HeaderAnalysisCheck()
        response = make_response(error="Connection refused")

        with patch(
            "app.checks.web.web_header_analysis.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.errors) > 0
