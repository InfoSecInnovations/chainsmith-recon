"""Tests for the robots_txt check.

Extracted from tests/checks/test_web.py during the 56.1 pilot migration. The
patch target points at the `check` submodule where AsyncHttpClient is bound
(`app.checks.web.web_robots_txt.check`), not the package re-export.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_robots_txt import RobotsTxtCheck
from app.lib.http import HttpResponse

# ─── Fixtures (mirrors tests/checks/test_web.py) ─────────────────────────────


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

    This check is split into probe + grade, so `check_service()`
    now returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.check_service(service, context or {})
    return await grade_result(check, result, context or {})


# ─── Tests ───────────────────────────────────────────────────────────────────


class TestRobotsTxtCheckInit:
    """Tests for RobotsTxtCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = RobotsTxtCheck()

        assert check.name == "web_robots_txt"
        assert len(check.INTERESTING_PATTERNS) > 0


class TestRobotsTxtCheckService:
    """Tests for RobotsTxtCheck.check_service."""

    async def test_robots_not_found(self, sample_service):
        """No observation when robots.txt missing."""
        check = RobotsTxtCheck()
        response = make_response(status_code=404)

        with patch(
            "app.checks.web.web_robots_txt.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 0

    async def test_parses_disallow_paths(self, sample_service):
        """Disallow paths are extracted."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /private/
Disallow: /admin/
Disallow: /public/
"""
        response = make_response(body=robots_content)

        with patch(
            "app.checks.web.web_robots_txt.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        # /admin/ matches "admin" pattern
        sensitive_observations = [f for f in result.observations if "Sensitive paths" in f.title]
        assert len(sensitive_observations) == 1

    async def test_detects_sensitive_paths(self, sample_service):
        """Sensitive patterns in robots.txt are flagged with correct title and severity."""
        check = RobotsTxtCheck()
        # Realistic robots.txt with sensitive paths embedded among normal directives
        robots_content = (
            "# robots.txt for example.com\n"
            "User-agent: *\n"
            "Disallow: /search\n"
            "Disallow: /cgi-bin/\n"
            "Disallow: /wp-content/uploads/\n"
            "Disallow: /staging/api/v2/health\n"
            "Disallow: /data/export/reports\n"
            "Disallow: /internal/debug/console\n"
            "Allow: /public/\n"
        )
        response = make_response(body=robots_content)

        with patch(
            "app.checks.web.web_robots_txt.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        sensitive_observations = [f for f in result.observations if "Sensitive paths" in f.title]
        assert len(sensitive_observations) == 1
        obs = sensitive_observations[0]
        assert obs.severity == "low"
        assert obs.title.startswith("Sensitive paths in robots.txt")
        # Evidence should contain the matching paths
        assert "/staging/api/v2/health" in obs.evidence or "/data/export/reports" in obs.evidence

    async def test_benign_robots_no_sensitive_observation(self, sample_service):
        """A robots.txt with only benign paths produces no sensitive-path observation."""
        check = RobotsTxtCheck()
        robots_content = (
            "# Standard robots.txt\n"
            "User-agent: *\n"
            "Disallow: /search\n"
            "Disallow: /cgi-bin/\n"
            "Disallow: /wp-content/uploads/\n"
            "Disallow: /tmp/\n"
            "Allow: /public/\n"
        )
        response = make_response(body=robots_content)

        with patch(
            "app.checks.web.web_robots_txt.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        sensitive_observations = [f for f in result.observations if "Sensitive paths" in f.title]
        assert len(sensitive_observations) == 0

    async def test_extracts_sitemaps(self, sample_service):
        """Sitemap URLs are extracted."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
"""
        response = make_response(body=robots_content)

        with patch(
            "app.checks.web.web_robots_txt.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        sitemap_observations = [f for f in result.observations if "Sitemaps" in f.title]
        assert len(sitemap_observations) == 1
        assert sitemap_observations[0].severity == "info"

    async def test_sets_outputs(self, sample_service):
        """Outputs contain parsed data."""
        check = RobotsTxtCheck()
        robots_content = """
User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
"""
        response = make_response(body=robots_content)

        with patch(
            "app.checks.web.web_robots_txt.check.AsyncHttpClient",
            return_value=mock_client(response),
        ):
            result = await probe_and_grade(check, sample_service)

        key = f"robots_{sample_service.port}"
        assert key in result.outputs
        assert "/admin/" in result.outputs[key]["disallowed"]
