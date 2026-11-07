"""Tests for web_sri."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_sri import SRICheck
from app.lib.http import HttpResponse


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
    )


@pytest.fixture
def https_service():
    return Service(
        url="https://target.com:443",
        host="target.com",
        port=443,
        scheme="https",
        service_type="http",
    )


def resp(status_code=200, body="", headers=None, error=None, url="http://target.com:80"):
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client_multi(response_map=None, default=None):
    """Mock client that returns different responses based on URL/method."""
    if default is None:
        default = resp(404)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()

    def _lookup(method, url):
        # The real client stamps the requested URL onto the response, and a
        # migrated check records that URL on the exchange its grader reads.
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return replace(response, url=url)
        return replace(default, url=url)

    async def dispatch_get(url, **kwargs):
        return _lookup("GET", url)

    async def dispatch_post(url, **kwargs):
        return _lookup("POST", url)

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=lambda m, url, **kw: _lookup(m, url))

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


HTML_WITH_EXTERNAL_NO_SRI = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.css">
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="/static/local.js"></script>
</head>
<body>Hello</body>
</html>"""
HTML_WITH_SRI = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.css"
          integrity="sha384-abc123" crossorigin="anonymous">
    <script src="https://cdn.example.com/app.js"
            integrity="sha384-def456" crossorigin="anonymous"></script>
</head>
<body>Hello</body>
</html>"""
HTML_NO_EXTERNAL = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/app.js"></script>
</head>
<body>Hello</body>
</html>"""
HTML_MIXED_SRI = """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.example.com/jquery.js"
            integrity="sha384-xyz789" crossorigin="anonymous"></script>
    <script src="https://cdn.example.com/app.js"></script>
</head>
<body>Hello</body>
</html>"""


class TestSRICheck:
    def test_init(self):
        check = SRICheck()
        assert check.name == "web_sri"
        assert "sri_info" in check.produces

    @pytest.mark.asyncio
    async def test_external_without_sri(self, service):
        """External resources without SRI are flagged."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_WITH_EXTERNAL_NO_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        assert result.success
        # Should find 3 external resources without SRI (2 scripts + 1 stylesheet)
        assert result.outputs["sri_info"]["without_sri"] == 3
        assert result.outputs["sri_info"]["with_sri"] == 0
        # Summary observation
        summary = [f for f in result.observations if "external resource(s) without SRI" in f.title]
        assert len(summary) == 1

    @pytest.mark.asyncio
    async def test_all_sri_present(self, service):
        """All external resources have SRI — good observation."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_WITH_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["sri_info"]["with_sri"] == 2
        assert result.outputs["sri_info"]["without_sri"] == 0
        assert any("All external resources use SRI" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_no_external_resources(self, service):
        """No external resources — info observation."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_NO_EXTERNAL, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["sri_info"]["total_external"] == 0
        assert any("No external resources" in f.title for f in result.observations)

    @pytest.mark.asyncio
    async def test_mixed_sri(self, service):
        """Mix of SRI and non-SRI external resources."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_MIXED_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["sri_info"]["with_sri"] == 1
        assert result.outputs["sri_info"]["without_sri"] == 1

    @pytest.mark.asyncio
    async def test_severity_scales_with_count(self, service):
        """Medium severity when 3+ external resources lack SRI."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_WITH_EXTERNAL_NO_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        summary = [f for f in result.observations if "external resource(s) without SRI" in f.title]
        assert summary[0].severity == "medium"  # 3 resources = medium

    @pytest.mark.asyncio
    async def test_protocol_relative_url(self, service):
        """Protocol-relative URLs (//cdn.example.com) are treated as external."""
        html = '<html><head><script src="//cdn.example.com/lib.js"></script></head></html>'
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=html, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["sri_info"]["without_sri"] == 1

    @pytest.mark.asyncio
    async def test_non_html_response_skipped(self, service):
        """Non-HTML responses are not analyzed."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body='{"api": true}', headers={"content-type": "application/json"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.web_sri.check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await probe_and_grade(check, service)

        assert result.outputs["sri_info"]["total_external"] == 0
