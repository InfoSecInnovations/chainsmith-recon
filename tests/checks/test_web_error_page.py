"""Tests for ErrorPageCheck — error page framework detection."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.error_page import ErrorPageCheck
from app.lib.http import HttpResponse


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
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
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return response
        return default

    async def dispatch_get(url, **kwargs):
        return _lookup("GET", url)

    async def dispatch_post(url, **kwargs):
        return _lookup("POST", url)

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=lambda m, url, **kw: _lookup(m, url))

    return mock


# ═══════════════════════════════════════════════════════════════════════════════
# ErrorPageCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorPageCheck:
    def test_init(self):
        check = ErrorPageCheck()
        assert check.name == "error_page"
        assert "error_page_info" in check.produces

    @pytest.mark.asyncio
    async def test_django_debug_detected(self, service):
        """Django DEBUG=True is detected from 404 response."""
        check = ErrorPageCheck()
        body = "<html>You're seeing this error because you have DEBUG = True in your Django settings file.</html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        django = [f for f in result.findings if "django" in (f.id or "")]
        assert len(django) == 1
        assert django[0].severity == "medium"
        assert "Debug mode" in django[0].title

    @pytest.mark.asyncio
    async def test_werkzeug_debugger_high_severity(self, service):
        """Werkzeug debugger is flagged as high severity."""
        check = ErrorPageCheck()
        body = (
            "<html><title>Werkzeug Debugger</title><p>The debugger caught an exception</p></html>"
        )

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        werkzeug = [f for f in result.findings if "werkzeug" in (f.id or "")]
        assert len(werkzeug) >= 1
        assert werkzeug[0].severity == "high"

    @pytest.mark.asyncio
    async def test_spring_boot_identified(self, service):
        """Spring Boot Whitelabel Error Page is identified."""
        check = ErrorPageCheck()
        body = "<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        spring = [f for f in result.findings if "spring-boot" in (f.id or "")]
        assert len(spring) == 1
        assert spring[0].severity == "low"
        assert "Framework identified" in spring[0].title

    @pytest.mark.asyncio
    async def test_express_identified(self, service):
        """Express.js Cannot GET is identified."""
        check = ErrorPageCheck()
        body = "<!DOCTYPE html><html><body><pre>Cannot GET /nonexistent-path</pre></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        express = [f for f in result.findings if "express" in (f.id or "")]
        assert len(express) == 1

    @pytest.mark.asyncio
    async def test_fastapi_identified(self, service):
        """FastAPI JSON error is identified."""
        check = ErrorPageCheck()
        body = '{"detail": "Not Found"}'

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        fastapi = [f for f in result.findings if "fastapi" in (f.id or "")]
        assert len(fastapi) == 1
        assert fastapi[0].severity == "info"

    @pytest.mark.asyncio
    async def test_stack_trace_detected(self, service):
        """Python stack trace in error response is flagged."""
        check = ErrorPageCheck()
        body = """<html>
        Traceback (most recent call last)
        File "app.py", line 42
        </html>"""

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        stack = [f for f in result.findings if "stack-trace" in (f.id or "")]
        assert len(stack) == 1

    @pytest.mark.asyncio
    async def test_custom_error_pages(self, service):
        """Custom error pages with no framework signature produce info finding."""
        check = ErrorPageCheck()
        body = "<html><body><h1>Page Not Found</h1><p>Sorry, we could not find that page.</p></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        custom = [f for f in result.findings if "custom-errors" in (f.id or "")]
        assert len(custom) == 1
        assert custom[0].severity == "info"

    @pytest.mark.asyncio
    async def test_outputs_error_page_info(self, service):
        """Check outputs error_page_info with frameworks and debug status."""
        check = ErrorPageCheck()
        body = "<html>Whitelabel Error Page</html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        assert "error_page_info" in result.outputs
        assert "Spring Boot" in result.outputs["error_page_info"]["frameworks"]

    @pytest.mark.asyncio
    async def test_asp_net_detected(self, service):
        """ASP.NET error page is identified."""
        check = ErrorPageCheck()
        body = "<html><body><h1>Server Error in '/' Application.</h1></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        asp = [f for f in result.findings if "asp.net" in (f.id or "")]
        assert len(asp) == 1

    @pytest.mark.asyncio
    async def test_malformed_json_triggers_500(self, service):
        """Malformed JSON to API paths triggers error analysis."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("POST", "/api"): resp(
                        500, body='Traceback (most recent call last)\nFile "app.py", line 42'
                    ),
                },
                default=resp(404, body="not found"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success

    @pytest.mark.asyncio
    async def test_connection_error_handled(self, service):
        """Connection errors produce no findings."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
