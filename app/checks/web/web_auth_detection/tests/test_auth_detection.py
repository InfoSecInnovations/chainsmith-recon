"""Tests for web_auth_detection."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_auth_detection import AuthDetectionCheck
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


def resp(status_code=200, body="", headers=None, error=None):
    return HttpResponse(
        url="http://target.com:80",
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


class TestAuthDetectionCheck:
    def test_init(self):
        check = AuthDetectionCheck()
        assert check.name == "web_auth_detection"
        assert "auth_mechanisms" in check.produces

    @pytest.mark.asyncio
    async def test_detects_basic_auth(self, service):
        check = AuthDetectionCheck()
        # Only the root returns 401 with Basic auth; other paths return 404
        # so we don't get duplicate observations for every probed path.
        root_resp = resp(
            401,
            headers={
                "WWW-Authenticate": 'Basic realm="app"',
                "Content-Type": "text/html; charset=utf-8",
                "X-Request-Id": "abc-123",
                "Server": "nginx/1.24",
            },
        )
        # Use a custom mock that only returns 401 for the exact root URL
        mock = mock_client_multi()

        async def selective_get(url, **kwargs):
            if url.rstrip("/") == service.url.rstrip("/"):
                return root_resp
            return resp(404)

        mock.get = AsyncMock(side_effect=selective_get)
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock,
        ):
            result = await probe_and_grade(check, service)
        auth_observations = [f for f in result.observations if "basic" in f.title.lower()]
        assert len(auth_observations) == 1
        assert auth_observations[0].title == "Basic auth required: target.com/"
        assert auth_observations[0].severity == "info"
        assert "WWW-Authenticate" in auth_observations[0].evidence
        assert result.outputs["auth_mechanisms"]["basic"] == ["/"]

    @pytest.mark.asyncio
    async def test_detects_bearer_auth(self, service):
        check = AuthDetectionCheck()
        # Only the root returns 401 with Bearer; probe paths return 404
        root_resp = resp(
            401,
            headers={
                "WWW-Authenticate": "Bearer",
                "Content-Type": "application/json",
                "X-Request-Id": "def-456",
            },
        )
        mock = mock_client_multi()

        async def selective_get(url, **kwargs):
            if url.rstrip("/") == service.url.rstrip("/"):
                return root_resp
            return resp(404)

        mock.get = AsyncMock(side_effect=selective_get)
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock,
        ):
            result = await probe_and_grade(check, service)
        assert result.outputs["auth_mechanisms"]["bearer"] == ["/"]

    @pytest.mark.asyncio
    async def test_bearer_over_http_low_severity(self, service):
        check = AuthDetectionCheck()
        responses = {
            ("GET", "target.com:80/"): resp(
                401,
                headers={
                    "WWW-Authenticate": "Bearer",
                    "Content-Type": "text/html",
                    "Server": "Apache/2.4",
                },
            ),
        }
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service)
        bearer_observations = [f for f in result.observations if "bearer" in f.title.lower()]
        assert len(bearer_observations) >= 1
        # Bearer over plain HTTP is severity "low" because tokens leak
        assert bearer_observations[0].severity == "low"
        assert "Bearer" in bearer_observations[0].evidence

    @pytest.mark.asyncio
    async def test_detects_oidc_discovery(self, service):
        check = AuthDetectionCheck()
        oidc_body = '{"issuer": "https://auth.example.com", "authorization_endpoint": "https://auth.example.com/authorize"}'
        responses = {
            ("GET", ".well-known/openid-configuration"): resp(200, body=oidc_body),
        }
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service)
        oidc_observations = [
            f
            for f in result.observations
            if "oidc" in f.title.lower() or "oauth" in f.title.lower()
        ]
        assert len(oidc_observations) == 1
        assert oidc_observations[0].title == "OAuth/OIDC provider detected: target.com"
        assert oidc_observations[0].severity == "info"
        assert result.outputs["auth_mechanisms"]["oidc"] == ["/.well-known/openid-configuration"]

    @pytest.mark.asyncio
    async def test_detects_login_form(self, service):
        check = AuthDetectionCheck()
        login_html = '<html><form><input type="password" name="pass"></form></html>'
        responses = {
            ("GET", "/login"): resp(200, body=login_html),
            ("GET", "/signin"): resp(200, body=login_html),
        }
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service)
        login_observations = [f for f in result.observations if "login" in f.title.lower()]
        assert len(login_observations) >= 1
        assert "Login page detected" in login_observations[0].title
        assert login_observations[0].severity == "info"
        assert result.outputs["auth_mechanisms"]["login_form"]

    @pytest.mark.asyncio
    async def test_detects_unauthenticated_api(self, service):
        check = AuthDetectionCheck()
        context = {
            f"paths_{service.port}": {"accessible": ["/api/v1/data"]},
        }
        responses = {
            ("GET", "target.com:80/"): resp(200),
            ("GET", "/api/v1/data"): resp(
                200, headers={"Content-Type": "application/json"}, body='{"ok":true}'
            ),
        }
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)
        noauth = [f for f in result.observations if "no authentication" in f.title.lower()]
        assert len(noauth) == 1
        assert noauth[0].severity == "medium"
        assert noauth[0].title == "API endpoint requires no authentication: target.com/api/v1/data"

    @pytest.mark.asyncio
    async def test_no_auth_paths_no_extra_observations(self, service):
        check = AuthDetectionCheck()
        with patch(
            "app.checks.web.web_auth_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(),
        ):
            result = await probe_and_grade(check, service)
        assert result.success is True
        assert "auth_mechanisms" in result.outputs
        # With no auth signals, mechanisms should be empty
        assert result.outputs["auth_mechanisms"] == {}
