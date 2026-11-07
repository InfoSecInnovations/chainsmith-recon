"""Tests for web_cookie_security."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_cookie_security import CookieSecurityCheck
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


class TestCookieSecurityCheck:
    def test_init(self):
        check = CookieSecurityCheck()
        assert check.name == "web_cookie_security"
        assert "http" in check.service_types

    @pytest.mark.asyncio
    async def test_session_cookie_missing_secure(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "sessionid=abc123; HttpOnly; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        secure_observations = [f for f in result.observations if "no-secure" in (f.id or "")]
        assert len(secure_observations) == 1
        assert secure_observations[0].severity == "medium"  # session cookie -> medium

    @pytest.mark.asyncio
    async def test_session_cookie_missing_httponly(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "JSESSIONID=xyz; Secure; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        httponly_observations = [f for f in result.observations if "no-httponly" in (f.id or "")]
        assert len(httponly_observations) == 1
        assert httponly_observations[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_cookie_missing_samesite(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "sid=abc; Secure; HttpOnly; Path=/"}
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        samesite_observations = [f for f in result.observations if "no-samesite" in (f.id or "")]
        assert len(samesite_observations) == 1

    @pytest.mark.asyncio
    async def test_cookie_samesite_none(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "auth=tok; Secure; HttpOnly; SameSite=None; Path=/"}
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        samesite_none = [f for f in result.observations if "samesite-none" in (f.id or "")]
        assert len(samesite_none) == 1

    @pytest.mark.asyncio
    async def test_cookie_broad_domain(self, service):
        check = CookieSecurityCheck()
        headers = {
            "Set-Cookie": "tracker=x; Domain=.example.com; Secure; HttpOnly; SameSite=Strict; Path=/"
        }
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        domain_observations = [f for f in result.observations if "broad-domain" in (f.id or "")]
        assert len(domain_observations) == 1

    @pytest.mark.asyncio
    async def test_non_session_cookie_lower_severity(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "theme=dark; Path=/"}
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        secure_observations = [f for f in result.observations if "no-secure" in (f.id or "")]
        assert len(secure_observations) == 1
        assert secure_observations[0].severity == "low"  # non-session -> low

    @pytest.mark.asyncio
    async def test_fully_secured_cookie_no_security_observations(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "theme=dark; Secure; HttpOnly; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        # No secure/httponly/samesite observations
        issue_observations = [
            f
            for f in result.observations
            if any(
                x in (f.id or "")
                for x in ["no-secure", "no-httponly", "no-samesite", "samesite-none"]
            )
        ]
        assert len(issue_observations) == 0

    @pytest.mark.asyncio
    async def test_no_cookies_no_observations(self, service):
        check = CookieSecurityCheck()
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers={})),
        ):
            result = await probe_and_grade(check, service)
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_long_lived_session_cookie(self, service):
        check = CookieSecurityCheck()
        headers = {
            "Set-Cookie": "session=tok; Secure; HttpOnly; SameSite=Strict; Max-Age=99999999; Path=/"
        }
        with patch(
            "app.checks.web.web_cookie_security.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        long_lived = [f for f in result.observations if "long-lived" in (f.id or "")]
        assert len(long_lived) == 1
