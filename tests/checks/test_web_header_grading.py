"""
Tests for Phase 6b security header & protocol enhancement checks.

Covers:
- HeaderAnalysisCheck (enhanced value grading: CSP, HSTS, XFO, Referrer-Policy, Permissions-Policy)
- CookieSecurityCheck
- AuthDetectionCheck
- WAFDetectionCheck

All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.auth_detection import AuthDetectionCheck
from app.checks.web.cookie_security import CookieSecurityCheck
from app.checks.web.headers import HeaderAnalysisCheck
from app.checks.web.waf_detection import WAFDetectionCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════════
# HeaderAnalysisCheck — CSP Grading
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderCSPGrading:
    def test_init(self):
        check = HeaderAnalysisCheck()
        assert check.name == "header_analysis"

    @pytest.mark.asyncio
    async def test_weak_csp_unsafe_inline(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        csp_findings = [f for f in result.findings if "csp" in f.id.lower()]
        assert len(csp_findings) == 1
        assert csp_findings[0].severity == "medium"
        assert "'unsafe-inline'" in csp_findings[0].description

    @pytest.mark.asyncio
    async def test_weak_csp_unsafe_eval(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-eval'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "strict-origin",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        csp_findings = [f for f in result.findings if "csp" in f.id.lower()]
        assert len(csp_findings) == 1
        assert "'unsafe-eval'" in csp_findings[0].description

    @pytest.mark.asyncio
    async def test_csp_wildcard_source(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Content-Security-Policy": "default-src *",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        csp_findings = [f for f in result.findings if "csp" in f.id.lower()]
        assert len(csp_findings) == 1
        assert "wildcard" in csp_findings[0].description.lower()

    @pytest.mark.asyncio
    async def test_csp_missing_default_src(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Content-Security-Policy": "script-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        csp_findings = [f for f in result.findings if "csp" in f.id.lower()]
        assert len(csp_findings) == 1
        assert "default-src" in csp_findings[0].description

    @pytest.mark.asyncio
    async def test_strict_csp_no_finding(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        csp_findings = [f for f in result.findings if "csp" in (f.id or "").lower()]
        assert len(csp_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# HeaderAnalysisCheck — HSTS Grading
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderHSTSGrading:
    @pytest.mark.asyncio
    async def test_hsts_short_max_age(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Strict-Transport-Security": "max-age=86400",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        hsts_findings = [f for f in result.findings if "hsts" in (f.id or "").lower()]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == "low"
        assert "max-age too short" in hsts_findings[0].description

    @pytest.mark.asyncio
    async def test_hsts_missing_include_subdomains(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        hsts_findings = [f for f in result.findings if "hsts" in (f.id or "").lower()]
        assert len(hsts_findings) == 1
        assert "includeSubDomains" in hsts_findings[0].description

    @pytest.mark.asyncio
    async def test_strong_hsts_no_finding(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        hsts_findings = [f for f in result.findings if "hsts" in (f.id or "").lower()]
        assert len(hsts_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# HeaderAnalysisCheck — X-Frame-Options Grading
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderXFOGrading:
    @pytest.mark.asyncio
    async def test_xfo_allow_from_deprecated(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "X-Frame-Options": "ALLOW-FROM https://example.com",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        xfo_findings = [f for f in result.findings if "xfo" in (f.id or "").lower()]
        assert len(xfo_findings) == 1
        assert xfo_findings[0].severity == "medium"
        assert "deprecated" in xfo_findings[0].description.lower()

    @pytest.mark.asyncio
    async def test_xfo_deny_no_finding(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        xfo_findings = [f for f in result.findings if "xfo" in (f.id or "").lower()]
        assert len(xfo_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# HeaderAnalysisCheck — Referrer-Policy Grading
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderReferrerPolicyGrading:
    @pytest.mark.asyncio
    async def test_weak_referrer_policy_unsafe_url(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Referrer-Policy": "unsafe-url",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        rp_findings = [f for f in result.findings if "referrer" in (f.id or "").lower()]
        assert len(rp_findings) == 1
        assert rp_findings[0].severity == "low"

    @pytest.mark.asyncio
    async def test_strict_referrer_policy_no_finding(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        rp_findings = [f for f in result.findings if "referrer" in (f.id or "").lower()]
        assert len(rp_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# HeaderAnalysisCheck — Permissions-Policy Grading
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeaderPermissionsPolicyGrading:
    @pytest.mark.asyncio
    async def test_permissive_permissions_policy(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Permissions-Policy": "camera=*, microphone=*, geolocation=(self)",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        pp_findings = [f for f in result.findings if "permissions" in (f.id or "").lower()]
        assert len(pp_findings) == 1
        assert "camera" in pp_findings[0].description
        assert "microphone" in pp_findings[0].description

    @pytest.mark.asyncio
    async def test_restricted_permissions_policy_no_finding(self, service):
        check = HeaderAnalysisCheck()
        headers = {
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1",
            "Referrer-Policy": "no-referrer",
        }
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        pp_findings = [f for f in result.findings if "permissions" in (f.id or "").lower()]
        assert len(pp_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# CookieSecurityCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestCookieSecurityCheck:
    def test_init(self):
        check = CookieSecurityCheck()
        assert check.name == "cookie_security"
        assert "http" in check.service_types

    @pytest.mark.asyncio
    async def test_session_cookie_missing_secure(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "sessionid=abc123; HttpOnly; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        secure_findings = [f for f in result.findings if "no-secure" in (f.id or "")]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == "medium"  # session cookie → medium

    @pytest.mark.asyncio
    async def test_session_cookie_missing_httponly(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "JSESSIONID=xyz; Secure; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        httponly_findings = [f for f in result.findings if "no-httponly" in (f.id or "")]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_cookie_missing_samesite(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "sid=abc; Secure; HttpOnly; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        samesite_findings = [f for f in result.findings if "no-samesite" in (f.id or "")]
        assert len(samesite_findings) == 1

    @pytest.mark.asyncio
    async def test_cookie_samesite_none(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "auth=tok; Secure; HttpOnly; SameSite=None; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        samesite_none = [f for f in result.findings if "samesite-none" in (f.id or "")]
        assert len(samesite_none) == 1

    @pytest.mark.asyncio
    async def test_cookie_broad_domain(self, service):
        check = CookieSecurityCheck()
        headers = {
            "Set-Cookie": "tracker=x; Domain=.example.com; Secure; HttpOnly; SameSite=Strict; Path=/"
        }
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        domain_findings = [f for f in result.findings if "broad-domain" in (f.id or "")]
        assert len(domain_findings) == 1

    @pytest.mark.asyncio
    async def test_non_session_cookie_lower_severity(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "theme=dark; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        secure_findings = [f for f in result.findings if "no-secure" in (f.id or "")]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == "low"  # non-session → low

    @pytest.mark.asyncio
    async def test_fully_secured_cookie_no_security_findings(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "theme=dark; Secure; HttpOnly; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        # No secure/httponly/samesite findings
        issue_findings = [
            f
            for f in result.findings
            if any(
                x in (f.id or "")
                for x in ["no-secure", "no-httponly", "no-samesite", "samesite-none"]
            )
        ]
        assert len(issue_findings) == 0

    @pytest.mark.asyncio
    async def test_no_cookies_no_findings(self, service):
        check = CookieSecurityCheck()
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers={})),
        ):
            result = await check.check_service(service, {})
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_long_lived_session_cookie(self, service):
        check = CookieSecurityCheck()
        headers = {
            "Set-Cookie": "session=tok; Secure; HttpOnly; SameSite=Strict; Max-Age=99999999; Path=/"
        }
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        long_lived = [f for f in result.findings if "long-lived" in (f.id or "")]
        assert len(long_lived) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# AuthDetectionCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuthDetectionCheck:
    def test_init(self):
        check = AuthDetectionCheck()
        assert check.name == "auth_detection"
        assert "auth_mechanisms" in check.produces

    @pytest.mark.asyncio
    async def test_detects_basic_auth(self, service):
        check = AuthDetectionCheck()
        # Use default=401 with WWW-Authenticate; the root check won't match specific paths
        default_resp = resp(401, headers={"WWW-Authenticate": 'Basic realm="app"'})
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=default_resp),
        ):
            result = await check.check_service(service, {})
        auth_findings = [f for f in result.findings if "basic" in f.title.lower()]
        assert len(auth_findings) >= 1
        assert result.outputs.get("auth_mechanisms", {}).get("basic")

    @pytest.mark.asyncio
    async def test_detects_bearer_auth(self, service):
        check = AuthDetectionCheck()
        default_resp = resp(401, headers={"WWW-Authenticate": "Bearer"})
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=default_resp),
        ):
            result = await check.check_service(service, {})
        assert result.outputs.get("auth_mechanisms", {}).get("bearer")

    @pytest.mark.asyncio
    async def test_bearer_over_http_low_severity(self, service):
        check = AuthDetectionCheck()
        responses = {
            ("GET", "target.com:80/"): resp(401, headers={"WWW-Authenticate": "Bearer"}),
        }
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, {})
        bearer_findings = [f for f in result.findings if "bearer" in f.title.lower()]
        assert any(f.severity == "low" for f in bearer_findings)

    @pytest.mark.asyncio
    async def test_detects_oidc_discovery(self, service):
        check = AuthDetectionCheck()
        oidc_body = '{"issuer": "https://auth.example.com", "authorization_endpoint": "https://auth.example.com/authorize"}'
        responses = {
            ("GET", ".well-known/openid-configuration"): resp(200, body=oidc_body),
        }
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, {})
        oidc_findings = [
            f for f in result.findings if "oidc" in f.title.lower() or "oauth" in f.title.lower()
        ]
        assert len(oidc_findings) >= 1
        assert result.outputs.get("auth_mechanisms", {}).get("oidc")

    @pytest.mark.asyncio
    async def test_detects_login_form(self, service):
        check = AuthDetectionCheck()
        login_html = '<html><form><input type="password" name="pass"></form></html>'
        responses = {
            ("GET", "/login"): resp(200, body=login_html),
            ("GET", "/signin"): resp(200, body=login_html),
        }
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, {})
        login_findings = [f for f in result.findings if "login" in f.title.lower()]
        assert len(login_findings) >= 1
        assert result.outputs.get("auth_mechanisms", {}).get("login_form")

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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)
        noauth = [f for f in result.findings if "no authentication" in f.title.lower()]
        assert len(noauth) >= 1
        assert noauth[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_auth_paths_no_extra_findings(self, service):
        check = AuthDetectionCheck()
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient", return_value=mock_client_multi()
        ):
            result = await check.check_service(service, {})
        assert result.success is True
        assert "auth_mechanisms" in result.outputs


# ═══════════════════════════════════════════════════════════════════════════════
# WAFDetectionCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestWAFDetectionCheck:
    def test_init(self):
        check = WAFDetectionCheck()
        assert check.name == "waf_detection"
        assert "waf_detected" in check.produces

    @pytest.mark.asyncio
    async def test_detects_cloudflare_header(self, service):
        check = WAFDetectionCheck()
        headers = {"cf-ray": "abc123-IAD", "Server": "cloudflare"}
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        cf_findings = [f for f in result.findings if "cloudflare" in f.title.lower()]
        assert len(cf_findings) >= 1
        assert "Cloudflare" in result.outputs.get("waf_detected", {})

    @pytest.mark.asyncio
    async def test_detects_aws_waf(self, service):
        check = WAFDetectionCheck()
        headers = {"x-amzn-waf-action": "block"}
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        aws_findings = [f for f in result.findings if "aws" in f.title.lower()]
        assert len(aws_findings) >= 1
        # Should also have accuracy warning
        warn_findings = [f for f in result.findings if "accuracy" in f.title.lower()]
        assert len(warn_findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_imperva_cookie(self, service):
        check = WAFDetectionCheck()
        headers = {"Set-Cookie": "incap_ses_12345=abc; path=/"}
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        imperva = [
            f
            for f in result.findings
            if "imperva" in f.title.lower() or "incapsula" in f.title.lower()
        ]
        assert len(imperva) >= 1

    @pytest.mark.asyncio
    async def test_detects_waf_from_block_page(self, service):
        check = WAFDetectionCheck()
        block_body = "<html>Attention Required! | Cloudflare</html>"
        # Default returns block page so both root and probe path trigger it
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(403, body=block_body)),
        ):
            result = await check.check_service(service, {})
        cf_findings = [f for f in result.findings if "cloudflare" in f.title.lower()]
        assert len(cf_findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_azure_front_door(self, service):
        check = WAFDetectionCheck()
        headers = {"x-azure-ref": "abc123"}
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        azure_findings = [f for f in result.findings if "azure" in f.title.lower()]
        assert len(azure_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_waf_no_findings(self, service):
        check = WAFDetectionCheck()
        headers = {"Server": "nginx/1.24", "Content-Type": "text/html"}
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        # Should be no WAF findings (just empty outputs)
        assert len(result.findings) == 0
        assert result.outputs.get("waf_detected") == {}

    @pytest.mark.asyncio
    async def test_waf_accuracy_warning(self, service):
        """WAF detection should produce an accuracy warning finding when WAF detected."""
        check = WAFDetectionCheck()
        # Sucuri is classified as WAF, so should trigger accuracy warning
        headers = {"x-sucuri-id": "12345", "Server": "Sucuri/Cloudproxy"}
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        warn = [f for f in result.findings if "accuracy" in f.title.lower()]
        assert len(warn) >= 1
        assert warn[0].severity == "low"

    @pytest.mark.asyncio
    async def test_http_error_handled(self, service):
        check = WAFDetectionCheck()
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(error="Connection refused")),
        ):
            result = await check.check_service(service, {})
        assert result.success is True
        assert len(result.findings) == 0
