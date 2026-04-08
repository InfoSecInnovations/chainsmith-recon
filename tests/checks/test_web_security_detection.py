"""Tests for cookie security, auth detection, and WAF detection checks."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.auth_detection import AuthDetectionCheck
from app.checks.web.cookie_security import CookieSecurityCheck
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
        secure_observations = [f for f in result.observations if "no-secure" in (f.id or "")]
        assert len(secure_observations) == 1
        assert secure_observations[0].severity == "medium"  # session cookie -> medium

    @pytest.mark.asyncio
    async def test_session_cookie_missing_httponly(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "JSESSIONID=xyz; Secure; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        httponly_observations = [f for f in result.observations if "no-httponly" in (f.id or "")]
        assert len(httponly_observations) == 1
        assert httponly_observations[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_cookie_missing_samesite(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "sid=abc; Secure; HttpOnly; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        samesite_observations = [f for f in result.observations if "no-samesite" in (f.id or "")]
        assert len(samesite_observations) == 1

    @pytest.mark.asyncio
    async def test_cookie_samesite_none(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "auth=tok; Secure; HttpOnly; SameSite=None; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        samesite_none = [f for f in result.observations if "samesite-none" in (f.id or "")]
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
        domain_observations = [f for f in result.observations if "broad-domain" in (f.id or "")]
        assert len(domain_observations) == 1

    @pytest.mark.asyncio
    async def test_non_session_cookie_lower_severity(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "theme=dark; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        secure_observations = [f for f in result.observations if "no-secure" in (f.id or "")]
        assert len(secure_observations) == 1
        assert secure_observations[0].severity == "low"  # non-session -> low

    @pytest.mark.asyncio
    async def test_fully_secured_cookie_no_security_observations(self, service):
        check = CookieSecurityCheck()
        headers = {"Set-Cookie": "theme=dark; Secure; HttpOnly; SameSite=Strict; Path=/"}
        with patch(
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
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
            "app.checks.web.cookie_security.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers={})),
        ):
            result = await check.check_service(service, {})
        assert len(result.observations) == 0

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
        long_lived = [f for f in result.observations if "long-lived" in (f.id or "")]
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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock,
        ):
            result = await check.check_service(service, {})
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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock,
        ):
            result = await check.check_service(service, {})
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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, {})
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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, {})
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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, {})
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
            "app.checks.web.auth_detection.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)
        noauth = [f for f in result.observations if "no authentication" in f.title.lower()]
        assert len(noauth) == 1
        assert noauth[0].severity == "medium"
        assert noauth[0].title == "API endpoint requires no authentication: target.com/api/v1/data"

    @pytest.mark.asyncio
    async def test_no_auth_paths_no_extra_observations(self, service):
        check = AuthDetectionCheck()
        with patch(
            "app.checks.web.auth_detection.AsyncHttpClient", return_value=mock_client_multi()
        ):
            result = await check.check_service(service, {})
        assert result.success is True
        assert "auth_mechanisms" in result.outputs
        # With no auth signals, mechanisms should be empty
        assert result.outputs["auth_mechanisms"] == {}


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
        """Cloudflare detected via cf-ray among many irrelevant headers."""
        check = WAFDetectionCheck()
        # Realistic response: cf-ray is the WAF indicator, surrounded by
        # unrelated headers that the detection logic must ignore.
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "X-Request-Id": "req-9f3a2b",
            "cf-ray": "7f1234abcde-IAD",
            "Cache-Control": "max-age=300",
            "Vary": "Accept-Encoding",
            "X-Content-Type-Options": "nosniff",
            "Server": "cloudflare",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        cf_observations = [f for f in result.observations if "cloudflare" in f.title.lower()]
        assert len(cf_observations) == 1
        assert cf_observations[0].title == "WAF detected: Cloudflare"
        assert cf_observations[0].severity == "info"
        assert "cf-ray" in cf_observations[0].evidence
        assert "Cloudflare" in result.outputs["waf_detected"]
        assert result.outputs["waf_detected"]["Cloudflare"]["type"] == "WAF"

    @pytest.mark.asyncio
    async def test_detects_aws_waf(self, service):
        """AWS WAF detected via x-amzn-waf-action among unrelated headers."""
        check = WAFDetectionCheck()
        headers = {
            "Content-Type": "text/html",
            "x-amzn-waf-action": "block",
            "Date": "Mon, 07 Apr 2025 12:00:00 GMT",
            "Connection": "keep-alive",
            "X-Frame-Options": "DENY",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        aws_observations = [f for f in result.observations if "aws waf" in f.title.lower()]
        assert len(aws_observations) == 1
        assert aws_observations[0].title == "WAF detected: AWS WAF"
        assert aws_observations[0].severity == "info"
        assert "x-amzn-waf-action" in aws_observations[0].evidence
        # WAF products trigger an accuracy warning
        warn_observations = [f for f in result.observations if "accuracy" in f.title.lower()]
        assert len(warn_observations) == 1
        assert warn_observations[0].severity == "low"
        assert "AWS WAF" in warn_observations[0].evidence

    @pytest.mark.asyncio
    async def test_detects_imperva_cookie(self, service):
        """Imperva detected via incap_ses cookie among other Set-Cookie noise."""
        check = WAFDetectionCheck()
        headers = {
            "Set-Cookie": "incap_ses_12345=abc; path=/",
            "Content-Type": "text/html",
            "Server": "nginx",
            "X-Powered-By": "Express",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        imperva = [
            f
            for f in result.observations
            if "imperva" in f.title.lower() or "incapsula" in f.title.lower()
        ]
        assert len(imperva) == 1
        assert "Imperva/Incapsula" in imperva[0].title
        assert imperva[0].severity == "info"
        assert "incap_ses_" in imperva[0].evidence

    @pytest.mark.asyncio
    async def test_detects_waf_from_block_page(self, service):
        """Cloudflare detected from error-page body signature on probe path."""
        check = WAFDetectionCheck()
        block_body = (
            "<html><head><title>Attention Required! | Cloudflare</title></head>"
            "<body><h1>Sorry, you have been blocked</h1></body></html>"
        )
        # Normal root returns clean page; probe path triggers a block page
        normal_resp = resp(
            200,
            body="<html>OK</html>",
            headers={"Content-Type": "text/html", "Server": "nginx"},
        )
        block_resp = resp(
            403,
            body=block_body,
            headers={"Content-Type": "text/html", "Server": "cloudflare"},
        )
        responses = {
            ("GET", "target.com:80/"): normal_resp,
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(response_map=responses, default=block_resp),
        ):
            result = await check.check_service(service, {})
        cf_observations = [f for f in result.observations if "cloudflare" in f.title.lower()]
        assert len(cf_observations) >= 1
        # At least one detection method found Cloudflare
        body_detected = any(
            "error page" in f.evidence.lower() or "body" in f.evidence.lower()
            for f in cf_observations
        )
        server_detected = any("server" in f.evidence.lower() for f in cf_observations)
        assert body_detected or server_detected

    @pytest.mark.asyncio
    async def test_detects_azure_front_door(self, service):
        """Azure Front Door detected via x-azure-ref among irrelevant headers."""
        check = WAFDetectionCheck()
        headers = {
            "x-azure-ref": "0abcdef1234567890",
            "Content-Type": "text/html",
            "Date": "Mon, 07 Apr 2025 12:00:00 GMT",
            "Strict-Transport-Security": "max-age=31536000",
            "Server": "Microsoft-IIS/10.0",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        azure_observations = [f for f in result.observations if "azure" in f.title.lower()]
        assert len(azure_observations) == 1
        assert azure_observations[0].title == "CDN detected: Azure Front Door"
        assert azure_observations[0].severity == "info"
        assert "x-azure-ref" in azure_observations[0].evidence

    @pytest.mark.asyncio
    async def test_no_waf_clean_response(self, service):
        """A plain nginx response with no WAF signatures produces no observations."""
        check = WAFDetectionCheck()
        headers = {
            "Server": "nginx/1.24",
            "Content-Type": "text/html",
            "X-Request-Id": "abc-123",
            "Cache-Control": "no-cache",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        assert result.observations == []
        assert result.outputs["waf_detected"] == {}

    @pytest.mark.asyncio
    async def test_waf_accuracy_warning_content(self, service):
        """WAF accuracy warning has correct title, severity, and lists detected products."""
        check = WAFDetectionCheck()
        headers = {
            "x-sucuri-id": "12345",
            "Server": "Sucuri/Cloudproxy",
            "Content-Type": "text/html",
            "X-Frame-Options": "SAMEORIGIN",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        # Sucuri is a WAF product, so accuracy warning should fire
        warn = [f for f in result.observations if "accuracy" in f.title.lower()]
        assert len(warn) == 1
        assert warn[0].severity == "low"
        assert "Sucuri" in warn[0].evidence
        assert warn[0].title == "WAF may affect scan accuracy: target.com"
        # The Sucuri detection observation itself should also be present
        sucuri = [
            f
            for f in result.observations
            if "sucuri" in f.title.lower() and "accuracy" not in f.title.lower()
        ]
        assert len(sucuri) == 1
        assert sucuri[0].severity == "info"

    @pytest.mark.asyncio
    async def test_http_error_handled(self, service):
        """Connection errors produce no observations and do not fail the check."""
        check = WAFDetectionCheck()
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(error="Connection refused")),
        ):
            result = await check.check_service(service, {})
        assert result.success is True
        assert result.observations == []
        assert result.outputs["waf_detected"] == {}

    # ── Negative tests ────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_cf_connecting_ip_without_cf_ray_not_cloudflare(self, service):
        """cf-connecting-ip is set by proxies forwarding through Cloudflare, but
        without cf-ray or Server: cloudflare the response should NOT flag as
        Cloudflare WAF/CDN."""
        check = WAFDetectionCheck()
        headers = {
            "cf-connecting-ip": "203.0.113.50",
            "Content-Type": "text/html",
            "Server": "nginx/1.24",
            "X-Forwarded-For": "203.0.113.50",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        cf_observations = [f for f in result.observations if "cloudflare" in f.title.lower()]
        assert cf_observations == [], (
            "cf-connecting-ip alone should not trigger Cloudflare detection"
        )

    @pytest.mark.asyncio
    async def test_generic_403_no_waf_signatures(self, service):
        """A generic 403 Forbidden page without any WAF body/header signatures
        should not produce WAF observations."""
        check = WAFDetectionCheck()
        generic_body = (
            "<html><head><title>403 Forbidden</title></head>"
            "<body><h1>Forbidden</h1><p>You don't have permission to access "
            "this resource.</p></body></html>"
        )
        headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.52",
            "Date": "Mon, 07 Apr 2025 12:00:00 GMT",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(403, body=generic_body, headers=headers)),
        ):
            result = await check.check_service(service, {})
        assert result.observations == [], (
            "A generic 403 page with no WAF signatures should produce zero observations"
        )
        assert result.outputs["waf_detected"] == {}

    @pytest.mark.asyncio
    async def test_unrelated_x_headers_no_false_positive(self, service):
        """Headers like X-Powered-By or X-Content-Type-Options should not
        trigger any WAF/CDN detection."""
        check = WAFDetectionCheck()
        headers = {
            "X-Powered-By": "Express",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Server": "gunicorn/20.1",
            "Content-Type": "text/html",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        assert result.observations == []
        assert result.outputs["waf_detected"] == {}

    @pytest.mark.asyncio
    async def test_cdn_detection_no_waf_accuracy_warning(self, service):
        """CDN-only products (e.g., Azure Front Door) should NOT trigger the
        WAF accuracy warning -- that warning is only for WAF products."""
        check = WAFDetectionCheck()
        headers = {
            "x-azure-ref": "0abcdef1234567890",
            "Content-Type": "text/html",
            "Server": "Microsoft-IIS/10.0",
        }
        with patch(
            "app.checks.web.waf_detection.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        # Azure Front Door is classified as CDN, not WAF
        azure_observations = [f for f in result.observations if "azure" in f.title.lower()]
        assert len(azure_observations) == 1
        assert "CDN detected" in azure_observations[0].title
        # No accuracy warning for CDN-only
        warn = [f for f in result.observations if "accuracy" in f.title.lower()]
        assert warn == [], "CDN-only detection should not produce WAF accuracy warning"
