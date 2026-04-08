"""Tests for security header value grading (CSP, HSTS, XFO, Referrer-Policy, Permissions-Policy)."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.headers import HeaderAnalysisCheck
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
        csp_observations = [f for f in result.observations if "csp" in f.id.lower()]
        assert len(csp_observations) == 1
        assert csp_observations[0].severity == "medium"
        assert "'unsafe-inline'" in csp_observations[0].description

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
        csp_observations = [f for f in result.observations if "csp" in f.id.lower()]
        assert len(csp_observations) == 1
        assert "'unsafe-eval'" in csp_observations[0].description

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
        csp_observations = [f for f in result.observations if "csp" in f.id.lower()]
        assert len(csp_observations) == 1
        assert "wildcard" in csp_observations[0].description.lower()

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
        csp_observations = [f for f in result.observations if "csp" in f.id.lower()]
        assert len(csp_observations) == 1
        assert "default-src" in csp_observations[0].description

    @pytest.mark.asyncio
    async def test_strict_csp_no_observation(self, service):
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
        csp_observations = [f for f in result.observations if "csp" in (f.id or "").lower()]
        assert len(csp_observations) == 0


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
        hsts_observations = [f for f in result.observations if "hsts" in (f.id or "").lower()]
        assert len(hsts_observations) == 1
        assert hsts_observations[0].severity == "low"
        assert "max-age too short" in hsts_observations[0].description

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
        hsts_observations = [f for f in result.observations if "hsts" in (f.id or "").lower()]
        assert len(hsts_observations) == 1
        assert "includeSubDomains" in hsts_observations[0].description

    @pytest.mark.asyncio
    async def test_strong_hsts_no_observation(self, service):
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
        hsts_observations = [f for f in result.observations if "hsts" in (f.id or "").lower()]
        assert len(hsts_observations) == 0


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
        xfo_observations = [f for f in result.observations if "xfo" in (f.id or "").lower()]
        assert len(xfo_observations) == 1
        assert xfo_observations[0].severity == "medium"
        assert "deprecated" in xfo_observations[0].description.lower()

    @pytest.mark.asyncio
    async def test_xfo_deny_no_observation(self, service):
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
        xfo_observations = [f for f in result.observations if "xfo" in (f.id or "").lower()]
        assert len(xfo_observations) == 0


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
        rp_observations = [f for f in result.observations if "referrer" in (f.id or "").lower()]
        assert len(rp_observations) == 1
        assert rp_observations[0].severity == "low"

    @pytest.mark.asyncio
    async def test_strict_referrer_policy_no_observation(self, service):
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
        rp_observations = [f for f in result.observations if "referrer" in (f.id or "").lower()]
        assert len(rp_observations) == 0


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
        pp_observations = [f for f in result.observations if "permissions" in (f.id or "").lower()]
        assert len(pp_observations) == 1
        assert "camera" in pp_observations[0].description
        assert "microphone" in pp_observations[0].description

    @pytest.mark.asyncio
    async def test_restricted_permissions_policy_no_observation(self, service):
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
        pp_observations = [f for f in result.observations if "permissions" in (f.id or "").lower()]
        assert len(pp_observations) == 0

    @pytest.mark.asyncio
    async def test_absent_permissions_policy_no_grading_observation(self, service):
        """When Permissions-Policy header is completely absent, no *grading*
        observation is emitted. Permissions-Policy is NOT in the SECURITY_HEADERS
        dict, so it also does not appear in the missing-security-headers list."""
        check = HeaderAnalysisCheck()
        headers = {
            # All other security headers present, but NO Permissions-Policy
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
        # No Permissions-Policy grading observation should appear
        pp_observations = [f for f in result.observations if "permissions" in (f.id or "").lower()]
        assert len(pp_observations) == 0
        # Permissions-Policy is NOT in the SECURITY_HEADERS dict, so the
        # missing-security-headers observation (if any) must NOT mention it.
        missing_obs = [
            f for f in result.observations if "missing-security-headers" in (f.id or "").lower()
        ]
        for obs in missing_obs:
            assert "permissions-policy" not in obs.evidence.lower()

    @pytest.mark.asyncio
    async def test_absent_permissions_policy_all_headers_missing(self, service):
        """When ALL security headers are absent (including Permissions-Policy),
        the missing-security-headers observation lists the 6 tracked headers but
        NOT Permissions-Policy (which is graded separately, not tracked in
        SECURITY_HEADERS)."""
        check = HeaderAnalysisCheck()
        # Completely bare response — no security headers at all
        headers = {}
        with patch(
            "app.checks.web.headers.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await check.check_service(service, {})
        missing_obs = [
            f for f in result.observations if "missing-security-headers" in (f.id or "").lower()
        ]
        assert len(missing_obs) == 1
        obs = missing_obs[0]
        assert obs.severity == "low"
        # Should report exactly the 6 headers from SECURITY_HEADERS
        assert "Missing security headers (6)" in obs.title
        assert "strict-transport-security" in obs.evidence
        assert "content-security-policy" in obs.evidence
        assert "x-content-type-options" in obs.evidence
        assert "x-frame-options" in obs.evidence
        assert "x-xss-protection" in obs.evidence
        assert "referrer-policy" in obs.evidence
        # Permissions-Policy is NOT in SECURITY_HEADERS, so not listed as missing
        assert "permissions-policy" not in obs.evidence.lower()
        # No Permissions-Policy grading observation either
        pp_obs = [f for f in result.observations if "permissions" in (f.id or "").lower()]
        assert len(pp_obs) == 0
