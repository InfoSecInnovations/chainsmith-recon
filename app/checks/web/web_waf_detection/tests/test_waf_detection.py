"""Tests for web_waf_detection."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_waf_detection import WAFDetectionCheck
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


class TestWAFDetectionCheck:
    def test_init(self):
        check = WAFDetectionCheck()
        assert check.name == "web_waf_detection"
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(response_map=responses, default=block_resp),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(error="Connection refused")),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(403, body=generic_body, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
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
            "app.checks.web.web_waf_detection.check.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, headers=headers)),
        ):
            result = await probe_and_grade(check, service)
        # Azure Front Door is classified as CDN, not WAF
        azure_observations = [f for f in result.observations if "azure" in f.title.lower()]
        assert len(azure_observations) == 1
        assert "CDN detected" in azure_observations[0].title
        # No accuracy warning for CDN-only
        warn = [f for f in result.observations if "accuracy" in f.title.lower()]
        assert warn == [], "CDN-only detection should not produce WAF accuracy warning"
