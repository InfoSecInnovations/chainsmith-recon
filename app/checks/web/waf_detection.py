"""
app/checks/web/waf_detection.py - WAF/CDN Detection

Identifies WAF and CDN presence from:
- Response headers
- Cookie names
- Error page signatures
- Server header values

Outputs waf_detected for downstream check annotation.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# ── WAF/CDN signature database ──────────────────────────────────────

WAF_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    # (header_name_lower, value_pattern_or_None, product_name)
    ("cf-ray", None, "Cloudflare"),
    ("cf-cache-status", None, "Cloudflare"),
    ("x-amz-cf-id", None, "AWS CloudFront"),
    ("x-amz-cf-pop", None, "AWS CloudFront"),
    ("x-amzn-waf-action", None, "AWS WAF"),
    ("x-amzn-requestid", None, "AWS (API Gateway/ALB)"),
    ("x-cache", "HIT from", "CDN (generic)"),
    ("x-akamai-transformed", None, "Akamai"),
    ("x-akamai-request-id", None, "Akamai"),
    ("x-cdn", None, "CDN (generic)"),
    ("x-sucuri-id", None, "Sucuri"),
    ("x-sucuri-cache", None, "Sucuri"),
    ("x-azure-ref", None, "Azure Front Door"),
    ("x-msedge-ref", None, "Azure CDN"),
    ("x-served-by", None, "Fastly/Varnish"),
    ("x-timer", None, "Fastly"),
    ("x-iinfo", None, "Imperva/Incapsula"),
    ("x-cdn-geo", None, "KeyCDN"),
    ("x-hw", None, "Huawei CDN"),
]

WAF_COOKIE_PATTERNS: list[tuple[str, str]] = [
    ("__cfduid", "Cloudflare"),
    ("__cf_bm", "Cloudflare"),
    ("incap_ses_", "Imperva/Incapsula"),
    ("visid_incap_", "Imperva/Incapsula"),
    ("sucuri_cloudproxy", "Sucuri"),
    ("akavpau_", "Akamai"),
    ("_citrix_ns_", "Citrix ADC"),
]

WAF_SERVER_PATTERNS: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("akamaighost", "Akamai"),
    ("sucuri/cloudproxy", "Sucuri"),
    ("bigip", "F5 BIG-IP"),
    ("yunjiasu", "Baidu Yunjiasu"),
    ("denyall", "DenyAll WAF"),
    ("barracuda", "Barracuda WAF"),
    ("netscaler", "Citrix NetScaler"),
]

WAF_BODY_PATTERNS: list[tuple[str, str]] = [
    ("attention required! | cloudflare", "Cloudflare"),
    ("blocked by cloudflare", "Cloudflare"),
    ("access denied | sucuri", "Sucuri"),
    ("incapsula incident", "Imperva/Incapsula"),
    ("request unsuccessful. incapsula", "Imperva/Incapsula"),
    ("this request was blocked by the security rules", "AWS WAF"),
]


# Products known to provide WAF functionality (not just CDN)
WAF_PRODUCTS = {
    "Cloudflare",
    "AWS WAF",
    "Imperva/Incapsula",
    "Sucuri",
    "F5 BIG-IP",
    "DenyAll WAF",
    "Barracuda WAF",
    "Citrix ADC",
    "Citrix NetScaler",
    "Baidu Yunjiasu",
}


class WAFDetectionCheck(ServiceIteratingCheck):
    """Detect WAF and CDN presence from response characteristics."""

    name = "waf_detection"
    description = "Detect WAF/CDN from headers, cookies, and error page signatures"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["waf_detected"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "WAF/CDN presence affects interpretation of all downstream check results"
    references = ["OWASP WSTG-INFO-10", "CWE-693"]
    techniques = ["WAF fingerprinting", "CDN detection"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        detected: dict[str, dict[str, Any]] = {}  # product -> {type, evidence}

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                # ── Normal request ──
                resp = await client.get(service.url)
                if not resp.error:
                    self._check_headers(resp.headers, detected)
                    self._check_cookies(resp.headers, detected)
                    self._check_server(resp.headers, detected)

                # ── Trigger a potential WAF block ──
                await self._rate_limit()
                block_resp = await client.get(
                    service.with_path("/chainsmith-waf-probe-" + "x" * 50)
                )
                if not block_resp.error:
                    self._check_headers(block_resp.headers, detected)
                    self._check_body(block_resp.body or "", detected)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # ── Build observations ──
        is_waf = False
        for product, info in detected.items():
            product_type = info.get("type", "CDN/WAF")
            is_waf = is_waf or "waf" in product_type.lower()

            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"{product_type} detected: {product}",
                    description=f"{product} identified on {service.host} via {info.get('method', 'header analysis')}",
                    severity="info",
                    evidence=info.get("evidence", f"{product} signatures found"),
                    host=service.host,
                    discriminator=f"detected-{_slugify(product)}",
                    target=service,
                )
            )

        if is_waf:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"WAF may affect scan accuracy: {service.host}",
                    description="A WAF was detected — downstream AI/injection check results "
                    "may reflect WAF behavior rather than application behavior",
                    severity="low",
                    evidence=f"WAF products detected: {', '.join(detected.keys())}",
                    host=service.host,
                    discriminator="waf-accuracy-warning",
                    target=service,
                )
            )

        result.outputs["waf_detected"] = {
            product: {"type": info.get("type", "unknown")} for product, info in detected.items()
        }
        return result

    @staticmethod
    def _check_headers(headers: dict[str, str], detected: dict) -> None:
        """Check response headers against WAF/CDN signatures."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, value_pattern, product in WAF_HEADER_SIGNATURES:
            if header_name in headers_lower:
                val = headers_lower[header_name]
                if value_pattern is None or value_pattern.lower() in val.lower():
                    if product not in detected:
                        ptype = "WAF" if product in WAF_PRODUCTS else "CDN"
                        detected[product] = {
                            "type": ptype,
                            "method": "response header",
                            "evidence": f"Header '{header_name}': {val[:100]}",
                        }

    @staticmethod
    def _check_cookies(headers: dict[str, str], detected: dict) -> None:
        """Check Set-Cookie headers for WAF/CDN cookie patterns."""
        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue
            cookie_str = value.lower()
            for pattern, product in WAF_COOKIE_PATTERNS:
                if pattern in cookie_str and product not in detected:
                    detected[product] = {
                        "type": "WAF" if product in WAF_PRODUCTS else "CDN/WAF",
                        "method": "cookie signature",
                        "evidence": f"Cookie pattern '{pattern}' found",
                    }

    @staticmethod
    def _check_server(headers: dict[str, str], detected: dict) -> None:
        """Check Server header for WAF/CDN signatures."""
        server = ""
        for k, v in headers.items():
            if k.lower() == "server":
                server = v.lower()
                break
        if not server:
            return

        for pattern, product in WAF_SERVER_PATTERNS:
            if pattern in server and product not in detected:
                detected[product] = {
                    "type": "WAF" if product in WAF_PRODUCTS else "CDN/WAF",
                    "method": "server header",
                    "evidence": f"Server: {server[:100]}",
                }

    @staticmethod
    def _check_body(body: str, detected: dict) -> None:
        """Check response body for WAF/CDN error page signatures."""
        body_lower = body.lower()
        for pattern, product in WAF_BODY_PATTERNS:
            if pattern in body_lower and product not in detected:
                detected[product] = {
                    "type": "WAF",
                    "method": "error page signature",
                    "evidence": f"Body contains: '{pattern}'",
                }


def _slugify(text: str) -> str:
    """Simple slug for discriminator use."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
