"""
app/checks/web/waf_detection.py - WAF/CDN Detection

Identifies WAF and CDN presence from:
- Response headers
- Cookie names
- Error page signatures
- Server header values

Outputs waf_detected for downstream check annotation.

**Probe/grade.** `check_service()` sends the normal request
and the long nonsense path meant to trip a block page, records both, and judges
nothing; `grade()` re-reads them and names what it recognises. `waf_detected` is
an output, so both halves call `_detect()` over the same exchanges (§6.2's two
parses, with one parser) — which also keeps the product ordering identical,
since first match wins per product.

#### Confidence comes from how specific the signature is

Rather than hand-rating forty rows, the rule is structural, because the tables
already say which signatures are ambiguous *in the product name they map to*:

- A vendor's own block-page text (`attention required! | cloudflare`) or a
  vendor-prefixed cookie (`incap_ses_`) names one product and nothing else.
- A header like `cf-ray` or a `Server: cloudflare` likewise.
- But `x-cache` and `x-cdn` map to **"CDN (generic)"**, which identifies no
  product at all, and `x-served-by` maps to **"Fastly/Varnish"** — a name that
  says the check cannot tell which. Those are the rows worth less, and they are
  recognisable by the name carrying `generic` or a `/`.

So `_signature_confidence()` reads the product name and the detection method.
The `waf-accuracy-warning` verdict then inherits the best confidence among the
WAF-typed products, because the warning is exactly as good as the strongest
evidence that a WAF is there. No severity changed.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
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

#: Path requested to try to trip a WAF block page.
BLOCK_PROBE_PATH = "/chainsmith-waf-probe-" + "x" * 50

#: How much a signature establishes *which* product answered, by method.
METHOD_CONFIDENCE = {
    "error page signature": 0.97,  # the vendor's own block page, verbatim
    "cookie signature": 0.95,  # vendor-prefixed cookie names
    "server header": 0.95,  # the product naming itself
    "response header": 0.95,  # a vendor-prefixed header
}


class WAFDetectionCheck(ServiceIteratingCheck):
    """Detect WAF and CDN presence from response characteristics."""

    name = "web_waf_detection"
    description = "Detect WAF/CDN from headers, cookies, and error page signatures"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["waf_detected"]
    service_types = ["http", "html", "api", "ai"]

    reason = "WAF/CDN presence affects interpretation of all downstream check results"
    references = ["OWASP WSTG-INFO-10", "CWE-693"]
    techniques = ["WAF fingerprinting", "CDN detection"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Send both requests, record both. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate per service: each product is a separate judgement over
        # the same two responses, so the candidate stays undiscriminated and
        # `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:

                def record(resp) -> None:
                    if resp.error:
                        return
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                # ── Normal request ──
                record(await client.get(service.url))

                # ── Trigger a potential WAF block ──
                await self._rate_limit()
                record(await client.get(service.with_path(BLOCK_PROBE_PATH)))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        detected = _detect(candidate.exchanges)
        result.outputs["waf_detected"] = {
            product: {"type": info.get("type", "unknown")} for product, info in detected.items()
        }
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded responses. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Name the WAF and CDN products one service's responses reveal."""
        exchanges = list(evidence)
        detected = _detect(exchanges)
        ids = [e.id for e in exchanges]

        verdicts: list[Verdict] = []
        waf_confidences: list[float] = []

        for product, info in detected.items():
            product_type = info.get("type", "CDN/WAF")
            method = info.get("method", "header analysis")
            confidence = _signature_confidence(product, method)
            if "waf" in product_type.lower():
                waf_confidences.append(confidence)

            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=confidence,
                    discriminator=f"detected-{_slugify(product)}",
                    title=f"{product_type} detected: {product}",
                    description=(f"{product} identified on {ctx.host} via {method}"),
                    evidence=info.get("evidence", f"{product} signatures found"),
                    reasoning=_signature_reasoning(product, method),
                    signals={
                        "product": product,
                        "type": product_type,
                        "method": method,
                    },
                    evidence_ids=ids,
                )
            )

        if waf_confidences:
            verdicts.append(
                Verdict(
                    severity="low",
                    # The warning is exactly as good as the strongest evidence
                    # that a WAF is in front of the target — a vendor block page
                    # settles it, a generic `x-cdn` header does not.
                    confidence=max(waf_confidences),
                    discriminator="waf-accuracy-warning",
                    title=f"WAF may affect scan accuracy: {ctx.host}",
                    description=(
                        "A WAF was detected — downstream AI/injection check results "
                        "may reflect WAF behavior rather than application behavior"
                    ),
                    evidence=f"WAF products detected: {', '.join(detected.keys())}",
                    reasoning=(
                        f"{len(waf_confidences)} WAF-class product(s) identified; this "
                        "verdict carries the confidence of the strongest of them"
                    ),
                    signals={
                        "waf_products": [
                            p for p, i in detected.items() if "waf" in i.get("type", "").lower()
                        ],
                    },
                    evidence_ids=ids,
                )
            )

        return verdicts


# ── The one parser, called by both halves ────────────────────────────


def _ambiguous(product: str) -> bool:
    """True when the product name itself admits it does not identify a product.

    `CDN (generic)` names a category; `Fastly/Varnish` and
    `AWS (API Gateway/ALB)` name alternatives. Both are the tables saying the
    signature is not decisive, which is what the confidence should reflect.
    """
    return "generic" in product.lower() or "/" in product


def _signature_confidence(product: str, method: str) -> float:
    """How much one signature establishes which product answered."""
    base = METHOD_CONFIDENCE.get(method, 0.8)
    if not _ambiguous(product):
        return base
    return 0.6 if "generic" in product.lower() else 0.7


def _signature_reasoning(product: str, method: str) -> str:
    """Why that confidence, in words, for the record."""
    if "generic" in product.lower():
        return (
            f"matched a {method} that indicates a CDN but names no product — the "
            "signature identifies a category, not a vendor"
        )
    if "/" in product:
        return (
            f"matched a {method} shared by the products in '{product}', so which one "
            "answered is not determined"
        )
    return f"matched a {method} specific to {product}"


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


def _is_block_probe(exchange: Exchange) -> bool:
    """True for the long nonsense path meant to trip a block page."""
    return BLOCK_PROBE_PATH in (exchange.request_url or "")


def _detect(exchanges: list[Exchange]) -> dict[str, dict[str, Any]]:
    """Read the WAF/CDN products out of the recorded responses.

    The single parser behind §6.2's two parses. The order of the checks is the
    original's — headers, cookies and Server on the normal response, then
    headers and body on the block probe — because first match wins per product
    and the `method` recorded against each one depends on that order.
    """
    detected: dict[str, dict[str, Any]] = {}

    normal = [e for e in exchanges if not _is_block_probe(e)]
    probes = [e for e in exchanges if _is_block_probe(e)]

    for exchange in normal:
        headers = exchange.response_headers or {}
        _check_headers(headers, detected)
        _check_cookies(headers, detected)
        _check_server(headers, detected)

    for exchange in probes:
        _check_headers(exchange.response_headers or {}, detected)
        _check_body(exchange.response_body or "", detected)

    return detected


def _slugify(text: str) -> str:
    """Simple slug for discriminator use."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
