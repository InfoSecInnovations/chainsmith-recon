"""
app/checks/cag/multi_layer.py - Multi-Layer Cache Detection

Detect multiple cache layers (CDN -> application cache -> semantic cache)
and test bypass behavior for each layer.

Attack vectors:
- Different layers have different security properties
- Bypassing HTTP cache may still hit semantic cache
- CDN layer: bypassed by Cache-Control headers
- Application cache: may ignore HTTP cache headers
- Semantic cache: ignores all HTTP cache semantics

**Probe/grade.** The probe warms the cache and sends the
four bypass strategies (normal, `Cache-Control: no-cache`, `Pragma: no-cache`,
cache-buster), records every exchange, and hands them over as one candidate per
endpoint (the observation's `target_url` is the endpoint — §0.15). `grade()`
re-reads the recorded exchanges and rebuilds the layer analysis; `_reading()` is
the one parser both halves call (§0.12). Two conventions it contributes:

- **Timing is read back, not re-measured.** The original wrapped each strategy
  in `time.time()`; the reading now takes `Exchange.elapsed_ms`, so a re-grade
  reproduces the same latency profile from the corpus.
- **Which strategy an exchange used is recovered from its own recorded request**
  — the `Cache-Control` / `Pragma` request headers and the cache-buster's `_cb`
  body key (`_strategy_of`) — never from the order the four were sent.

**Fixed**: the discriminator embeds the endpoint path (an
open set), so the contract declares no `observations:` map and `grade()` places
the severity. Confidence is where the split pays: layer detection is a pure
timing heuristic, and `>1.5x`/`<0.7x` latency ratios are as easily produced by
backend load as by a distinct cache tier.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import hashlib
import json
import time
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

BASE_HEADERS = {"Content-Type": "application/json"}

# Strategy -> the extra request headers that identify it on the record. The
# cache-buster strategy is told apart by its body (`_cb` key), not a header.
STRATEGY_HEADERS = {
    "normal": {},
    "no_cache": {"Cache-Control": "no-cache"},
    "pragma": {"Pragma": "no-cache"},
}

CACHE_HEADER_NAMES = [
    "x-cache",
    "x-cache-hit",
    "x-cache-status",
    "age",
    "x-served-by",
    "x-cache-node",
    "via",
    "cf-cache-status",
]


class MultiLayerCacheCheck(ServiceIteratingCheck):
    """
    Detect multiple cache layers and test bypass behavior.

    Sends the same query with different cache-control strategies to
    identify distinct cache layers with different latency profiles
    and bypass behaviors.
    """

    name = "cag_multi_layer_cache"
    description = "Detect multiple cache layers and test bypass behavior"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_layers"]
    service_types = ["ai", "api", "http"]

    reason = "Multi-layer caches may have inconsistent security properties; bypassing one layer can reveal vulnerabilities in another"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache layer detection", "cache bypass", "timing analysis"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        layer_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    path = endpoint.get("path", "unknown")
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"layers-{path.strip('/').replace('/', '-')}",
                        target=service,
                        target_url=url,
                    )
                    await self._probe_layers(client, url, scan_id, service.host, candidate)
                    result.candidates.append(candidate)
                    reading = self._reading(candidate.exchanges, url)
                    if reading:
                        layer_results.append(reading)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if layer_results:
            result.outputs["cache_layers"] = layer_results

        return result

    async def _probe_layers(
        self, client: AsyncHttpClient, url: str, scan_id: str, host: str, candidate
    ) -> None:
        """Warm the cache, then fire the four bypass strategies and record them."""
        unique_id = hashlib.md5(f"{time.time()}_{url}".encode()).hexdigest()[:12]
        test_query = f"multi_layer_test_{unique_id}"
        payload = {"input": test_query, "query": test_query}

        # Warm the cache first (not graded; carries no strategy marker).
        await client.post(url, json=payload, headers=BASE_HEADERS)

        for strategy in ("normal", "no_cache", "pragma"):
            headers = {**BASE_HEADERS, **STRATEGY_HEADERS[strategy]}
            candidate.attach(await self._send(client, url, payload, headers, scan_id, host))

        buster_payload = dict(payload)
        buster_payload["_cb"] = str(int(time.time()))
        candidate.attach(
            await self._send(client, url, buster_payload, dict(BASE_HEADERS), scan_id, host)
        )

    async def _send(
        self,
        client: AsyncHttpClient,
        url: str,
        payload: dict,
        headers: dict,
        scan_id: str,
        host: str,
    ) -> Exchange:
        resp = await client.post(url, json=payload, headers=headers)
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=headers,
            request_json=payload,
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        layer_info = self._reading(list(evidence), ctx.target_url or "")
        if layer_info is None:
            return []

        severity = self._determine_severity(layer_info)
        confidence, why = self._confidence(layer_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=None,  # inherit the candidate's path discriminator
                title=self._build_title(layer_info),
                description=self._build_description(layer_info),
                evidence=self._build_evidence(layer_info),
                reasoning=why,
                signals={
                    "layers_detected": layer_info["layers_detected"],
                    "layer_types": [layer.get("type") for layer in layer_info["layers"]],
                },
                references=self.references,
                raw_data=layer_info,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(layer_info: dict) -> tuple[float, str]:
        types = [layer.get("type") for layer in layer_info.get("layers", [])]
        if "cdn" in types and layer_info["layers_detected"] == 1:
            return 0.85, (
                "the single layer is a CDN identified by an explicit cache header "
                "(cf-cache-status / x-cache / via), which is a named signal rather than a "
                "timing guess"
            )
        if layer_info["layers_detected"] > 1:
            return 0.35, (
                "multiple layers are inferred purely from latency ratios (>1.5x on bypass, "
                "<0.7x between strategies); backend load, cold-start and queueing produce the "
                "same ratios with a single cache, and no per-layer header confirms the split"
            )
        return 0.4, (
            "a single cache layer is inferred from timing alone; the fast, uniform responses "
            "are consistent with a cache but equally with a cheap endpoint under no load"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], url: str) -> dict | None:
        """Rebuild the layer reading off the recorded exchanges' latencies/headers."""
        timings: dict[str, dict] = {}
        for exchange in exchanges:
            strategy = self._strategy_of(exchange)
            if strategy is None or exchange.error:
                continue
            timings[strategy] = {
                "elapsed_ms": round(exchange.elapsed_ms, 2)
                if exchange.elapsed_ms is not None
                else 0.0,
                "status_code": exchange.response_status,
                "cache_headers": self._cache_headers(exchange),
                "response_length": len(exchange.response_body or ""),
            }

        if not all(k in timings for k in ("normal", "no_cache", "pragma", "cache_buster")):
            return None

        layers = self._analyze_layers(timings)
        if not layers:
            return None

        return {
            "url": url,
            "timings": timings,
            "layers_detected": len(layers),
            "layers": layers,
        }

    @staticmethod
    def _strategy_of(exchange: Exchange) -> str | None:
        """Which bypass strategy an exchange used, off its recorded request.

        The cache-buster carries a `_cb` body key; the others are told apart by
        their `Cache-Control` / `Pragma` request headers. The warm-up request
        carries neither marker and returns None (it is not graded).
        """
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            body = {}
        if isinstance(body, dict) and "_cb" in body:
            return "cache_buster"

        headers = {k.lower(): v.lower() for k, v in (exchange.request_headers or {}).items()}
        if headers.get("cache-control") == "no-cache":
            return "no_cache"
        if headers.get("pragma") == "no-cache":
            return "pragma"
        # A plain request with no cache-busting marker is the "normal" strategy.
        # The warm-up request is byte-identical but is never attached to the
        # candidate, so only the graded "normal" reaches here.
        return "normal"

    @staticmethod
    def _cache_headers(exchange: Exchange) -> dict:
        resp = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        return {h: resp[h] for h in CACHE_HEADER_NAMES if h in resp}

    def _analyze_layers(self, timings: dict) -> list[dict]:
        """Analyze timing patterns to identify cache layers."""
        layers = []
        normal = timings["normal"]["elapsed_ms"]
        no_cache = timings["no_cache"]["elapsed_ms"]
        pragma = timings["pragma"]["elapsed_ms"]
        buster = timings["cache_buster"]["elapsed_ms"]

        # Layer 1: HTTP cache (bypassed by Cache-Control/Pragma)
        http_cache_bypassed = no_cache > normal * 1.5 or pragma > normal * 1.5
        if http_cache_bypassed:
            layers.append(
                {
                    "type": "http_cache",
                    "bypass_method": "Cache-Control: no-cache",
                    "normal_ms": normal,
                    "bypassed_ms": no_cache,
                }
            )

        # Layer 2: Semantic/application cache (not bypassed by HTTP headers)
        # If no-cache is still faster than cache-buster, there's another layer
        if no_cache < buster * 0.7 and http_cache_bypassed:
            layers.append(
                {
                    "type": "application_cache",
                    "bypass_method": "none (ignores HTTP cache headers)",
                    "normal_ms": no_cache,
                    "bypassed_ms": buster,
                }
            )

        # If all strategies yield similar fast times, single cache layer
        all_fast = all(
            timings[k]["elapsed_ms"] < normal * 1.5 for k in ["no_cache", "pragma", "cache_buster"]
        )
        if all_fast and normal < 500:
            layers.append(
                {
                    "type": "semantic_or_application_cache",
                    "bypass_method": "none detected",
                    "note": "Cache ignores all HTTP cache-busting strategies",
                }
            )

        # Check for CDN indicators in headers
        for _strategy, data in timings.items():
            for header in ["cf-cache-status", "x-cache", "via"]:
                if header in data.get("cache_headers", {}):
                    if not any(layer["type"] == "cdn" for layer in layers):
                        layers.append(
                            {
                                "type": "cdn",
                                "header": header,
                                "value": data["cache_headers"][header],
                            }
                        )

        return layers

    def _determine_severity(self, layer_info: dict) -> str:
        """Determine observation severity."""
        n_layers = layer_info.get("layers_detected", 0)
        if n_layers > 1:
            return "medium"
        return "info"

    def _build_title(self, layer_info: dict) -> str:
        """Build observation title."""
        n = layer_info["layers_detected"]
        if n > 1:
            return f"Multiple cache layers detected: {n} layers with different bypass behavior"
        layer_type = layer_info["layers"][0]["type"] if layer_info["layers"] else "unknown"
        return f"Single cache layer detected ({layer_type})"

    def _build_description(self, layer_info: dict) -> str:
        """Build observation description."""
        parts = []
        for layer in layer_info.get("layers", []):
            ltype = layer.get("type", "unknown")
            bypass = layer.get("bypass_method", "unknown")
            parts.append(f"Layer: {ltype} (bypass: {bypass})")

        if layer_info["layers_detected"] > 1:
            parts.append(
                "Multiple cache layers may have inconsistent security properties. "
                "Bypassing one layer can expose vulnerabilities in another."
            )

        return ". ".join(parts)

    def _build_evidence(self, layer_info: dict) -> str:
        """Build evidence string."""
        lines = [f"Layers detected: {layer_info['layers_detected']}"]

        timings = layer_info.get("timings", {})
        for strategy, data in timings.items():
            if data:
                lines.append(f"  {strategy}: {data['elapsed_ms']}ms")

        for layer in layer_info.get("layers", []):
            lines.append(f"Layer: {layer.get('type', 'unknown')}")

        return "\n".join(lines)
