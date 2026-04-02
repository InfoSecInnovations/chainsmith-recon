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

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import hashlib
import time
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


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

    timeout_seconds = 90.0
    delay_between_targets = 0.3

    reason = "Multi-layer caches may have inconsistent security properties; bypassing one layer can reveal vulnerabilities in another"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache layer detection", "cache bypass", "timing analysis"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints
            if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        layer_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    layer_info = await self._detect_layers(client, url, service)

                    if layer_info:
                        layer_results.append(layer_info)

                        severity = self._determine_severity(layer_info)
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=self._build_title(layer_info),
                            description=self._build_description(layer_info),
                            severity=severity,
                            evidence=self._build_evidence(layer_info),
                            host=service.host,
                            discriminator=f"layers-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                            target=service,
                            target_url=url,
                            raw_data=layer_info,
                            references=self.references,
                        ))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if layer_results:
            result.outputs["cache_layers"] = layer_results

        return result

    async def _detect_layers(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Detect cache layers by testing different bypass strategies."""
        unique_id = hashlib.md5(f"{time.time()}_{url}".encode()).hexdigest()[:12]
        test_query = f"multi_layer_test_{unique_id}"
        payload = {"input": test_query, "query": test_query}

        # Warm the cache first
        await client.post(url, json=payload, headers={"Content-Type": "application/json"})

        # Strategy 1: Normal request (hits all layers)
        timing_normal = await self._timed_request(client, url, payload, {})

        # Strategy 2: Cache-Control: no-cache (bypass HTTP cache)
        timing_no_cache = await self._timed_request(
            client, url, payload,
            {"Cache-Control": "no-cache"},
        )

        # Strategy 3: Pragma: no-cache (bypass older HTTP caches)
        timing_pragma = await self._timed_request(
            client, url, payload,
            {"Pragma": "no-cache"},
        )

        # Strategy 4: Cache-buster parameter
        buster_payload = dict(payload)
        buster_payload["_cb"] = str(int(time.time()))
        timing_buster = await self._timed_request(client, url, buster_payload, {})

        if not all([timing_normal, timing_no_cache, timing_pragma, timing_buster]):
            return None

        # Analyze timing patterns to detect layers
        timings = {
            "normal": timing_normal,
            "no_cache": timing_no_cache,
            "pragma": timing_pragma,
            "cache_buster": timing_buster,
        }

        layers = self._analyze_layers(timings)

        if not layers:
            return None

        return {
            "url": url,
            "timings": timings,
            "layers_detected": len(layers),
            "layers": layers,
        }

    async def _timed_request(
        self, client: AsyncHttpClient, url: str, payload: dict,
        extra_headers: dict
    ) -> dict | None:
        """Send a request and measure timing."""
        headers = {"Content-Type": "application/json"}
        headers.update(extra_headers)

        try:
            start = time.time()
            resp = await client.post(url, json=payload, headers=headers)
            elapsed_ms = (time.time() - start) * 1000

            if resp.error:
                return None

            # Collect cache-related headers
            cache_headers = {}
            for h in ["x-cache", "x-cache-hit", "x-cache-status", "age",
                       "x-served-by", "x-cache-node", "via", "cf-cache-status"]:
                val = resp.headers.get(h) or resp.headers.get(h.title())
                if val:
                    cache_headers[h] = val

            return {
                "elapsed_ms": round(elapsed_ms, 2),
                "status_code": resp.status_code,
                "cache_headers": cache_headers,
                "response_length": len(resp.body or ""),
            }

        except Exception:
            return None

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
            layers.append({
                "type": "http_cache",
                "bypass_method": "Cache-Control: no-cache",
                "normal_ms": normal,
                "bypassed_ms": no_cache,
            })

        # Layer 2: Semantic/application cache (not bypassed by HTTP headers)
        # If no-cache is still faster than cache-buster, there's another layer
        if no_cache < buster * 0.7 and http_cache_bypassed:
            layers.append({
                "type": "application_cache",
                "bypass_method": "none (ignores HTTP cache headers)",
                "normal_ms": no_cache,
                "bypassed_ms": buster,
            })

        # If all strategies yield similar fast times, single cache layer
        all_fast = all(
            timings[k]["elapsed_ms"] < normal * 1.5
            for k in ["no_cache", "pragma", "cache_buster"]
        )
        if all_fast and normal < 500:
            layers.append({
                "type": "semantic_or_application_cache",
                "bypass_method": "none detected",
                "note": "Cache ignores all HTTP cache-busting strategies",
            })

        # Check for CDN indicators in headers
        for strategy, data in timings.items():
            for header in ["cf-cache-status", "x-cache", "via"]:
                if header in data.get("cache_headers", {}):
                    if not any(l["type"] == "cdn" for l in layers):
                        layers.append({
                            "type": "cdn",
                            "header": header,
                            "value": data["cache_headers"][header],
                        })

        return layers

    def _determine_severity(self, layer_info: dict) -> str:
        """Determine finding severity."""
        n_layers = layer_info.get("layers_detected", 0)
        if n_layers > 1:
            return "medium"
        return "info"

    def _build_title(self, layer_info: dict) -> str:
        """Build finding title."""
        n = layer_info["layers_detected"]
        if n > 1:
            return f"Multiple cache layers detected: {n} layers with different bypass behavior"
        layer_type = layer_info["layers"][0]["type"] if layer_info["layers"] else "unknown"
        return f"Single cache layer detected ({layer_type})"

    def _build_description(self, layer_info: dict) -> str:
        """Build finding description."""
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
