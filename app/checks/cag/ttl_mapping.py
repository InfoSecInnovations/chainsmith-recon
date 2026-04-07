"""
app/checks/cag/ttl_mapping.py - TTL/Expiry Mapping

Determine cache TTL by re-querying at increasing intervals and detecting
the transition from cache hit to cache miss.

Attack vectors:
- Long TTL increases poisoning exposure window
- No TTL = indefinite caching = highest risk
- TTL mismatch between headers and actual behavior

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import hashlib
import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

# TTL test intervals in seconds
TTL_TEST_INTERVALS = [5, 15, 30, 60]


class TTLMappingCheck(ServiceIteratingCheck):
    """
    Map cache TTL and expiry behavior to assess poisoning exposure windows.

    Sends a unique query, confirms it is cached via timing analysis, then
    re-queries at increasing intervals to detect when the cache entry
    expires. Compares observed TTL with cache header values.
    """

    name = "cag_ttl_mapping"
    description = "Map cache TTL and expiry behavior to assess poisoning exposure windows"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_ttl"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 180.0
    delay_between_targets = 0.5

    reason = "Long cache TTL increases the exposure window for cache poisoning attacks and stale context exploitation"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["TTL analysis", "timing analysis", "cache header inspection"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        ttl_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    ttl_info = await self._map_ttl(client, url, service)

                    if ttl_info:
                        ttl_results.append(ttl_info)

                        severity = self._determine_severity(ttl_info)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=self._build_title(ttl_info),
                                description=self._build_description(ttl_info),
                                severity=severity,
                                evidence=self._build_evidence(ttl_info),
                                host=service.host,
                                discriminator=f"ttl-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=ttl_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if ttl_results:
            result.outputs["cache_ttl"] = ttl_results

        return result

    async def _map_ttl(self, client: AsyncHttpClient, url: str, service: Service) -> dict | None:
        """Map cache TTL for a given endpoint."""
        unique_id = hashlib.md5(f"{time.time()}_{url}".encode()).hexdigest()[:12]
        unique_query = f"ttl_mapping_test_{unique_id}"

        # First request: establish cache entry (cache miss)
        start1 = time.time()
        resp1 = await client.post(
            url,
            json={"input": unique_query, "query": unique_query},
            headers={"Content-Type": "application/json"},
        )
        time1 = (time.time() - start1) * 1000

        if resp1.error or resp1.status_code >= 400:
            return None

        # Extract header-stated TTL
        header_ttl = self._extract_header_ttl(resp1.headers)

        # Second request: confirm caching (should be cache hit)
        start2 = time.time()
        resp2 = await client.post(
            url,
            json={"input": unique_query, "query": unique_query},
            headers={"Content-Type": "application/json"},
        )
        time2 = (time.time() - start2) * 1000

        if resp2.error:
            return None

        # Check if caching is happening
        speedup = (time1 - time2) / time1 if time1 > 0 else 0
        caching_detected = time2 < time1 * 0.7

        if not caching_detected:
            return None

        # Test at increasing intervals to find TTL
        observed_ttl = None
        last_hit_interval = 0

        for interval in TTL_TEST_INTERVALS:
            await asyncio.sleep(interval - last_hit_interval)

            start = time.time()
            resp = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            elapsed = (time.time() - start) * 1000

            if resp.error:
                break

            # Cache miss if response time is close to original (slow) time
            is_cache_hit = elapsed < time1 * 0.7

            if is_cache_hit:
                last_hit_interval = interval
            else:
                observed_ttl = interval
                break

        return {
            "url": url,
            "caching_detected": True,
            "initial_request_ms": round(time1, 2),
            "cached_request_ms": round(time2, 2),
            "speedup_ratio": round(speedup, 2),
            "header_ttl_seconds": header_ttl,
            "observed_ttl_seconds": observed_ttl,
            "last_cache_hit_interval": last_hit_interval,
            "ttl_unbounded": observed_ttl is None,
            "ttl_mismatch": (
                header_ttl is not None
                and observed_ttl is not None
                and abs(header_ttl - observed_ttl) > 10
            ),
        }

    def _extract_header_ttl(self, headers: dict) -> int | None:
        """Extract TTL from cache-related response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check Cache-Control: max-age
        cache_control = headers_lower.get("cache-control", "")
        if "max-age=" in cache_control:
            try:
                max_age = int(cache_control.split("max-age=")[1].split(",")[0].strip())
                return max_age
            except (ValueError, IndexError):
                pass

        # Check Expires header (simplified — just detect presence)
        if "expires" in headers_lower:
            return -1  # Present but not parsed to seconds

        # Check Age header
        age = headers_lower.get("age")
        if age:
            try:
                return int(age)
            except ValueError:
                pass

        return None

    def _determine_severity(self, ttl_info: dict) -> str:
        """Determine observation severity based on TTL."""
        if ttl_info.get("ttl_unbounded"):
            return "medium"
        if ttl_info.get("ttl_mismatch"):
            return "low"

        observed = ttl_info.get("observed_ttl_seconds")
        if observed and observed > 300:
            return "medium"
        if observed:
            return "info"

        header_ttl = ttl_info.get("header_ttl_seconds")
        if header_ttl and header_ttl > 300:
            return "medium"

        return "low"

    def _build_title(self, ttl_info: dict) -> str:
        """Build observation title."""
        if ttl_info.get("ttl_unbounded"):
            return "Unbounded cache TTL (no expiry detected within test window)"
        if ttl_info.get("ttl_mismatch"):
            return (
                f"Cache TTL mismatch: header says {ttl_info['header_ttl_seconds']}s "
                f"but observed {ttl_info['observed_ttl_seconds']}s"
            )
        observed = ttl_info.get("observed_ttl_seconds")
        if observed:
            return f"Cache TTL: {observed}s"
        return "Cache TTL detected via headers"

    def _build_description(self, ttl_info: dict) -> str:
        """Build observation description."""
        parts = []

        if ttl_info.get("ttl_unbounded"):
            parts.append(
                f"Cache entries did not expire within the test window "
                f"(last cache hit at {ttl_info['last_cache_hit_interval']}s). "
                f"Long-lived or indefinite caching increases the exposure window "
                f"for cache poisoning attacks."
            )
        elif ttl_info.get("observed_ttl_seconds"):
            ttl = ttl_info["observed_ttl_seconds"]
            risk = "high" if ttl > 300 else "moderate" if ttl > 60 else "low"
            parts.append(f"Cache TTL observed at approximately {ttl} seconds ({risk} risk). ")

        if ttl_info.get("ttl_mismatch"):
            parts.append(
                f"TTL mismatch detected: headers state {ttl_info['header_ttl_seconds']}s "
                f"but actual expiry observed at {ttl_info['observed_ttl_seconds']}s."
            )

        return " ".join(parts) if parts else "Cache TTL detected."

    def _build_evidence(self, ttl_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Initial request: {ttl_info['initial_request_ms']}ms",
            f"Cached request: {ttl_info['cached_request_ms']}ms",
            f"Speedup: {ttl_info['speedup_ratio']:.0%}",
        ]
        if ttl_info.get("header_ttl_seconds") is not None:
            lines.append(f"Header TTL: {ttl_info['header_ttl_seconds']}s")
        if ttl_info.get("observed_ttl_seconds") is not None:
            lines.append(f"Observed TTL: {ttl_info['observed_ttl_seconds']}s")
        if ttl_info.get("ttl_unbounded"):
            lines.append(f"TTL unbounded: cache hit at {ttl_info['last_cache_hit_interval']}s")
        return "\n".join(lines)
