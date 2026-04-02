"""
app/checks/cag/cache_quota.py - Cache Quota/Size Exploitation

Test cache size limits and eviction behavior under load.

Attack vectors:
- Cache exhaustion: flood with garbage to evict legitimate entries
- Unbounded cache: memory exhaustion risk
- LRU eviction abuse: targeted eviction of specific entries

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import time
import uuid
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Max entries to test (keep low to avoid impacting production)
MAX_TEST_ENTRIES = 50


class CacheQuotaCheck(ServiceIteratingCheck):
    """
    Test cache size limits and eviction behavior under load.

    Sends unique queries to fill the cache and then re-queries early
    entries to detect eviction. Estimates approximate cache capacity.
    """

    name = "cag_cache_quota"
    description = "Test cache size limits and eviction behavior under load"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_size"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.1

    reason = "Cache exhaustion enables targeted eviction of legitimate entries and potential memory exhaustion on unbounded caches"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache flooding", "eviction analysis", "capacity estimation"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints
            if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        quota_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    quota_info = await self._test_quota(client, url, service)

                    if quota_info:
                        quota_results.append(quota_info)

                        severity = self._determine_severity(quota_info)
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=self._build_title(quota_info),
                            description=self._build_description(quota_info),
                            severity=severity,
                            evidence=self._build_evidence(quota_info),
                            host=service.host,
                            discriminator=f"quota-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                            target=service,
                            target_url=url,
                            raw_data=quota_info,
                            references=self.references,
                        ))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if quota_results:
            result.outputs["cache_size"] = quota_results

        return result

    async def _test_quota(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Test cache capacity and eviction behavior."""
        test_id = uuid.uuid4().hex[:8]
        queries = []

        # First, get a baseline timing for uncached requests
        baseline_query = f"quota_baseline_{test_id}_{uuid.uuid4().hex[:6]}"
        start = time.time()
        resp = await client.post(
            url,
            json={"input": baseline_query, "query": baseline_query},
            headers={"Content-Type": "application/json"},
        )
        baseline_ms = (time.time() - start) * 1000

        if resp.error or resp.status_code >= 400:
            return None

        # Confirm caching works: re-query the baseline
        start = time.time()
        resp2 = await client.post(
            url,
            json={"input": baseline_query, "query": baseline_query},
            headers={"Content-Type": "application/json"},
        )
        cached_ms = (time.time() - start) * 1000

        if resp2.error:
            return None

        # If no caching detected, skip
        if cached_ms >= baseline_ms * 0.7:
            return None

        cache_hit_threshold = baseline_ms * 0.7

        # Fill cache with unique entries
        for i in range(MAX_TEST_ENTRIES):
            query = f"quota_test_{test_id}_{i}"
            queries.append(query)

            await client.post(
                url,
                json={"input": query, "query": query},
                headers={"Content-Type": "application/json"},
            )

        # Re-query the first few entries to check for eviction
        evicted_count = 0
        check_count = min(5, len(queries))

        for i in range(check_count):
            query = queries[i]
            start = time.time()
            resp = await client.post(
                url,
                json={"input": query, "query": query},
                headers={"Content-Type": "application/json"},
            )
            elapsed = (time.time() - start) * 1000

            if resp.error:
                continue

            # If slow response, entry was evicted
            if elapsed >= cache_hit_threshold:
                evicted_count += 1

        # Also check if the last entries are still cached
        last_cached = 0
        for i in range(max(0, len(queries) - 3), len(queries)):
            query = queries[i]
            start = time.time()
            resp = await client.post(
                url,
                json={"input": query, "query": query},
                headers={"Content-Type": "application/json"},
            )
            elapsed = (time.time() - start) * 1000

            if not resp.error and elapsed < cache_hit_threshold:
                last_cached += 1

        return {
            "url": url,
            "total_entries_sent": MAX_TEST_ENTRIES,
            "early_entries_evicted": evicted_count,
            "early_entries_checked": check_count,
            "last_entries_cached": last_cached,
            "baseline_ms": round(baseline_ms, 2),
            "cached_ms": round(cached_ms, 2),
            "eviction_detected": evicted_count > 0,
            "unbounded": evicted_count == 0 and last_cached > 0,
            "estimated_capacity": (
                MAX_TEST_ENTRIES if evicted_count == 0
                else MAX_TEST_ENTRIES - evicted_count
            ),
        }

    def _determine_severity(self, quota_info: dict) -> str:
        """Determine finding severity."""
        if quota_info.get("eviction_detected"):
            return "medium"
        if quota_info.get("unbounded"):
            return "medium"
        return "low"

    def _build_title(self, quota_info: dict) -> str:
        """Build finding title."""
        if quota_info.get("eviction_detected"):
            n = quota_info["early_entries_evicted"]
            return f"Cache exhaustion possible: {n} early entries evicted (LRU eviction confirmed)"
        if quota_info.get("unbounded"):
            n = quota_info["total_entries_sent"]
            return f"Unbounded cache: {n} queries accepted with no eviction (memory exhaustion risk)"
        return f"Cache size limited: approximately {quota_info['estimated_capacity']} entries"

    def _build_description(self, quota_info: dict) -> str:
        """Build finding description."""
        if quota_info.get("eviction_detected"):
            return (
                f"After sending {quota_info['total_entries_sent']} unique queries, "
                f"{quota_info['early_entries_evicted']}/{quota_info['early_entries_checked']} "
                f"early entries were evicted from cache. An attacker can flush valuable "
                f"cache entries by flooding with garbage queries, degrading performance "
                f"for legitimate users."
            )
        if quota_info.get("unbounded"):
            return (
                f"Cache accepted {quota_info['total_entries_sent']} unique entries "
                f"with no eviction detected. Unbounded caches risk memory exhaustion "
                f"under sustained load."
            )
        return (
            f"Cache appears limited to approximately {quota_info['estimated_capacity']} entries. "
            f"Capacity testing inconclusive."
        )

    def _build_evidence(self, quota_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Entries sent: {quota_info['total_entries_sent']}",
            f"Early entries evicted: {quota_info['early_entries_evicted']}/{quota_info['early_entries_checked']}",
            f"Last entries cached: {quota_info['last_entries_cached']}",
            f"Baseline timing: {quota_info['baseline_ms']}ms (uncached)",
            f"Cached timing: {quota_info['cached_ms']}ms",
        ]
        return "\n".join(lines)
