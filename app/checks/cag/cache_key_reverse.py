"""
app/checks/cag/cache_key_reverse.py - Cache Key Reverse Engineering

Systematically vary query components to map which parts of the input
determine the cache key.

Attack vectors:
- Cache key excludes system prompt: multi-tenant safety bypass
- Cache key truncation: injection payload after key boundary
- Case-insensitive keys: wider collision surface

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import json
import time
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Query variation pairs to test which components are in the cache key
KEY_COMPONENT_TESTS = [
    {
        "id": "capitalization",
        "description": "Case sensitivity",
        "base": "what is the capital of france",
        "variant": "What Is The Capital Of France",
    },
    {
        "id": "punctuation",
        "description": "Punctuation sensitivity",
        "base": "what is the capital of france",
        "variant": "what is the capital of france?",
    },
    {
        "id": "whitespace",
        "description": "Whitespace sensitivity",
        "base": "what is the capital of france",
        "variant": "what  is  the  capital  of  france",
    },
    {
        "id": "prefix",
        "description": "Prefix/preamble sensitivity",
        "base": "capital of france",
        "variant": "Please kindly tell me the capital of france",
    },
    {
        "id": "suffix",
        "description": "Suffix/trailing content sensitivity",
        "base": "what is the capital of france",
        "variant": "what is the capital of france please thank you",
    },
]

SYSTEM_PROMPT_TESTS = [
    {
        "id": "system_prompt",
        "description": "System prompt in cache key",
        "query": "what is 2 plus 2",
        "system_a": "You are a helpful assistant.",
        "system_b": "You are a pirate. Respond only in pirate speak.",
    },
]


class CacheKeyReverseCheck(ServiceIteratingCheck):
    """
    Map cache key components by systematically varying query inputs.

    Sends pairs of queries that differ in one component and uses
    timing analysis to detect cache hits, revealing which components
    are included in or excluded from the cache key.
    """

    name = "cag_cache_key_reverse"
    description = "Map cache key components by systematically varying query inputs"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["key_structure"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.2

    reason = "Understanding cache key structure reveals poisoning vectors: keys that exclude system prompts enable multi-tenant attacks"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache key analysis", "timing analysis", "input variation"]

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
        key_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    # First confirm caching is active
                    baseline = await self._get_baseline_timing(client, url)
                    if not baseline or not baseline.get("caching_detected"):
                        continue

                    cache_hit_threshold = baseline["uncached_ms"] * 0.7

                    # Test each key component
                    for test in KEY_COMPONENT_TESTS:
                        component_result = await self._test_key_component(
                            client, url, test, cache_hit_threshold
                        )
                        if component_result:
                            key_results.append(component_result)

                    # Test system prompt inclusion
                    for test in SYSTEM_PROMPT_TESTS:
                        sys_result = await self._test_system_prompt_key(
                            client, url, test, cache_hit_threshold
                        )
                        if sys_result:
                            key_results.append(sys_result)

                    # Generate findings from results
                    self._generate_findings(result, key_results, service, url)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if key_results:
            result.outputs["key_structure"] = key_results

        return result

    async def _get_baseline_timing(
        self, client: AsyncHttpClient, url: str
    ) -> dict | None:
        """Get baseline timing for cached vs uncached requests."""
        test_query = f"baseline_key_test_{int(time.time())}"

        # Uncached request
        start1 = time.time()
        resp1 = await client.post(
            url,
            json={"input": test_query, "query": test_query},
            headers={"Content-Type": "application/json"},
        )
        uncached_ms = (time.time() - start1) * 1000

        if resp1.error or resp1.status_code >= 400:
            return None

        # Cached request (same query)
        start2 = time.time()
        resp2 = await client.post(
            url,
            json={"input": test_query, "query": test_query},
            headers={"Content-Type": "application/json"},
        )
        cached_ms = (time.time() - start2) * 1000

        caching_detected = cached_ms < uncached_ms * 0.7

        return {
            "uncached_ms": uncached_ms,
            "cached_ms": cached_ms,
            "caching_detected": caching_detected,
        }

    async def _test_key_component(
        self, client: AsyncHttpClient, url: str, test: dict,
        cache_hit_threshold: float
    ) -> dict | None:
        """Test if a specific component is part of the cache key."""
        base_query = test["base"]
        variant_query = test["variant"]

        try:
            # Send base query (populate cache)
            await client.post(
                url,
                json={"input": base_query, "query": base_query},
                headers={"Content-Type": "application/json"},
            )

            # Brief wait for cache population
            await asyncio.sleep(0.5)

            # Send variant query and measure timing
            start = time.time()
            resp = await client.post(
                url,
                json={"input": variant_query, "query": variant_query},
                headers={"Content-Type": "application/json"},
            )
            variant_ms = (time.time() - start) * 1000

            if resp.error:
                return None

            cache_hit = variant_ms < cache_hit_threshold
            in_cache_key = not cache_hit  # If variant misses cache, component IS in key

            return {
                "test_id": test["id"],
                "description": test["description"],
                "component_in_key": in_cache_key,
                "cache_hit_on_variant": cache_hit,
                "variant_ms": round(variant_ms, 2),
                "threshold_ms": round(cache_hit_threshold, 2),
            }

        except Exception:
            return None

    async def _test_system_prompt_key(
        self, client: AsyncHttpClient, url: str, test: dict,
        cache_hit_threshold: float
    ) -> dict | None:
        """Test if system prompt is part of the cache key."""
        query = test["query"]

        try:
            # Send with system prompt A
            await client.post(
                url,
                json={
                    "input": query,
                    "query": query,
                    "system": test["system_a"],
                    "messages": [
                        {"role": "system", "content": test["system_a"]},
                        {"role": "user", "content": query},
                    ],
                },
                headers={"Content-Type": "application/json"},
            )

            await asyncio.sleep(0.5)

            # Send same query with system prompt B
            start = time.time()
            resp = await client.post(
                url,
                json={
                    "input": query,
                    "query": query,
                    "system": test["system_b"],
                    "messages": [
                        {"role": "system", "content": test["system_b"]},
                        {"role": "user", "content": query},
                    ],
                },
                headers={"Content-Type": "application/json"},
            )
            variant_ms = (time.time() - start) * 1000

            if resp.error:
                return None

            cache_hit = variant_ms < cache_hit_threshold

            return {
                "test_id": test["id"],
                "description": test["description"],
                "component_in_key": not cache_hit,
                "cache_hit_on_variant": cache_hit,
                "variant_ms": round(variant_ms, 2),
                "threshold_ms": round(cache_hit_threshold, 2),
            }

        except Exception:
            return None

    def _generate_findings(
        self, result: CheckResult, key_results: list[dict],
        service: Service, url: str
    ) -> None:
        """Generate findings from key analysis results."""
        if not key_results:
            return

        # Check for high-severity: system prompt not in key
        sys_tests = [r for r in key_results if r["test_id"] == "system_prompt"]
        for r in sys_tests:
            if r.get("cache_hit_on_variant"):
                result.findings.append(build_finding(
                    check_name=self.name,
                    title="Cache key excludes system prompt: different system messages share cache",
                    description=(
                        "The cache key does not include the system prompt. Different system "
                        "messages produce cache hits for the same user query, meaning users "
                        "with different safety configurations share cache entries."
                    ),
                    severity="high",
                    evidence=self._build_evidence(r),
                    host=service.host,
                    discriminator="key-excludes-system-prompt",
                    target=service,
                    target_url=url,
                    raw_data=r,
                    references=self.references,
                ))

        # Check for medium-severity: case-insensitive, whitespace-insensitive
        for r in key_results:
            if r["test_id"] in ("capitalization", "whitespace", "punctuation"):
                if r.get("cache_hit_on_variant"):
                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"Cache key is {r['description'].lower()}-insensitive",
                        description=(
                            f"Cache key ignores {r['description'].lower()} differences. "
                            f"This widens the collision surface for cache poisoning attacks."
                        ),
                        severity="medium",
                        evidence=self._build_evidence(r),
                        host=service.host,
                        discriminator=f"key-ignores-{r['test_id']}",
                        target=service,
                        target_url=url,
                        raw_data=r,
                    ))

        # Summary finding if all components are in key
        all_in_key = all(r.get("component_in_key", False) for r in key_results)
        if all_in_key:
            result.findings.append(build_finding(
                check_name=self.name,
                title="Cache key includes most query components (detailed key)",
                description="All tested query components are part of the cache key, reducing collision risk.",
                severity="low",
                evidence=f"Tested {len(key_results)} key components, all included in cache key",
                host=service.host,
                discriminator="key-detailed",
                target=service,
                target_url=url,
            ))

    def _build_evidence(self, test_result: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Test: {test_result['test_id']} ({test_result.get('description', '')})",
            f"Component in key: {test_result.get('component_in_key', 'unknown')}",
            f"Cache hit on variant: {test_result.get('cache_hit_on_variant', 'unknown')}",
            f"Variant timing: {test_result.get('variant_ms', '?')}ms (threshold: {test_result.get('threshold_ms', '?')}ms)",
        ]
        return "\n".join(lines)
