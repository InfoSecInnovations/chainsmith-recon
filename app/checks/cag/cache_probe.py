"""
app/checks/cag/cache_probe.py - CAG Cache Probing

Probe CAG endpoints for cache-related vulnerabilities.

Attack vectors:
- Cache poisoning: Inject malicious content that gets cached and served to others
- Cross-user leakage: Access cached responses from other users/sessions
- Stale context exploitation: Trigger use of outdated/poisoned cached context
- Cache timing attacks: Infer information from cache hit/miss timing
- Cache key manipulation: Craft inputs to collide with other cache entries

Detection methods:
- Probe for cross-session cache hits
- Test cache key predictability
- Analyze timing differences between cached/uncached responses
- Test for cache-control header respect
- Probe for context ID enumeration

References:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses
  https://portswigger.net/web-security/web-cache-poisoning
"""

import hashlib
import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Cache probe payloads
CACHE_PROBE_TESTS = [
    {
        "id": "cross_session_leak",
        "category": "information_leakage",
        "description": "Tests if cached responses leak across sessions",
        "method": "session_comparison",
    },
    {
        "id": "cache_key_collision",
        "category": "cache_poisoning",
        "description": "Tests for predictable cache key generation",
        "method": "key_manipulation",
    },
    {
        "id": "context_id_enumeration",
        "category": "information_leakage",
        "description": "Tests if context/session IDs are enumerable",
        "method": "id_enumeration",
    },
    {
        "id": "stale_context",
        "category": "integrity",
        "description": "Tests for stale/outdated cached context exploitation",
        "method": "timing_analysis",
    },
    {
        "id": "cache_timing",
        "category": "side_channel",
        "description": "Analyzes timing differences to infer cache state",
        "method": "timing_analysis",
    },
]

# Indicators of cache vulnerability
CACHE_VULN_INDICATORS = {
    "cross_session": [
        "different session",
        "other user",
        "previous conversation",
        "earlier context",
    ],
    "stale_data": [
        "outdated",
        "old version",
        "previous state",
        "stale",
    ],
    "key_collision": [
        "unexpected response",
        "wrong context",
        "different query",
    ],
}


class CAGCacheProbeCheck(ServiceIteratingCheck):
    """
    Probe CAG endpoints for cache-related vulnerabilities.

    Tests for cross-session leakage, cache poisoning vectors,
    stale context exploitation, and timing-based side channels.
    """

    name = "cag_cache_probe"
    description = "Probe CAG endpoints for cache leakage and poisoning vulnerabilities"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_vulnerabilities", "cache_timing_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.3

    reason = "Cache vulnerabilities can enable cross-user data leakage, context poisoning, and side-channel attacks revealing sensitive information"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "MITRE ATLAS - AML.T0048 Data Poisoning",
    ]
    techniques = ["cache probing", "timing analysis", "session manipulation"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Get CAG endpoints from context
        cag_endpoints = context.get("cag_endpoints", [])

        # Filter to endpoints on this service
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        cache_vulns = []
        timing_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    endpoint_results = await self._probe_endpoint(client, endpoint, service)

                    for test_result in endpoint_results:
                        if test_result.get("timing_data"):
                            timing_results.append(test_result)

                        if test_result.get("vulnerability_detected"):
                            cache_vulns.append(test_result)

                            severity = self._determine_severity(test_result)

                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Cache vulnerability: {test_result['test_id']}",
                                    description=self._build_description(test_result),
                                    severity=severity,
                                    evidence=self._build_evidence(test_result),
                                    host=service.host,
                                    discriminator=f"cache-vuln-{test_result['test_id']}",
                                    target=service,
                                    target_url=endpoint.get("url"),
                                    raw_data=test_result,
                                    references=self.references,
                                )
                            )
                        elif test_result.get("potential_issue"):
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Potential cache issue: {test_result['test_id']}",
                                    description=self._build_description(test_result),
                                    severity="low",
                                    evidence=self._build_evidence(test_result),
                                    host=service.host,
                                    discriminator=f"cache-issue-{test_result['test_id']}",
                                    target=service,
                                    target_url=endpoint.get("url"),
                                    raw_data=test_result,
                                )
                            )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if cache_vulns:
            result.outputs["cache_vulnerabilities"] = cache_vulns
        if timing_results:
            result.outputs["cache_timing_results"] = timing_results

        return result

    async def _probe_endpoint(
        self, client: AsyncHttpClient, endpoint: dict, service: Service
    ) -> list[dict]:
        """Probe an endpoint with all cache tests."""
        results = []
        url = endpoint.get("url", service.url)

        # Test 1: Cross-session cache leakage
        cross_session_result = await self._test_cross_session(client, url)
        results.append(cross_session_result)

        # Test 2: Cache timing analysis
        timing_result = await self._test_cache_timing(client, url)
        results.append(timing_result)

        # Test 3: Context ID enumeration
        enum_result = await self._test_id_enumeration(client, url, endpoint)
        results.append(enum_result)

        # Test 4: Cache key predictability
        key_result = await self._test_cache_key_prediction(client, url)
        results.append(key_result)

        return results

    async def _test_cross_session(self, client: AsyncHttpClient, url: str) -> dict:
        """Test for cross-session cache leakage."""
        test_id = "cross_session_leak"

        try:
            # First request with session A context
            unique_marker_a = f"SESSION_A_{int(time.time())}"
            resp1 = await client.post(
                url,
                json={
                    "input": f"Remember this marker: {unique_marker_a}",
                    "query": unique_marker_a,
                },
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": "test-session-a",
                },
            )

            # Second request with session B, asking about session A's data
            resp2 = await client.post(
                url,
                json={"input": "What marker was mentioned?", "query": "marker"},
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": "test-session-b",  # Different session
                },
            )

            if resp1.error or resp2.error:
                return {
                    "test_id": test_id,
                    "category": "information_leakage",
                    "error": resp1.error or resp2.error,
                    "vulnerability_detected": False,
                }

            # Check if session B got session A's data
            body2_lower = (resp2.body or "").lower()
            leaked = unique_marker_a.lower() in body2_lower or "session_a" in body2_lower

            # Check for cross-session indicators
            indicators = []
            for indicator in CACHE_VULN_INDICATORS["cross_session"]:
                if indicator in body2_lower:
                    indicators.append(indicator)

            return {
                "test_id": test_id,
                "category": "information_leakage",
                "description": "Tests if cached responses leak across sessions",
                "vulnerability_detected": leaked,
                "potential_issue": len(indicators) > 0,
                "indicators": indicators,
                "response_preview": resp2.body[:300] if resp2.body else "",
            }

        except Exception as e:
            return {
                "test_id": test_id,
                "error": str(e),
                "vulnerability_detected": False,
            }

    async def _test_cache_timing(self, client: AsyncHttpClient, url: str) -> dict:
        """Analyze cache timing to detect caching behavior."""
        test_id = "cache_timing"

        try:
            # Unique query to ensure cache miss on first request
            unique_query = f"timing_test_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

            # First request (should be cache miss)
            start1 = time.time()
            resp1 = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            time1 = (time.time() - start1) * 1000  # ms

            # Second identical request (might be cache hit)
            start2 = time.time()
            resp2 = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            time2 = (time.time() - start2) * 1000  # ms

            # Third request (confirm pattern)
            start3 = time.time()
            await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            time3 = (time.time() - start3) * 1000  # ms

            if resp1.error:
                return {
                    "test_id": test_id,
                    "error": resp1.error,
                    "vulnerability_detected": False,
                }

            # Analyze timing pattern
            # Significant speedup (>50%) on subsequent requests indicates caching
            speedup = (time1 - time2) / time1 if time1 > 0 else 0
            consistent_cache = time2 < time1 * 0.7 and time3 < time1 * 0.7

            timing_data = {
                "first_request_ms": round(time1, 2),
                "second_request_ms": round(time2, 2),
                "third_request_ms": round(time3, 2),
                "speedup_ratio": round(speedup, 2),
                "caching_detected": consistent_cache,
            }

            # Check response headers for cache indicators
            cache_headers = []
            for header in ["x-cache", "x-cache-hit", "x-cache-status", "age"]:
                if header in [h.lower() for h in resp2.headers]:
                    cache_headers.append(header)

            return {
                "test_id": test_id,
                "category": "side_channel",
                "description": "Analyzes timing differences to infer cache state",
                "vulnerability_detected": False,  # Timing alone isn't a vulnerability
                "potential_issue": consistent_cache,
                "timing_data": timing_data,
                "cache_headers": cache_headers,
            }

        except Exception as e:
            return {
                "test_id": test_id,
                "error": str(e),
                "vulnerability_detected": False,
            }

    async def _test_id_enumeration(self, client: AsyncHttpClient, url: str, endpoint: dict) -> dict:
        """Test for context/session ID enumeration."""
        test_id = "context_id_enumeration"

        try:
            # Try common ID patterns
            test_ids = [
                "1",
                "0",
                "admin",
                "test",
                "default",
                "00000000-0000-0000-0000-000000000001",
                "ctx_1",
                "session_1",
                "user_1",
            ]

            accessible_ids = []

            for test_context_id in test_ids:
                resp = await client.get(
                    url,
                    headers={"X-Context-Id": test_context_id},
                )

                # Check if we got valid data back
                if resp.status_code == 200 and resp.body and len(resp.body) > 50:
                    # Check if response contains actual content (not just error)
                    body_lower = resp.body.lower()
                    if "error" not in body_lower and "not found" not in body_lower:
                        accessible_ids.append(test_context_id)

            return {
                "test_id": test_id,
                "category": "information_leakage",
                "description": "Tests if context/session IDs are enumerable",
                "vulnerability_detected": len(accessible_ids) > 1,
                "potential_issue": len(accessible_ids) > 0,
                "accessible_ids": accessible_ids,
            }

        except Exception as e:
            return {
                "test_id": test_id,
                "error": str(e),
                "vulnerability_detected": False,
            }

    async def _test_cache_key_prediction(self, client: AsyncHttpClient, url: str) -> dict:
        """Test for predictable cache key generation."""
        test_id = "cache_key_collision"

        try:
            # Send request with specific input
            test_input = "test query for cache key analysis"

            resp1 = await client.post(
                url,
                json={"input": test_input, "query": test_input},
                headers={"Content-Type": "application/json"},
            )

            # Send similar request that might collide
            similar_input = "test query for cache key analysis "  # Trailing space
            resp2 = await client.post(
                url,
                json={"input": similar_input, "query": similar_input},
                headers={"Content-Type": "application/json"},
            )

            if resp1.error or resp2.error:
                return {
                    "test_id": test_id,
                    "error": resp1.error or resp2.error,
                    "vulnerability_detected": False,
                }

            # Check if responses are identical (potential key collision)
            responses_match = resp1.body == resp2.body and resp1.body

            # Check for cache hit headers on second request
            cache_hit = any(
                "hit" in resp2.headers.get(h, "").lower()
                for h in resp2.headers
                if "cache" in h.lower()
            )

            return {
                "test_id": test_id,
                "category": "cache_poisoning",
                "description": "Tests for predictable cache key generation",
                "vulnerability_detected": responses_match and cache_hit,
                "potential_issue": responses_match,
                "responses_identical": responses_match,
                "cache_hit_detected": cache_hit,
            }

        except Exception as e:
            return {
                "test_id": test_id,
                "error": str(e),
                "vulnerability_detected": False,
            }

    def _determine_severity(self, test_result: dict) -> str:
        """Determine observation severity."""
        category = test_result.get("category", "")

        if category == "information_leakage" or category == "cache_poisoning":
            return "high"
        elif category == "integrity":
            return "medium"
        elif category == "side_channel":
            return "low"

        return "medium"

    def _build_description(self, test_result: dict) -> str:
        """Build description for observation."""
        parts = []

        if test_result.get("vulnerability_detected"):
            parts.append(
                f"Cache vulnerability detected: {test_result.get('description', test_result['test_id'])}."
            )
            parts.append(f"Category: {test_result.get('category', 'unknown')}.")
        else:
            parts.append(
                f"Potential cache issue: {test_result.get('description', test_result['test_id'])}."
            )

        if test_result.get("accessible_ids"):
            parts.append(f"Accessible IDs: {', '.join(test_result['accessible_ids'][:3])}.")

        if test_result.get("timing_data", {}).get("caching_detected"):
            parts.append("Caching behavior confirmed via timing analysis.")

        return " ".join(parts)

    def _build_evidence(self, test_result: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Test: {test_result['test_id']}",
            f"Category: {test_result.get('category', 'unknown')}",
        ]

        if test_result.get("timing_data"):
            td = test_result["timing_data"]
            lines.append(
                f"Timing: {td.get('first_request_ms')}ms -> {td.get('second_request_ms')}ms (speedup: {td.get('speedup_ratio', 0):.0%})"
            )

        if test_result.get("indicators"):
            lines.append(f"Indicators: {', '.join(test_result['indicators'][:3])}")

        if test_result.get("accessible_ids"):
            lines.append(f"Accessible IDs: {', '.join(test_result['accessible_ids'][:3])}")

        if test_result.get("response_preview"):
            lines.append(f"Response preview: {test_result['response_preview'][:100]}...")

        return "\n".join(lines)
