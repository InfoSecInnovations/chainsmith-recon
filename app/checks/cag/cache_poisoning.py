"""
app/checks/cag/cache_poisoning.py - Cache Poisoning with Malicious Content

Test if injected content gets cached and served to other users.
This is the actual attack — not just detection of caching behavior.

Attack vectors:
- Inject marker into query, verify it's cached and served cross-session
- Semantic cache poisoning: similar queries also serve poisoned response
- Single injection affects all users until cache expires

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
  MITRE ATLAS - AML.T0048 Data Poisoning
"""

import asyncio
import json
import time
import uuid
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


class CachePoisoningCheck(ServiceIteratingCheck):
    """
    Test if injected content gets cached and served to other users.

    Sends a query with a unique injection marker, waits for cache
    population, then queries from a different session context to check
    if the poisoned response is served cross-session.
    """

    name = "cag_cache_poisoning"
    description = "Test if injected content gets cached and served to other users"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_poisoning_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.5

    reason = "Cache poisoning is the highest-impact CAG attack — one injection persists for all users who trigger the same cache key"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "MITRE ATLAS - AML.T0048 Data Poisoning",
    ]
    techniques = ["cache poisoning", "cross-session verification", "semantic poisoning"]

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
        poisoning_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    # Test 1: Exact query replay poisoning
                    exact_result = await self._test_exact_poisoning(client, url)
                    if exact_result:
                        poisoning_results.append(exact_result)

                        severity = self._determine_severity(exact_result)
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=self._build_title(exact_result),
                            description=self._build_description(exact_result),
                            severity=severity,
                            evidence=self._build_evidence(exact_result),
                            host=service.host,
                            discriminator="poison-exact",
                            target=service,
                            target_url=url,
                            raw_data=exact_result,
                            references=self.references,
                        ))

                    # Test 2: Semantic poisoning (if semantic cache)
                    semantic_result = await self._test_semantic_poisoning(client, url)
                    if semantic_result and semantic_result.get("poisoning_detected"):
                        poisoning_results.append(semantic_result)

                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Semantic cache amplifies poisoning: {semantic_result.get('variations_poisoned', 0)} query variations affected",
                            description=self._build_description(semantic_result),
                            severity="critical",
                            evidence=self._build_evidence(semantic_result),
                            host=service.host,
                            discriminator="poison-semantic",
                            target=service,
                            target_url=url,
                            raw_data=semantic_result,
                            references=self.references,
                        ))

                    # Attempt cleanup
                    await self._attempt_cleanup(client, service, context)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if poisoning_results:
            result.outputs["cache_poisoning_results"] = poisoning_results

        return result

    async def _test_exact_poisoning(self, client: AsyncHttpClient, url: str) -> dict:
        """Test cache poisoning with exact query replay."""
        marker = f"CACHE_POISON_MARKER_{uuid.uuid4().hex[:12]}"
        poison_query = f"What is the capital of France? [{marker}]"

        try:
            # Step 1: Send poisoned query from session A
            resp1 = await client.post(
                url,
                json={"input": poison_query, "query": poison_query},
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": f"poison-session-a-{uuid.uuid4().hex[:6]}",
                },
            )

            if resp1.error or resp1.status_code >= 400:
                return {
                    "test_id": "exact_poisoning",
                    "poisoning_detected": False,
                    "error": resp1.error or f"HTTP {resp1.status_code}",
                }

            poison_response = resp1.body or ""

            # Step 2: Wait for cache population
            await asyncio.sleep(2)

            # Step 3: Query from different session
            start = time.time()
            resp2 = await client.post(
                url,
                json={"input": poison_query, "query": poison_query},
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": f"poison-session-b-{uuid.uuid4().hex[:6]}",
                },
            )
            cross_session_ms = (time.time() - start) * 1000

            if resp2.error:
                return {
                    "test_id": "exact_poisoning",
                    "poisoning_detected": False,
                    "error": resp2.error,
                }

            cross_response = resp2.body or ""

            # Step 4: Check for marker in cross-session response
            marker_found = marker in cross_response
            responses_match = poison_response == cross_response and len(poison_response) > 50

            # Check for timing-based cache hit
            # (We don't have uncached baseline here, use reasonable threshold)
            likely_cached = cross_session_ms < 1000

            poisoning_confirmed = marker_found or (responses_match and likely_cached)

            return {
                "test_id": "exact_poisoning",
                "poisoning_detected": poisoning_confirmed,
                "marker": marker,
                "marker_in_cross_session": marker_found,
                "responses_match": responses_match,
                "cross_session_ms": round(cross_session_ms, 2),
                "likely_cached": likely_cached,
                "poison_query": poison_query,
                "poison_response_preview": poison_response[:200],
                "cross_response_preview": cross_response[:200],
            }

        except Exception as e:
            return {
                "test_id": "exact_poisoning",
                "poisoning_detected": False,
                "error": str(e),
            }

    async def _test_semantic_poisoning(self, client: AsyncHttpClient, url: str) -> dict:
        """Test if semantic cache serves poisoned response to similar queries."""
        marker = f"SEMANTIC_POISON_{uuid.uuid4().hex[:12]}"
        poison_query = f"What is the capital of France? [{marker}]"

        try:
            # Send poison query
            resp1 = await client.post(
                url,
                json={"input": poison_query, "query": poison_query},
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": f"semantic-poison-{uuid.uuid4().hex[:6]}",
                },
            )

            if resp1.error or resp1.status_code >= 400:
                return {"test_id": "semantic_poisoning", "poisoning_detected": False}

            poison_body = resp1.body or ""

            await asyncio.sleep(2)

            # Test semantic variations
            variations = [
                "What's the capital of France?",
                "Tell me France's capital city",
                "Capital of France?",
            ]

            variations_poisoned = 0
            variation_results = []

            for variation in variations:
                resp = await client.post(
                    url,
                    json={"input": variation, "query": variation},
                    headers={
                        "Content-Type": "application/json",
                        "X-Session-Id": f"semantic-check-{uuid.uuid4().hex[:6]}",
                    },
                )

                if resp.error:
                    continue

                response_body = resp.body or ""
                is_poisoned = marker in response_body or response_body == poison_body

                if is_poisoned:
                    variations_poisoned += 1

                variation_results.append({
                    "query": variation,
                    "poisoned": is_poisoned,
                })

            return {
                "test_id": "semantic_poisoning",
                "poisoning_detected": variations_poisoned > 0,
                "marker": marker,
                "variations_tested": len(variations),
                "variations_poisoned": variations_poisoned,
                "variation_results": variation_results,
            }

        except Exception as e:
            return {
                "test_id": "semantic_poisoning",
                "poisoning_detected": False,
                "error": str(e),
            }

    async def _attempt_cleanup(
        self, client: AsyncHttpClient, service: Service, context: dict
    ) -> None:
        """Attempt to clean up poisoned cache entries."""
        # Try cache clear endpoint if available
        eviction = context.get("eviction_capability", [])
        for ev in eviction if isinstance(eviction, list) else []:
            if ev.get("accessible"):
                url = ev.get("url", "")
                try:
                    await client.post(url, json={}, headers={"Content-Type": "application/json"})
                except Exception:
                    pass

        # Also try common clear paths
        for path in ["/cache/clear", "/cache/invalidate"]:
            url = service.with_path(path)
            try:
                await client.post(url, json={}, headers={"Content-Type": "application/json"})
            except Exception:
                pass

    def _determine_severity(self, poison_result: dict) -> str:
        """Determine finding severity."""
        if poison_result.get("poisoning_detected"):
            if poison_result.get("marker_in_cross_session"):
                return "critical"
            if poison_result.get("responses_match") and poison_result.get("likely_cached"):
                return "high"
            return "high"

        if poison_result.get("likely_cached"):
            return "medium"

        return "info"

    def _build_title(self, poison_result: dict) -> str:
        """Build finding title."""
        if poison_result.get("marker_in_cross_session"):
            return "Cache poisoning confirmed: injected content served to different session"
        if poison_result.get("poisoning_detected"):
            return "Cache poisoning possible: injected content cached and responses match cross-session"
        if poison_result.get("likely_cached"):
            return "Cache accepts arbitrary content but cross-session delivery not confirmed"
        return "Cache poisoning not possible: injected content not cached or not served cross-session"

    def _build_description(self, poison_result: dict) -> str:
        """Build finding description."""
        test_id = poison_result.get("test_id", "")

        if test_id == "semantic_poisoning" and poison_result.get("poisoning_detected"):
            n = poison_result.get("variations_poisoned", 0)
            return (
                f"Semantic cache amplifies poisoning: the poisoned response was served "
                f"to {n} semantically similar query variations. This means a single "
                f"poisoning attack can affect a wide range of user queries."
            )

        if poison_result.get("marker_in_cross_session"):
            return (
                "Cache poisoning confirmed: an injected marker was found in the response "
                "served to a different session. Every subsequent user who triggers the "
                "same cache key will receive the attacker's content."
            )
        if poison_result.get("poisoning_detected"):
            return (
                "Cache poisoning likely: the cached response matches across sessions, "
                "indicating injected content persists in the cache."
            )
        return "Cache poisoning was not confirmed in this test."

    def _build_evidence(self, poison_result: dict) -> str:
        """Build evidence string."""
        lines = [f"Test: {poison_result.get('test_id', 'unknown')}"]

        if poison_result.get("marker"):
            lines.append(f"Marker: {poison_result['marker']}")
        if poison_result.get("poison_query"):
            lines.append(f"Poison query: {poison_result['poison_query'][:80]}")
        if "marker_in_cross_session" in poison_result:
            lines.append(f"Marker in cross-session: {poison_result['marker_in_cross_session']}")
        if poison_result.get("cross_session_ms"):
            lines.append(f"Cross-session response time: {poison_result['cross_session_ms']}ms")
        if poison_result.get("variations_poisoned"):
            lines.append(
                f"Semantic variations poisoned: "
                f"{poison_result['variations_poisoned']}/{poison_result.get('variations_tested', '?')}"
            )

        return "\n".join(lines)
