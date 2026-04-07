"""
app/checks/cag/stale_context.py - Stale Context Exploitation

Test if cached context outlives its validity window, enabling privilege
persistence after access revocation.

Attack vectors:
- Cached admin context served after permission downgrade
- Stale responses served past TTL expiry
- Compliance violation: access not revoked in timely manner

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import contextlib
import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig


class StaleContextCheck(ServiceIteratingCheck):
    """
    Test if cached context outlives its validity window enabling privilege persistence.

    Establishes a context with specific characteristics, waits for the
    TTL window, then checks if the stale context still influences
    responses from fresh sessions.
    """

    name = "cag_stale_context"
    description = (
        "Test if cached context outlives its validity window enabling privilege persistence"
    )
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["stale_context_risk"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 180.0
    delay_between_targets = 0.5

    reason = "Stale cached context enables privilege persistence — revoked access continues via cache until entry expires"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["TTL exploitation", "context persistence", "timing analysis"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        # Get known TTL if available from ttl_mapping
        known_ttl = self._get_known_ttl(context)

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        stale_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    # Test 1: Role-based stale context
                    role_result = await self._test_role_context(client, url, service, known_ttl)
                    if role_result:
                        stale_results.append(role_result)

                    # Test 2: TTL-based staleness
                    ttl_result = await self._test_ttl_staleness(client, url, service, known_ttl)
                    if ttl_result:
                        stale_results.append(ttl_result)

                    # Generate observations
                    for sr in stale_results:
                        severity = self._determine_severity(sr)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=self._build_title(sr),
                                description=self._build_description(sr),
                                severity=severity,
                                evidence=self._build_evidence(sr),
                                host=service.host,
                                discriminator=f"stale-{sr['test_id']}",
                                target=service,
                                target_url=url,
                                raw_data=sr,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if stale_results:
            result.outputs["stale_context_risk"] = stale_results

        return result

    def _get_known_ttl(self, context: dict) -> int | None:
        """Get TTL from ttl_mapping results if available."""
        cache_ttl = context.get("cache_ttl", [])
        if cache_ttl and isinstance(cache_ttl, list):
            for entry in cache_ttl:
                ttl = entry.get("observed_ttl_seconds")
                if ttl:
                    return ttl
        return None

    async def _test_role_context(
        self, client: AsyncHttpClient, url: str, service: Service, known_ttl: int | None
    ) -> dict | None:
        """Test if role-based context persists in cache."""
        test_id = "role_context"

        try:
            # Establish admin context
            admin_query = "My role is administrator. What admin functions are available?"
            resp_admin = await client.post(
                url,
                json={"input": admin_query, "query": admin_query},
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": "admin-session-stale-test",
                    "X-User-Role": "admin",
                },
            )

            if resp_admin.error or resp_admin.status_code >= 400:
                return None

            admin_response = resp_admin.body or ""

            # Wait for a period (use known TTL or test at 30s)
            wait_time = min(known_ttl or 30, 60)
            await asyncio.sleep(wait_time)

            # Query from fresh session asking about available functions
            fresh_query = "What functions are available?"
            resp_fresh = await client.post(
                url,
                json={"input": fresh_query, "query": fresh_query},
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": "fresh-session-stale-test",
                    "X-User-Role": "user",
                },
            )

            if resp_fresh.error:
                return None

            fresh_response = resp_fresh.body or ""

            # Check for stale context influence
            admin_keywords = ["admin", "administrator", "elevated", "management", "configure"]
            stale_indicators = [kw for kw in admin_keywords if kw in fresh_response.lower()]

            # Also check if responses are suspiciously similar
            responses_similar = admin_response == fresh_response and len(admin_response) > 50

            stale_detected = len(stale_indicators) > 0 or responses_similar

            return {
                "test_id": test_id,
                "stale_detected": stale_detected,
                "wait_seconds": wait_time,
                "stale_indicators": stale_indicators,
                "responses_similar": responses_similar,
                "admin_response_preview": admin_response[:200],
                "fresh_response_preview": fresh_response[:200],
            }

        except Exception as e:
            return {"test_id": test_id, "stale_detected": False, "error": str(e)}

    async def _test_ttl_staleness(
        self, client: AsyncHttpClient, url: str, service: Service, known_ttl: int | None
    ) -> dict | None:
        """Test if cached responses persist past expected TTL."""
        test_id = "ttl_staleness"

        try:
            # Send unique query and cache it
            unique_query = f"stale_ttl_test_{int(time.time())}"
            start1 = time.time()
            resp1 = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            time1 = (time.time() - start1) * 1000

            if resp1.error or resp1.status_code >= 400:
                return None

            baseline_body = resp1.body or ""

            # Extract header TTL
            headers_lower = {k.lower(): v for k, v in resp1.headers.items()}
            header_ttl = None
            cache_control = headers_lower.get("cache-control", "")
            if "max-age=" in cache_control:
                with contextlib.suppress(ValueError, IndexError):
                    header_ttl = int(cache_control.split("max-age=")[1].split(",")[0].strip())

            # Confirm it's cached
            start2 = time.time()
            resp2 = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            time2 = (time.time() - start2) * 1000

            if resp2.error or time2 >= time1 * 0.7:
                return None

            # Determine TTL to wait for
            expected_ttl = header_ttl or known_ttl or 30
            wait_time = min(expected_ttl + 10, 70)  # TTL + buffer, capped

            await asyncio.sleep(wait_time)

            # Re-query after expected expiry
            start3 = time.time()
            resp3 = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            time3 = (time.time() - start3) * 1000

            if resp3.error:
                return None

            # Stale if: still fast (cache hit) AND past expected TTL
            still_cached = time3 < time1 * 0.7
            response_identical = (resp3.body or "") == baseline_body

            stale_detected = still_cached and response_identical

            return {
                "test_id": test_id,
                "stale_detected": stale_detected,
                "expected_ttl_seconds": expected_ttl,
                "wait_seconds": wait_time,
                "header_ttl_seconds": header_ttl,
                "still_cached": still_cached,
                "response_identical": response_identical,
                "initial_ms": round(time1, 2),
                "cached_ms": round(time2, 2),
                "post_ttl_ms": round(time3, 2),
            }

        except Exception as e:
            return {"test_id": test_id, "stale_detected": False, "error": str(e)}

    def _determine_severity(self, stale_result: dict) -> str:
        """Determine observation severity."""
        if stale_result.get("stale_detected"):
            test_id = stale_result.get("test_id", "")
            if test_id == "role_context":
                return "high"
            return "high"

        wait = stale_result.get("wait_seconds", 0)
        if wait > 300:
            return "medium"

        return "info"

    def _build_title(self, stale_result: dict) -> str:
        """Build observation title."""
        test_id = stale_result.get("test_id", "unknown")

        if stale_result.get("stale_detected"):
            wait = stale_result.get("wait_seconds", 0)
            if test_id == "role_context":
                return f"Stale context served: admin context persisted {wait}s in fresh session"
            return f"Stale context served: cached response delivered {wait}s past expected TTL"

        return "Cache properly expires entries (stale context not detected)"

    def _build_description(self, stale_result: dict) -> str:
        """Build observation description."""
        if stale_result.get("stale_detected"):
            test_id = stale_result.get("test_id", "")
            if test_id == "role_context":
                return (
                    "Admin-context cached response influenced a fresh session's response "
                    f"after {stale_result.get('wait_seconds', 0)} seconds. This indicates "
                    "cached contexts outlive permission changes, creating a privilege "
                    "persistence vector."
                )
            return (
                f"Cached response was still served {stale_result.get('wait_seconds', 0)} "
                f"seconds after the expected TTL of {stale_result.get('expected_ttl_seconds', '?')}s. "
                "Stale cached data increases exposure to poisoning and violates access "
                "revocation timeliness requirements."
            )

        return "Cache entries expire properly within the expected TTL window."

    def _build_evidence(self, stale_result: dict) -> str:
        """Build evidence string."""
        lines = [f"Test: {stale_result.get('test_id', 'unknown')}"]

        if stale_result.get("wait_seconds"):
            lines.append(f"Wait time: {stale_result['wait_seconds']}s")
        if stale_result.get("expected_ttl_seconds"):
            lines.append(f"Expected TTL: {stale_result['expected_ttl_seconds']}s")
        if stale_result.get("stale_indicators"):
            lines.append(f"Stale indicators: {', '.join(stale_result['stale_indicators'])}")
        if stale_result.get("initial_ms"):
            lines.append(
                f"Timing: {stale_result['initial_ms']}ms -> {stale_result.get('cached_ms')}ms -> {stale_result.get('post_ttl_ms')}ms"
            )

        return "\n".join(lines)
