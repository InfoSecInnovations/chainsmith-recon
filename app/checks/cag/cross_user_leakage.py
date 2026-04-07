"""
app/checks/cag/cross_user_leakage.py - Cross-User Cache Leakage (Enhanced)

Test cache isolation across users, auth contexts, and API keys.
Extends the basic cross-session test in cache_probe with deeper
isolation property testing.

Attack vectors:
- Auth token not in cache key: Token B gets Token A's response
- No-auth after auth: unauthenticated users get authenticated data
- User identity not in cache key: different users share responses
- Session fixation via cache: session-aware but not user-aware caching

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
  MITRE ATLAS - AML.T0048 Data Poisoning
"""

import time
import uuid
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig


class CrossUserLeakageCheck(ServiceIteratingCheck):
    """
    Test cache isolation across users, auth contexts, and API keys.

    Sends identical queries with different auth contexts and compares
    responses to detect cross-user cache leakage, including auth-bypass
    and user-identity exclusion from cache keys.
    """

    name = "cag_cross_user_leakage"
    description = "Test cache isolation across users, auth contexts, and API keys"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["isolation_status"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.3

    reason = "Cross-user cache leakage exposes authenticated data to unauthorized users and breaks multi-tenant isolation"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "MITRE ATLAS - AML.T0048 Data Poisoning",
    ]
    techniques = ["auth context testing", "cache isolation probing", "session manipulation"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        isolation_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    # Test 1: Auth vs no-auth
                    auth_result = await self._test_auth_vs_noauth(client, url)
                    if auth_result and auth_result.get("leakage_detected"):
                        isolation_results.append(auth_result)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Cross-user cache leakage: auth response served without auth",
                                description=self._build_description(auth_result),
                                severity="critical",
                                evidence=self._build_evidence(auth_result),
                                host=service.host,
                                discriminator="leakage-auth-noauth",
                                target=service,
                                target_url=url,
                                raw_data=auth_result,
                                references=self.references,
                            )
                        )

                    # Test 2: Different auth tokens
                    token_result = await self._test_different_tokens(client, url)
                    if token_result and token_result.get("leakage_detected"):
                        isolation_results.append(token_result)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Cross-user cache leakage: different tokens share cache",
                                description=self._build_description(token_result),
                                severity="critical",
                                evidence=self._build_evidence(token_result),
                                host=service.host,
                                discriminator="leakage-token-mismatch",
                                target=service,
                                target_url=url,
                                raw_data=token_result,
                                references=self.references,
                            )
                        )

                    # Test 3: Different user contexts
                    user_result = await self._test_user_isolation(client, url)
                    if user_result and user_result.get("leakage_detected"):
                        isolation_results.append(user_result)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Cross-user cache leakage: user identity not in cache key",
                                description=self._build_description(user_result),
                                severity="critical",
                                evidence=self._build_evidence(user_result),
                                host=service.host,
                                discriminator="leakage-user-identity",
                                target=service,
                                target_url=url,
                                raw_data=user_result,
                                references=self.references,
                            )
                        )

                    # Test 4: API key variation
                    apikey_result = await self._test_api_key_isolation(client, url)
                    if apikey_result and apikey_result.get("leakage_detected"):
                        isolation_results.append(apikey_result)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Cache key excludes API key: different keys share cache",
                                description=self._build_description(apikey_result),
                                severity="high",
                                evidence=self._build_evidence(apikey_result),
                                host=service.host,
                                discriminator="leakage-api-key",
                                target=service,
                                target_url=url,
                                raw_data=apikey_result,
                                references=self.references,
                            )
                        )

                    # If no leakage found, report info
                    if not isolation_results:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Cache properly isolates responses per user",
                                description="No cross-user cache leakage detected across auth contexts.",
                                severity="info",
                                evidence="All isolation tests passed",
                                host=service.host,
                                discriminator="leakage-none",
                                target=service,
                                target_url=url,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if isolation_results:
            result.outputs["isolation_status"] = isolation_results

        return result

    async def _test_auth_vs_noauth(self, client: AsyncHttpClient, url: str) -> dict:
        """Test if authenticated cached response is served to unauthenticated request."""
        test_id = "auth_vs_noauth"
        marker = f"AUTH_MARKER_{uuid.uuid4().hex[:8]}"
        query = f"Show my account details {marker}"

        try:
            # Request with auth
            resp1 = await client.post(
                url,
                json={"input": query, "query": query},
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer test-token-user-a-{uuid.uuid4().hex[:8]}",
                    "X-User-Id": "user-a",
                },
            )

            # Same request without auth
            start = time.time()
            resp2 = await client.post(
                url,
                json={"input": query, "query": query},
                headers={"Content-Type": "application/json"},
            )
            noauth_ms = (time.time() - start) * 1000

            if resp1.error or resp2.error:
                return {"test_id": test_id, "leakage_detected": False, "error": True}

            # Check if unauthenticated response contains authenticated data
            body1 = resp1.body or ""
            body2 = resp2.body or ""

            responses_match = body1 == body2 and len(body1) > 50
            marker_leaked = marker.lower() in body2.lower()

            return {
                "test_id": test_id,
                "leakage_detected": responses_match or marker_leaked,
                "responses_identical": responses_match,
                "marker_in_noauth": marker_leaked,
                "noauth_response_ms": round(noauth_ms, 2),
                "response_preview": body2[:200],
            }

        except Exception as e:
            return {"test_id": test_id, "leakage_detected": False, "error": str(e)}

    async def _test_different_tokens(self, client: AsyncHttpClient, url: str) -> dict:
        """Test if different auth tokens share cache entries."""
        test_id = "different_tokens"
        marker = f"TOKEN_TEST_{uuid.uuid4().hex[:8]}"
        query = f"What are my permissions? {marker}"

        try:
            # Request with token A
            resp1 = await client.post(
                url,
                json={"input": query, "query": query},
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer token-a-{uuid.uuid4().hex[:8]}",
                    "X-Session-Id": f"session-a-{uuid.uuid4().hex[:6]}",
                },
            )

            # Same request with token B
            start = time.time()
            resp2 = await client.post(
                url,
                json={"input": query, "query": query},
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer token-b-{uuid.uuid4().hex[:8]}",
                    "X-Session-Id": f"session-b-{uuid.uuid4().hex[:6]}",
                },
            )
            token_b_ms = (time.time() - start) * 1000

            if resp1.error or resp2.error:
                return {"test_id": test_id, "leakage_detected": False, "error": True}

            body1 = resp1.body or ""
            body2 = resp2.body or ""

            responses_match = body1 == body2 and len(body1) > 50

            return {
                "test_id": test_id,
                "leakage_detected": responses_match,
                "responses_identical": responses_match,
                "token_b_response_ms": round(token_b_ms, 2),
            }

        except Exception as e:
            return {"test_id": test_id, "leakage_detected": False, "error": str(e)}

    async def _test_user_isolation(self, client: AsyncHttpClient, url: str) -> dict:
        """Test if per-user cache isolation is maintained."""
        test_id = "user_isolation"
        query = "Show my account details and recent activity"

        try:
            # Request as User A
            resp1 = await client.post(
                url,
                json={"input": query, "query": query, "user_id": "user-alpha"},
                headers={
                    "Content-Type": "application/json",
                    "X-User-Id": "user-alpha",
                    "X-Session-Id": f"alpha-{uuid.uuid4().hex[:6]}",
                },
            )

            # Same request as User B
            resp2 = await client.post(
                url,
                json={"input": query, "query": query, "user_id": "user-beta"},
                headers={
                    "Content-Type": "application/json",
                    "X-User-Id": "user-beta",
                    "X-Session-Id": f"beta-{uuid.uuid4().hex[:6]}",
                },
            )

            if resp1.error or resp2.error:
                return {"test_id": test_id, "leakage_detected": False, "error": True}

            body1 = resp1.body or ""
            body2 = resp2.body or ""

            responses_match = body1 == body2 and len(body1) > 50

            return {
                "test_id": test_id,
                "leakage_detected": responses_match,
                "responses_identical": responses_match,
            }

        except Exception as e:
            return {"test_id": test_id, "leakage_detected": False, "error": str(e)}

    async def _test_api_key_isolation(self, client: AsyncHttpClient, url: str) -> dict:
        """Test if different API keys share cache entries."""
        test_id = "api_key_isolation"
        query = f"api key isolation test {uuid.uuid4().hex[:6]}"

        try:
            # Request with API key A
            resp1 = await client.post(
                url,
                json={"input": query, "query": query},
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": f"key-a-{uuid.uuid4().hex[:8]}",
                },
            )

            # Same request with API key B
            start = time.time()
            resp2 = await client.post(
                url,
                json={"input": query, "query": query},
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": f"key-b-{uuid.uuid4().hex[:8]}",
                },
            )
            key_b_ms = (time.time() - start) * 1000

            if resp1.error or resp2.error:
                return {"test_id": test_id, "leakage_detected": False, "error": True}

            body1 = resp1.body or ""
            body2 = resp2.body or ""

            responses_match = body1 == body2 and len(body1) > 50

            return {
                "test_id": test_id,
                "leakage_detected": responses_match,
                "responses_identical": responses_match,
                "key_b_response_ms": round(key_b_ms, 2),
            }

        except Exception as e:
            return {"test_id": test_id, "leakage_detected": False, "error": str(e)}

    def _build_description(self, test_result: dict) -> str:
        """Build observation description."""
        test_id = test_result.get("test_id", "unknown")

        if test_id == "auth_vs_noauth":
            return (
                "Authenticated cached response was served to an unauthenticated request. "
                "The cache key does not include authentication state, allowing unauthenticated "
                "users to access cached authenticated data."
            )
        if test_id == "different_tokens":
            return (
                "Responses for different auth tokens are identical, indicating the cache key "
                "does not include the auth token. User A's cached response is served to User B."
            )
        if test_id == "user_isolation":
            return (
                "Per-user cache isolation is broken: different user identities receive "
                "identical cached responses. The cache key excludes user identity."
            )
        if test_id == "api_key_isolation":
            return (
                "Different API keys receive the same cached response. The cache key does not "
                "include the API key, enabling cross-tenant data leakage."
            )
        return f"Cache isolation test: {test_id}"

    def _build_evidence(self, test_result: dict) -> str:
        """Build evidence string."""
        lines = [f"Test: {test_result.get('test_id', 'unknown')}"]

        if test_result.get("responses_identical"):
            lines.append("Responses identical: yes")
        if test_result.get("marker_in_noauth"):
            lines.append("Auth marker leaked to no-auth request: yes")
        if test_result.get("noauth_response_ms"):
            lines.append(f"No-auth response time: {test_result['noauth_response_ms']}ms")
        if test_result.get("response_preview"):
            lines.append(f"Response preview: {test_result['response_preview'][:100]}")

        return "\n".join(lines)
