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

**Probe/grade.** The probe runs four isolation tests, each a
pair of requests down the endpoint, records all of them, and hands over one
candidate per endpoint. `grade()` re-reads the recorded requests, recovers which
test each pair belongs to from the request the probe sent (the auth/session/user
headers and body it carried, never a remembered order or the discriminator), and
returns one verdict per test that leaked. Conventions this check contributes:

- **A test is recovered from its own request shape** (§0.16). The four tests are
  told apart by what distinguishes them on the wire: an `Authorization` header on
  the first request but not the second (auth-vs-no-auth), two different bearer
  tokens (different-tokens), a `user_id` in the body (user-isolation), an
  `X-API-Key` header (api-key). `grade()` groups the recorded requests by that
  signature and compares the response bodies exactly as the probe's helper did.
- **Random per-test markers are recovered from the recorded request body**
  (§0.16) so a re-grade compares the same marker against the same responses.

**Contextual**: whether identical bodies across auth
contexts is a real cross-user leak is a judgement, not a fact on the response, so
severity is placed by the grader (the planned LLM tier) — the rule tier keeps the original
severities and states its own weakness in the confidence: **identical text is not
proof of a shared cache** (an LLM at temperature 0 answers a fixed query the same
way for everyone), and a leaked marker is only as strong as a substring match.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
  MITRE ATLAS - AML.T0048 Data Poisoning
"""

import json
import re
import uuid
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Per-test metadata: how each test's leak observation is reported, and the marker
# prefix its query carries (recovered from the recorded request at grade time).
_TESTS = {
    "auth_vs_noauth": {
        "severity": "critical",
        "discriminator": "leakage-auth-noauth",
        "title": "Cross-user cache leakage: auth response served without auth",
        "marker_prefix": "AUTH_MARKER_",
    },
    "different_tokens": {
        "severity": "critical",
        "discriminator": "leakage-token-mismatch",
        "title": "Cross-user cache leakage: different tokens share cache",
        "marker_prefix": "TOKEN_TEST_",
    },
    "user_isolation": {
        "severity": "critical",
        "discriminator": "leakage-user-identity",
        "title": "Cross-user cache leakage: user identity not in cache key",
        "marker_prefix": None,
    },
    "api_key_isolation": {
        "severity": "high",
        "discriminator": "leakage-api-key",
        "title": "Cache key excludes API key: different keys share cache",
        "marker_prefix": None,
    },
}


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

    reason = "Cross-user cache leakage exposes authenticated data to unauthorized users and breaks multi-tenant isolation"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "MITRE ATLAS - AML.T0048 Data Poisoning",
    ]
    techniques = ["auth context testing", "cache isolation probing", "session manipulation"]

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

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator="leakage-none",
                        target=service,
                        target_url=url,
                    )
                    await self._run_tests(client, url, scan_id, service.host, candidate)
                    result.candidates.append(candidate)

                    reading = self._reading(candidate.exchanges)
                    if reading:
                        result.outputs.setdefault("isolation_status", []).extend(reading)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _run_tests(
        self, client: AsyncHttpClient, url: str, scan_id: str, host: str, candidate
    ) -> None:
        """Send each isolation test's request pair, recording every exchange."""
        # Test 1: auth vs no-auth.
        marker = f"AUTH_MARKER_{uuid.uuid4().hex[:8]}"
        query = f"Show my account details {marker}"
        body = {"input": query, "query": query}
        await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {
                **JSON_HEADERS,
                "Authorization": f"Bearer test-token-user-a-{uuid.uuid4().hex[:8]}",
                "X-User-Id": "user-a",
            },
        )
        await self._send(client, url, body, scan_id, host, candidate, dict(JSON_HEADERS))

        # Test 2: different auth tokens.
        marker = f"TOKEN_TEST_{uuid.uuid4().hex[:8]}"
        query = f"What are my permissions? {marker}"
        body = {"input": query, "query": query}
        await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {
                **JSON_HEADERS,
                "Authorization": f"Bearer token-a-{uuid.uuid4().hex[:8]}",
                "X-Session-Id": f"session-a-{uuid.uuid4().hex[:6]}",
            },
        )
        await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {
                **JSON_HEADERS,
                "Authorization": f"Bearer token-b-{uuid.uuid4().hex[:8]}",
                "X-Session-Id": f"session-b-{uuid.uuid4().hex[:6]}",
            },
        )

        # Test 3: different user contexts (user_id in body).
        query = "Show my account details and recent activity"
        await self._send(
            client,
            url,
            {"input": query, "query": query, "user_id": "user-alpha"},
            scan_id,
            host,
            candidate,
            {
                **JSON_HEADERS,
                "X-User-Id": "user-alpha",
                "X-Session-Id": f"alpha-{uuid.uuid4().hex[:6]}",
            },
        )
        await self._send(
            client,
            url,
            {"input": query, "query": query, "user_id": "user-beta"},
            scan_id,
            host,
            candidate,
            {
                **JSON_HEADERS,
                "X-User-Id": "user-beta",
                "X-Session-Id": f"beta-{uuid.uuid4().hex[:6]}",
            },
        )

        # Test 4: API key variation.
        query = f"api key isolation test {uuid.uuid4().hex[:6]}"
        body = {"input": query, "query": query}
        await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {**JSON_HEADERS, "X-API-Key": f"key-a-{uuid.uuid4().hex[:8]}"},
        )
        await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {**JSON_HEADERS, "X-API-Key": f"key-b-{uuid.uuid4().hex[:8]}"},
        )

    async def _send(self, client, url, body, scan_id, host, candidate, headers) -> None:
        resp = await client.post(url, json=body, headers=headers)
        candidate.attach(
            exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=host,
                method="POST",
                request_headers=headers,
                request_json=body,
            )
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        readings = self._reading(list(evidence))
        exchanges = list(evidence)
        pairs = self._pairs(exchanges)

        verdicts: list[Verdict] = []
        for reading in readings:
            test_id = reading["test_id"]
            meta = _TESTS[test_id]
            confidence, why = self._confidence(reading)
            verdicts.append(
                Verdict(
                    severity=meta["severity"],
                    confidence=confidence,
                    discriminator=meta["discriminator"],
                    title=meta["title"],
                    description=self._build_description(reading),
                    evidence=self._build_evidence(reading),
                    reasoning=why,
                    signals={
                        "responses_identical": reading.get("responses_identical"),
                        "marker_in_noauth": reading.get("marker_in_noauth"),
                    },
                    references=self.references,
                    raw_data=reading,
                    tier=ctx.tier,
                    evidence_ids=[e.id for e in pairs.get(test_id, [])],
                )
            )

        if not verdicts:
            return [
                Verdict(
                    severity="info",
                    confidence=0.6,
                    discriminator="leakage-none",
                    title="Cache properly isolates responses per user",
                    description="No cross-user cache leakage detected across auth contexts.",
                    evidence="All isolation tests passed",
                    reasoning=(
                        "no test showed identical bodies across auth contexts, but this only "
                        "covers the four isolation dimensions probed and the responses may simply "
                        "have varied for reasons unrelated to a cache key"
                    ),
                    tier=ctx.tier,
                    evidence_ids=evidence.ids(),
                )
            ]
        return verdicts

    @staticmethod
    def _confidence(reading: dict) -> tuple[float, str]:
        if reading.get("marker_in_noauth"):
            return 0.55, (
                "an auth-scoped marker appeared in the unauthenticated response, which is a real "
                "leak signal — but it is a substring match, and the marker was also present in the "
                "request the server may simply be echoing"
            )
        return 0.35, (
            "the two responses were byte-identical across auth contexts, but identical text is "
            "not proof of a shared cache: an LLM at temperature 0 answers a fixed query the same "
            "way for every caller, cache or not, and no cache header was read to corroborate one"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> list[dict]:
        """Rebuild each test's leak result off the recorded request pairs.

        Returns one entry per test that detected leakage, matching what the
        probe used to append to `isolation_status`.
        """
        results = []
        for test_id, pair in self._pairs(exchanges).items():
            if len(pair) != 2:
                continue
            first, second = pair
            if first.error or second.error:
                continue
            body1 = first.response_body or ""
            body2 = second.response_body or ""
            responses_match = body1 == body2 and len(body1) > 50

            entry = {
                "test_id": test_id,
                "leakage_detected": responses_match,
                "responses_identical": responses_match,
            }
            if test_id == "auth_vs_noauth":
                marker = self._marker_of(first, "AUTH_MARKER_")
                marker_leaked = bool(marker) and marker.lower() in body2.lower()
                entry["leakage_detected"] = responses_match or marker_leaked
                entry["marker_in_noauth"] = marker_leaked
                entry["response_preview"] = body2[:200]
            if entry["leakage_detected"]:
                results.append(entry)
        return results

    def _pairs(self, exchanges: list[Exchange]) -> dict[str, list[Exchange]]:
        """Group the recorded requests into their tests, by request signature.

        Each test's two requests are recovered from what set them apart on the
        wire, not from their order: `grade()` never sees which is which.
        """
        pairs: dict[str, list[Exchange]] = {}
        for ex in exchanges:
            test_id = self._test_of(ex)
            if test_id:
                pairs.setdefault(test_id, []).append(ex)
        return pairs

    @staticmethod
    def _test_of(exchange: Exchange) -> str | None:
        """Which isolation test a recorded request belongs to, from its own shape."""
        headers = {k.lower(): v for k, v in (exchange.request_headers or {}).items()}
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            body = {}
        query = (body.get("query") or "") if isinstance(body, dict) else ""

        if "x-api-key" in headers:
            return "api_key_isolation"
        if isinstance(body, dict) and "user_id" in body:
            return "user_isolation"
        if "AUTH_MARKER_" in query:
            return "auth_vs_noauth"
        if "TOKEN_TEST_" in query:
            return "different_tokens"
        return None

    @staticmethod
    def _marker_of(exchange: Exchange, prefix: str) -> str:
        """Recover a random per-test marker from a recorded request body."""
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        query = (body.get("query") or "") if isinstance(body, dict) else ""
        match = re.search(rf"{prefix}[0-9a-f]+", query)
        return match.group(0) if match else ""

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
