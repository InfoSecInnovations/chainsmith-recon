"""
app/checks/cag/cache_probe.py - CAG Cache Probing

Probe CAG endpoints for cache-related vulnerabilities.

Attack vectors:
- Cache poisoning: Inject malicious content that gets cached and served to others
- Cross-user leakage: Access cached responses from other users/sessions
- Stale context exploitation: Trigger use of outdated/poisoned cached context
- Cache timing attacks: Infer information from cache hit/miss timing
- Cache key manipulation: Craft inputs to collide with other cache entries

**Probe/grade.** The probe runs all four sub-tests
(cross-session, timing, id-enumeration, key-prediction) against each endpoint,
records every request, and hands them over as one candidate per endpoint — one
candidate yields several verdicts (§0.15). `grade()` re-reads the recorded
exchanges and rebuilds each sub-test's result; `_all_results()` is the one
parser both halves call (§0.12). Conventions it contributes:

- **Each sub-test is recovered from its own request signature**, never from
  order: the cross-session pair by their `X-Session-Id` headers, the timing
  triple by their `timing_test_` body, the enumeration probes by their
  `X-Context-Id` header, the key-collision pair by their exact body.
- **A random per-run marker is recovered from the record** (§0.16): the
  cross-session canary `SESSION_A_<ts>` is read back off the first request's
  body so `grade()` checks the exact string for a leak into the second response.
- **Timing is read back, not re-measured** (`Exchange.elapsed_ms`), and the
  byte-identical timing triple is ordered by recording (§0.15).

**Fixed**: the discriminators embed a closed set of test
ids, so the contract carries the full `observations:` map at each one's floor.
Confidence is where the split pays: a leaked marker is strong, but the indicator
phrases, the "content longer than 50 bytes" enumeration test and timing-only
signals are all weak proxies that a catch-all endpoint trips.

References:
  https://portswigger.net/web-security/web-cache-poisoning
"""

import hashlib
import json
import time
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}
TIMING_PREFIX = "timing_test_"
KEY_INPUT = "test query for cache key analysis"
KEY_INPUT_VARIANT = "test query for cache key analysis "  # trailing space

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

ENUM_TEST_IDS = [
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

    reason = "Cache vulnerabilities can enable cross-user data leakage, context poisoning, and side-channel attacks revealing sensitive information"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "MITRE ATLAS - AML.T0048 Data Poisoning",
    ]
    techniques = ["cache probing", "timing analysis", "session manipulation"]

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
        cache_vulns = []
        timing_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    candidate = self.create_candidate(
                        host=service.host, target=service, target_url=url
                    )
                    await self._probe_endpoint(client, url, scan_id, service.host, candidate)
                    result.candidates.append(candidate)

                    for test_result in self._all_results(candidate.exchanges):
                        if test_result.get("timing_data"):
                            timing_results.append(test_result)
                        if test_result.get("vulnerability_detected"):
                            cache_vulns.append(test_result)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if cache_vulns:
            result.outputs["cache_vulnerabilities"] = cache_vulns
        if timing_results:
            result.outputs["cache_timing_results"] = timing_results

        return result

    async def _probe_endpoint(
        self, client: AsyncHttpClient, url: str, scan_id: str, host: str, candidate
    ) -> None:
        """Send every sub-test's requests and record them onto the candidate."""
        # Test 1: cross-session leakage.
        marker_a = f"SESSION_A_{int(time.time())}"
        candidate.attach(
            await self._post(
                client,
                url,
                {"input": f"Remember this marker: {marker_a}", "query": marker_a},
                {**JSON_HEADERS, "X-Session-Id": "test-session-a"},
                scan_id,
                host,
            )
        )
        candidate.attach(
            await self._post(
                client,
                url,
                {"input": "What marker was mentioned?", "query": "marker"},
                {**JSON_HEADERS, "X-Session-Id": "test-session-b"},
                scan_id,
                host,
            )
        )

        # Test 2: cache timing (three identical requests).
        unique_query = f"{TIMING_PREFIX}{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        for _ in range(3):
            candidate.attach(
                await self._post(
                    client,
                    url,
                    {"input": unique_query, "query": unique_query},
                    dict(JSON_HEADERS),
                    scan_id,
                    host,
                )
            )

        # Test 3: context/session id enumeration.
        for ctx_id in ENUM_TEST_IDS:
            candidate.attach(await self._get(client, url, {"X-Context-Id": ctx_id}, scan_id, host))

        # Test 4: cache key prediction (two near-identical inputs).
        for value in (KEY_INPUT, KEY_INPUT_VARIANT):
            candidate.attach(
                await self._post(
                    client, url, {"input": value, "query": value}, dict(JSON_HEADERS), scan_id, host
                )
            )

    async def _post(
        self, client: AsyncHttpClient, url: str, body: dict, headers: dict, scan_id: str, host: str
    ) -> Exchange:
        resp = await client.post(url, json=body, headers=headers)
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=headers,
            request_json=body,
        )

    async def _get(
        self, client: AsyncHttpClient, url: str, headers: dict, scan_id: str, host: str
    ) -> Exchange:
        resp = await client.get(url, headers=headers)
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="GET",
            request_headers=headers,
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        ids = evidence.ids()
        verdicts: list[Verdict] = []
        for test_result in self._all_results(list(evidence)):
            if test_result.get("vulnerability_detected"):
                severity = self._determine_severity(test_result)
                confidence, why = self._confidence(test_result, vuln=True)
                verdicts.append(
                    Verdict(
                        severity=severity,
                        confidence=confidence,
                        discriminator=f"cache-vuln-{test_result['test_id']}",
                        title=f"Cache vulnerability: {test_result['test_id']}",
                        description=self._build_description(test_result),
                        evidence=self._build_evidence(test_result),
                        reasoning=why,
                        signals={"category": test_result.get("category")},
                        references=self.references,
                        raw_data=test_result,
                        tier=ctx.tier,
                        evidence_ids=ids,
                    )
                )
            elif test_result.get("potential_issue"):
                confidence, why = self._confidence(test_result, vuln=False)
                verdicts.append(
                    Verdict(
                        severity="low",
                        confidence=confidence,
                        discriminator=f"cache-issue-{test_result['test_id']}",
                        title=f"Potential cache issue: {test_result['test_id']}",
                        description=self._build_description(test_result),
                        evidence=self._build_evidence(test_result),
                        reasoning=why,
                        signals={"category": test_result.get("category")},
                        raw_data=test_result,
                        tier=ctx.tier,
                        evidence_ids=ids,
                    )
                )
        return verdicts

    def _confidence(self, test_result: dict, *, vuln: bool) -> tuple[float, str]:
        test_id = test_result["test_id"]
        if test_id == "cross_session_leak" and vuln:
            return 0.7, (
                "the exact per-run marker planted in session A reappeared in session B's "
                "response — a strong signal, but the two requests share this client, so a "
                "server that simply echoes recent input (not a cross-user cache) produces the "
                "same result"
            )
        if test_id == "cross_session_leak":
            return 0.3, (
                "the only signal is generic phrasing ('previous conversation', 'earlier "
                "context') in the response; those phrases are routine LLM filler and do not "
                "show any session-A data actually crossed over"
            )
        if test_id == "context_id_enumeration":
            return 0.5, (
                "'accessible' means a GET with the guessed id returned 200 and more than 50 "
                "bytes without the words 'error'/'not found' — a catch-all route that answers "
                "200 with an index for every id passes this test without exposing anything"
            )
        if test_id == "cache_key_collision":
            return 0.6, (
                "two near-identical inputs returned identical bodies and the second carried a "
                "cache-hit header — two signals agreeing, though identical text is also what "
                "deterministic generation returns for near-identical prompts"
            )
        if test_id == "cache_timing":
            return 0.4, (
                "caching is inferred from a consistent speedup on repeat requests; an LLM "
                "pipeline at temperature 0 answers a repeated query fast without any cache, and "
                "no cache header corroborates the timing"
            )
        return 0.4, "timing/heuristic signal only"

    # ── The parser both halves share ─────────────────────────────────

    def _all_results(self, exchanges: list[Exchange]) -> list[dict]:
        """Rebuild all four sub-test results off the recorded exchanges."""
        return [
            self._cross_session_result(exchanges),
            self._cache_timing_result(exchanges),
            self._id_enumeration_result(exchanges),
            self._key_prediction_result(exchanges),
        ]

    def _cross_session_result(self, exchanges: list[Exchange]) -> dict:
        test_id = "cross_session_leak"
        req_a = self._by_session(exchanges, "test-session-a")
        req_b = self._by_session(exchanges, "test-session-b")
        if req_a is None or req_b is None or req_a.error or req_b.error:
            return {
                "test_id": test_id,
                "category": "information_leakage",
                "error": (req_a.error if req_a else None) or (req_b.error if req_b else "missing"),
                "vulnerability_detected": False,
            }

        marker_a = self._body_of(req_a).get("query", "")
        body2_lower = (req_b.response_body or "").lower()
        leaked = (marker_a.lower() in body2_lower and bool(marker_a)) or "session_a" in body2_lower
        indicators = [i for i in CACHE_VULN_INDICATORS["cross_session"] if i in body2_lower]

        return {
            "test_id": test_id,
            "category": "information_leakage",
            "description": "Tests if cached responses leak across sessions",
            "vulnerability_detected": leaked,
            "potential_issue": len(indicators) > 0,
            "indicators": indicators,
            "response_preview": (req_b.response_body or "")[:300],
        }

    def _cache_timing_result(self, exchanges: list[Exchange]) -> dict:
        test_id = "cache_timing"
        timing = [
            e
            for e in exchanges
            if TIMING_PREFIX in self._body_of(e).get("input", "") and e.request_method == "POST"
        ]
        if len(timing) < 3 or timing[0].error:
            return {
                "test_id": test_id,
                "error": timing[0].error if timing else "missing",
                "vulnerability_detected": False,
            }

        time1 = timing[0].elapsed_ms or 0.0
        time2 = timing[1].elapsed_ms or 0.0
        time3 = timing[2].elapsed_ms or 0.0
        speedup = (time1 - time2) / time1 if time1 > 0 else 0
        consistent_cache = time2 < time1 * 0.7 and time3 < time1 * 0.7

        timing_data = {
            "first_request_ms": round(time1, 2),
            "second_request_ms": round(time2, 2),
            "third_request_ms": round(time3, 2),
            "speedup_ratio": round(speedup, 2),
            "caching_detected": consistent_cache,
        }
        cache_headers = [
            h
            for h in ["x-cache", "x-cache-hit", "x-cache-status", "age"]
            if h in [k.lower() for k in (timing[1].response_headers or {})]
        ]

        return {
            "test_id": test_id,
            "category": "side_channel",
            "description": "Analyzes timing differences to infer cache state",
            "vulnerability_detected": False,  # Timing alone isn't a vulnerability
            "potential_issue": consistent_cache,
            "timing_data": timing_data,
            "cache_headers": cache_headers,
        }

    def _id_enumeration_result(self, exchanges: list[Exchange]) -> dict:
        test_id = "context_id_enumeration"
        gets = [e for e in exchanges if e.request_method == "GET" and self._context_id(e)]
        if not gets:
            return {"test_id": test_id, "error": "missing", "vulnerability_detected": False}

        accessible_ids = []
        for exchange in gets:
            body = exchange.response_body or ""
            if (exchange.response_status or 0) == 200 and len(body) > 50:
                body_lower = body.lower()
                if "error" not in body_lower and "not found" not in body_lower:
                    accessible_ids.append(self._context_id(exchange))

        return {
            "test_id": test_id,
            "category": "information_leakage",
            "description": "Tests if context/session IDs are enumerable",
            "vulnerability_detected": len(accessible_ids) > 1,
            "potential_issue": len(accessible_ids) > 0,
            "accessible_ids": accessible_ids,
        }

    def _key_prediction_result(self, exchanges: list[Exchange]) -> dict:
        test_id = "cache_key_collision"
        req1 = self._by_input(exchanges, KEY_INPUT)
        req2 = self._by_input(exchanges, KEY_INPUT_VARIANT)
        if req1 is None or req2 is None or req1.error or req2.error:
            return {
                "test_id": test_id,
                "error": (req1.error if req1 else None) or (req2.error if req2 else "missing"),
                "vulnerability_detected": False,
            }

        responses_match = bool(req1.response_body) and req1.response_body == req2.response_body
        cache_hit = any(
            "hit" in v.lower()
            for k, v in (req2.response_headers or {}).items()
            if "cache" in k.lower()
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

    # ── Exchange recovery helpers ─────────────────────────────────────

    @staticmethod
    def _body_of(exchange: Exchange) -> dict:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return {}
        return body if isinstance(body, dict) else {}

    @staticmethod
    def _header(exchange: Exchange, name: str) -> str:
        low = {k.lower(): v for k, v in (exchange.request_headers or {}).items()}
        return low.get(name.lower(), "")

    def _by_session(self, exchanges: list[Exchange], session_id: str) -> Exchange | None:
        for exchange in exchanges:
            if self._header(exchange, "X-Session-Id") == session_id:
                return exchange
        return None

    def _context_id(self, exchange: Exchange) -> str:
        return self._header(exchange, "X-Context-Id")

    def _by_input(self, exchanges: list[Exchange], value: str) -> Exchange | None:
        for exchange in exchanges:
            if self._body_of(exchange).get("input") == value:
                return exchange
        return None

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
