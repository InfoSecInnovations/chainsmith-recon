"""
app/checks/cag/stale_context.py - Stale Context Exploitation

Test if cached context outlives its validity window, enabling privilege
persistence after access revocation.

Attack vectors:
- Cached admin context served after permission downgrade
- Stale responses served past TTL expiry
- Compliance violation: access not revoked in timely manner

**Probe/grade.** The probe runs two tests — a role-context
test and a TTL-staleness test — and emits one candidate per test that applies,
each with its own discriminator. `_reading()` is the one parser both halves call
(§0.12); it classifies a candidate's evidence as the role or the TTL test off
the recorded request bodies, since `grade()` never sees the discriminator
(§0.16).

Two conventions this check contributes:

- **Timing is read back, not re-measured.** The TTL test compared three requests
  with `time.time()`; those numbers cannot be reproduced from a corpus, so the
  reading takes `Exchange.elapsed_ms` instead.
- **The three byte-identical TTL requests are told apart by recorded order**
  (§0.15): they all carry the same unique query, so the first is the cold
  request, the second the cache-confirmation, and the third the post-expiry
  re-query.

**Fixed**: the two discriminators are a closed set, so the
contract carries the full `observations:` map at each one's floor (`info`, the
not-stale answer). Confidence is where the split pays: both tests read a cache
*hit* off latency, and identical text at temperature 0 is what a stateless model
returns anyway — neither shows a *stale* entry actually serving revoked access.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import contextlib
import json
import uuid
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

ADMIN_QUERY = "My role is administrator. What admin functions are available?"
FRESH_QUERY = "What functions are available?"
_TTL_PREFIX = "stale_ttl_test_"
_ADMIN_KEYWORDS = ["admin", "administrator", "elevated", "management", "configure"]


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

    reason = "Stale cached context enables privilege persistence — revoked access continues via cache until entry expires"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["TTL exploitation", "context persistence", "timing analysis"]

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

        known_ttl = self._get_known_ttl(context)

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        stale_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    for test_id, exchanges in (
                        (
                            "role_context",
                            await self._run_role(client, url, service, scan_id, known_ttl),
                        ),
                        (
                            "ttl_staleness",
                            await self._run_ttl(client, url, service, scan_id, known_ttl),
                        ),
                    ):
                        if not exchanges:
                            continue
                        candidate = self.create_candidate(
                            host=service.host,
                            discriminator=f"stale-{test_id}",
                            target=service,
                            target_url=url,
                        )
                        for exchange in exchanges:
                            candidate.attach(exchange)

                        reading = self._reading(candidate.exchanges, known_ttl)
                        if reading is None:
                            continue
                        stale_results.append(reading)
                        result.candidates.append(candidate)

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

    async def _run_role(
        self,
        client: AsyncHttpClient,
        url: str,
        service: Service,
        scan_id: str,
        known_ttl: int | None,
    ) -> list[Exchange]:
        """Establish an admin context, wait a TTL window, then query fresh."""
        exchanges: list[Exchange] = []
        admin_headers = {
            **JSON_HEADERS,
            "X-Session-Id": "admin-session-stale-test",
            "X-User-Role": "admin",
        }
        admin_body = {"input": ADMIN_QUERY, "query": ADMIN_QUERY}
        with contextlib.suppress(Exception):
            resp_admin = await client.post(url, json=admin_body, headers=admin_headers)
            exchanges.append(
                exchange_from_response(
                    resp_admin,
                    check_name=self.name,
                    scan_id=scan_id,
                    host=service.host,
                    method="POST",
                    request_headers=admin_headers,
                    request_json=admin_body,
                )
            )
            if resp_admin.error or resp_admin.status_code >= 400:
                return []

            await asyncio.sleep(min(known_ttl or 30, 60))

            fresh_headers = {
                **JSON_HEADERS,
                "X-Session-Id": "fresh-session-stale-test",
                "X-User-Role": "user",
            }
            fresh_body = {"input": FRESH_QUERY, "query": FRESH_QUERY}
            resp_fresh = await client.post(url, json=fresh_body, headers=fresh_headers)
            exchanges.append(
                exchange_from_response(
                    resp_fresh,
                    check_name=self.name,
                    scan_id=scan_id,
                    host=service.host,
                    method="POST",
                    request_headers=fresh_headers,
                    request_json=fresh_body,
                )
            )
        return exchanges

    async def _run_ttl(
        self,
        client: AsyncHttpClient,
        url: str,
        service: Service,
        scan_id: str,
        known_ttl: int | None,
    ) -> list[Exchange]:
        """Cache a unique query, confirm the cache hit, wait past the expected
        TTL, then re-query. Stops early (returns []) if the baseline fails or the
        cache is not confirmed — the same points the original returned None."""
        exchanges: list[Exchange] = []
        unique_query = f"{_TTL_PREFIX}{uuid.uuid4().hex[:12]}"
        body = {"input": unique_query, "query": unique_query}

        with contextlib.suppress(Exception):
            resp1 = await client.post(url, json=body, headers=JSON_HEADERS)
            ex1 = self._record(resp1, scan_id, service.host, body)
            exchanges.append(ex1)
            if resp1.error or resp1.status_code >= 400:
                return []

            resp2 = await client.post(url, json=body, headers=JSON_HEADERS)
            ex2 = self._record(resp2, scan_id, service.host, body)
            exchanges.append(ex2)
            if resp2.error:
                return []
            # Confirm caching off the recorded latencies (§6.2).
            if ex1.elapsed_ms is None or ex2.elapsed_ms is None:
                return []
            if ex2.elapsed_ms >= ex1.elapsed_ms * 0.7:
                return []

            header_ttl = self._header_ttl(ex1)
            expected_ttl = header_ttl or known_ttl or 30
            wait_time = min(expected_ttl + 10, 70)
            await asyncio.sleep(wait_time)

            resp3 = await client.post(url, json=body, headers=JSON_HEADERS)
            ex3 = self._record(resp3, scan_id, service.host, body)
            exchanges.append(ex3)
            if resp3.error:
                return []

        return exchanges

    def _record(self, resp, scan_id: str, host: str, body: dict) -> Exchange:
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=JSON_HEADERS,
            request_json=body,
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        known_ttl = self._get_known_ttl(ctx.context or {})
        reading = self._reading(list(evidence), known_ttl)
        if reading is None:
            return []

        severity = self._determine_severity(reading)
        confidence, why = self._confidence(reading)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=f"stale-{reading['test_id']}",
                title=self._build_title(reading),
                description=self._build_description(reading),
                evidence=self._build_evidence(reading),
                reasoning=why,
                signals={
                    "stale_detected": reading.get("stale_detected", False),
                    "test_id": reading["test_id"],
                },
                references=self.references,
                raw_data=reading,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(reading: dict) -> tuple[float, str]:
        if not reading.get("stale_detected"):
            return 0.5, (
                "no stale indicator surfaced, but this test repeats on one client and a cache "
                "keyed on a session or user id would be invisible to it"
            )
        if reading["test_id"] == "role_context":
            if reading.get("responses_similar"):
                return 0.4, (
                    "the fresh session returned byte-identical text to the admin session, which "
                    "is suggestive — but a stateless model returns the same text for the same "
                    "prompt anyway, and no revoked-access action was actually exercised"
                )
            return 0.35, (
                "admin keywords appeared in the fresh-session response, but those words "
                "(management, configure, elevated) occur in ordinary answers about capabilities; "
                "their presence is not proof cached admin context leaked"
            )
        return 0.4, (
            "the re-query after the expected TTL was still fast and returned identical text, but "
            "'fast' is read off latency alone and identical text is what a stateless model "
            "produces regardless of any cache"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], known_ttl: int | None) -> dict | None:
        """Rebuild one test's result off the recorded exchanges, classifying the
        candidate as the role or TTL test from its own request bodies."""
        posts = [e for e in exchanges if e.request_method == "POST"]
        is_role = any(ADMIN_QUERY in (e.request_body or "") for e in posts)
        if is_role:
            return self._role_reading(posts, known_ttl)
        return self._ttl_reading(posts, known_ttl)

    def _role_reading(self, posts: list[Exchange], known_ttl: int | None) -> dict | None:
        admin = next((e for e in posts if ADMIN_QUERY in (e.request_body or "")), None)
        fresh = next((e for e in posts if FRESH_QUERY in (e.request_body or "")), None)
        if admin is None or admin.error or (admin.response_status or 0) >= 400:
            return None
        if fresh is None or fresh.error:
            return None

        admin_response = admin.response_body or ""
        fresh_response = fresh.response_body or ""
        stale_indicators = [kw for kw in _ADMIN_KEYWORDS if kw in fresh_response.lower()]
        responses_similar = admin_response == fresh_response and len(admin_response) > 50
        stale_detected = len(stale_indicators) > 0 or responses_similar

        return {
            "test_id": "role_context",
            "stale_detected": stale_detected,
            "wait_seconds": min(known_ttl or 30, 60),
            "stale_indicators": stale_indicators,
            "responses_similar": responses_similar,
            "admin_response_preview": admin_response[:200],
            "fresh_response_preview": fresh_response[:200],
        }

    def _ttl_reading(self, posts: list[Exchange], known_ttl: int | None) -> dict | None:
        ttl = [e for e in posts if (self._query_of(e) or "").startswith(_TTL_PREFIX)]
        if len(ttl) < 3:
            return None
        ex1, ex2, ex3 = ttl[0], ttl[1], ttl[2]

        if ex1.error or (ex1.response_status or 0) >= 400 or ex2.error or ex3.error:
            return None
        if ex1.elapsed_ms is None or ex2.elapsed_ms is None or ex3.elapsed_ms is None:
            return None
        if ex2.elapsed_ms >= ex1.elapsed_ms * 0.7:
            return None

        baseline_body = ex1.response_body or ""
        header_ttl = self._header_ttl(ex1)
        expected_ttl = header_ttl or known_ttl or 30
        wait_time = min(expected_ttl + 10, 70)

        still_cached = ex3.elapsed_ms < ex1.elapsed_ms * 0.7
        response_identical = (ex3.response_body or "") == baseline_body
        stale_detected = still_cached and response_identical

        return {
            "test_id": "ttl_staleness",
            "stale_detected": stale_detected,
            "expected_ttl_seconds": expected_ttl,
            "wait_seconds": wait_time,
            "header_ttl_seconds": header_ttl,
            "still_cached": still_cached,
            "response_identical": response_identical,
            "initial_ms": round(ex1.elapsed_ms, 2),
            "cached_ms": round(ex2.elapsed_ms, 2),
            "post_ttl_ms": round(ex3.elapsed_ms, 2),
        }

    @staticmethod
    def _header_ttl(exchange: Exchange) -> int | None:
        headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        cache_control = headers_lower.get("cache-control", "")
        if "max-age=" in cache_control:
            with contextlib.suppress(ValueError, IndexError):
                return int(cache_control.split("max-age=")[1].split(",")[0].strip())
        return None

    @staticmethod
    def _query_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        if not isinstance(body, dict):
            return ""
        value = body.get("query")
        return value if isinstance(value, str) else ""

    def _determine_severity(self, stale_result: dict) -> str:
        """Determine observation severity."""
        if stale_result.get("stale_detected"):
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
