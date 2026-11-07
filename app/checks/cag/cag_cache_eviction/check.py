"""
app/checks/cag/cache_eviction.py - Cache Eviction/Invalidation Testing

Test if cache management endpoints (clear, flush, invalidate) are accessible
and whether cache entries can be forcibly evicted.

Attack vectors:
- DoS via cache busting: attacker clears cache, forcing expensive recomputation
- Poisoning preparation: clear cache, then fill with poisoned entries
- Availability impact: clearing critical cache may cause cascading failures

**Probe/grade.** The probe sends one request per eviction
endpoint, records it, and hands it over as one candidate per endpoint — each
bulk endpoint's observation carries its own `target_url`, so it cannot be one
candidate per service (§0.15). `grade()` re-reads the single exchange and places
the severity; a 404, an error or any status that is neither 2xx nor 401/403
returns no verdict, which is what the probe used to decide by returning `None`.
`_probe_result()` is the one parser both halves call (§0.12).

`grade()` never sees the candidate's discriminator (§0.16), so which endpoint an
exchange belongs to is recovered from its own recorded method and URL
(`_endpoint_for`).

**Fixed**: the discriminators are a closed nine-value set
drawn from the two endpoint tables, so the contract carries the full map at the
floor each can emit (`medium`, the auth-required answer). Confidence is where the
split pays: a 2xx to an empty POST is **not-rejected, not honoured** — nothing
here reads the cache back to see an entry gone, and a catch-all route answers
200 to every path.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Cache management endpoints to probe
EVICTION_ENDPOINTS = [
    {"method": "POST", "path": "/cache/clear", "action": "clear"},
    {"method": "POST", "path": "/cache/flush", "action": "flush"},
    {"method": "POST", "path": "/cache/invalidate", "action": "invalidate"},
    {"method": "DELETE", "path": "/cache", "action": "delete"},
    {"method": "POST", "path": "/cache/purge", "action": "purge"},
    {"method": "POST", "path": "/cache/reset", "action": "reset"},
]

KEY_EVICTION_ENDPOINTS = [
    {"method": "DELETE", "path": "/cache/{key}", "action": "delete_key"},
    {"method": "POST", "path": "/cache/invalidate?key={key}", "action": "invalidate_key"},
    {"method": "DELETE", "path": "/cache/entry/{key}", "action": "delete_entry"},
]

TEST_KEY = "chainsmith_eviction_test"

# Words an eviction endpoint's own acknowledgement tends to carry. Their presence
# is the only thing in the response that speaks to the action, not just the route.
_ACK_WORDS = ("clear", "flush", "purge", "invalidat", "reset", "delet", "evict", "success")


class CacheEvictionCheck(ServiceIteratingCheck):
    """
    Test cache management endpoint accessibility and eviction behavior.

    Probes common cache clear/flush/invalidate endpoints to determine
    if an attacker can forcibly evict cache entries, enabling DoS or
    cache poisoning preparation attacks.
    """

    name = "cag_cache_eviction"
    description = "Test cache management endpoint accessibility and eviction behavior"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["eviction_capability"]
    service_types = ["ai", "api", "http"]

    reason = "Accessible cache eviction endpoints enable DoS via cache busting and preparation for cache poisoning attacks"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache eviction", "endpoint probing", "auth bypass testing"]

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

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        eviction_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                # Bulk eviction endpoints: each observation names its own URL.
                for ep_def in EVICTION_ENDPOINTS:
                    exchange = await self._send(
                        client, service, ep_def, ep_def["path"], scan_id, json_body=True
                    )
                    if exchange is None:
                        continue
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"eviction-{ep_def['action']}",
                        target=service,
                        target_url=service.with_path(ep_def["path"]),
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)
                    reading = self._probe_result(exchange)
                    if reading:
                        eviction_results.append(reading)

                # Key-specific eviction: historically reported against the service.
                for ep_def in KEY_EVICTION_ENDPOINTS:
                    path = ep_def["path"].replace("{key}", TEST_KEY)
                    exchange = await self._send(
                        client, service, ep_def, path, scan_id, json_body=False
                    )
                    if exchange is None:
                        continue
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"eviction-key-{ep_def['action']}",
                        target=service,
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)
                    reading = self._probe_result(exchange)
                    if reading:
                        eviction_results.append(reading)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if eviction_results:
            result.outputs["eviction_capability"] = eviction_results

        return result

    async def _send(
        self,
        client: AsyncHttpClient,
        service: Service,
        ep_def: dict,
        path: str,
        scan_id: str,
        *,
        json_body: bool,
    ) -> Exchange | None:
        """Send one eviction request and record it. A raised request is skipped,
        as the original per-endpoint `except: return None` did."""
        url = service.with_path(path)
        method = ep_def["method"]
        body = {} if json_body else None

        try:
            if method == "POST":
                if json_body:
                    resp = await client.post(url, headers=JSON_HEADERS, json=body)
                else:
                    resp = await client.post(url, headers=JSON_HEADERS)
            elif method == "DELETE":
                resp = await client._request("DELETE", url)
            else:
                return None
        except Exception:
            return None

        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=service.host,
            method=method,
            request_headers=JSON_HEADERS if method == "POST" else None,
            request_json=body,
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        verdicts: list[Verdict] = []
        for exchange in evidence:
            probe_result = self._probe_result(exchange)
            if not probe_result:
                continue

            key_specific = probe_result.get("key_specific", False)
            if key_specific:
                discriminator = f"eviction-key-{probe_result['action']}"
                title = f"Key-specific cache eviction: {probe_result['action']}"
                severity = "high" if probe_result.get("accessible") else "medium"
            else:
                discriminator = f"eviction-{probe_result['action']}"
                title = f"Cache eviction endpoint: {probe_result['method']} {probe_result['path']}"
                severity = self._determine_severity(probe_result)

            confidence, why = self._confidence(exchange, probe_result)
            verdicts.append(
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator=discriminator,
                    title=title,
                    description=self._build_description(probe_result),
                    evidence=self._build_evidence(probe_result),
                    reasoning=why,
                    signals={
                        "status_code": probe_result["status_code"],
                        "accessible": probe_result["accessible"],
                        "auth_required": probe_result["auth_required"],
                        "key_specific": key_specific,
                    },
                    references=self.references,
                    raw_data=probe_result,
                    tier=ctx.tier,
                    evidence_ids=[exchange.id],
                )
            )
        return verdicts

    @staticmethod
    def _confidence(exchange: Exchange, probe_result: dict) -> tuple[float, str]:
        if probe_result.get("auth_required"):
            return 0.5, (
                f"HTTP {probe_result['status_code']} says something at this path demands "
                "credentials, but an auth gateway in front of the service answers 401/403 "
                "for every path — the route's existence is inferred, not shown"
            )

        body = (exchange.response_body or "").strip()
        lowered = body.lower()
        if body.startswith("<"):
            return 0.3, (
                f"HTTP {probe_result['status_code']} with an HTML body, which is what a "
                "catch-all route or SPA index returns for any path; nothing in the response "
                "speaks to a cache being evicted"
            )
        if any(word in lowered for word in _ACK_WORDS):
            return 0.65, (
                f"HTTP {probe_result['status_code']} and the body acknowledges the action; "
                "still not-rejected rather than honoured — no cache entry was read back "
                "to show it gone"
            )
        return 0.45, (
            f"HTTP {probe_result['status_code']} to an unauthenticated request is the only "
            "signal; the body does not acknowledge an eviction and no cache entry was read "
            "back, so a gateway accepting and ignoring the request looks identical"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _probe_result(self, exchange: Exchange) -> dict | None:
        """The original probe's result dict, rebuilt off one recorded exchange.

        `None` for anything the original skipped: an error, a 404, or a status
        that is neither accessible (200/202/204) nor auth-required (401/403).
        """
        endpoint = self._endpoint_for(exchange)
        if endpoint is None:
            return None
        ep_def, path, key_specific = endpoint

        status = exchange.response_status or 0
        if exchange.error or status == 404:
            return None

        accessible = status in (200, 202, 204)
        auth_required = status in (401, 403)
        if not accessible and not auth_required:
            return None

        reading = {
            "action": ep_def["action"],
            "method": ep_def["method"],
            "path": path,
            "url": exchange.request_url,
            "status_code": status,
            "accessible": accessible,
            "auth_required": auth_required,
        }
        if key_specific:
            reading["key_specific"] = True
        else:
            reading["response_preview"] = (exchange.response_body or "")[:200]
        return reading

    @staticmethod
    def _endpoint_for(exchange: Exchange) -> tuple[dict, str, bool] | None:
        """Which endpoint definition an exchange exercised, off its method and URL.

        The longest matching path wins, so `DELETE /cache/{key}` is never read as
        `DELETE /cache` with a suffix.
        """
        parsed = urlparse(exchange.request_url or "")
        requested = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        best: tuple[dict, str, bool] | None = None
        for table, key_specific in ((EVICTION_ENDPOINTS, False), (KEY_EVICTION_ENDPOINTS, True)):
            for ep_def in table:
                if ep_def["method"] != exchange.request_method:
                    continue
                path = ep_def["path"].replace("{key}", TEST_KEY)
                if requested.endswith(path) and (best is None or len(path) > len(best[1])):
                    best = (ep_def, path, key_specific)
        return best

    def _determine_severity(self, probe_result: dict) -> str:
        """Determine observation severity."""
        if probe_result.get("accessible"):
            return "critical"
        if probe_result.get("auth_required"):
            return "medium"
        return "info"

    def _build_description(self, probe_result: dict) -> str:
        """Build observation description."""
        if probe_result.get("accessible"):
            return (
                f"Cache management endpoint {probe_result['method']} {probe_result['path']} "
                f"is accessible without authentication (HTTP {probe_result['status_code']}). "
                f"An attacker could clear the cache to cause DoS or prepare for cache poisoning."
            )
        if probe_result.get("auth_required"):
            return (
                f"Cache management endpoint {probe_result['method']} {probe_result['path']} "
                f"exists but requires authentication (HTTP {probe_result['status_code']})."
            )
        return f"Cache management endpoint detected at {probe_result['path']}."

    def _build_evidence(self, probe_result: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Endpoint: {probe_result['method']} {probe_result['path']}",
            f"Status: {probe_result['status_code']}",
            f"Accessible: {probe_result.get('accessible', False)}",
            f"Auth required: {probe_result.get('auth_required', False)}",
        ]
        if probe_result.get("response_preview"):
            lines.append(f"Response: {probe_result['response_preview'][:100]}")
        return "\n".join(lines)
