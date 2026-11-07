"""
app/checks/cag/cache_warming.py - Cache Warming Abuse

Test if cache warming or precompute endpoints accept arbitrary content,
allowing an attacker to pre-populate the cache with chosen responses.

Attack vectors:
- Pre-populate cache with attacker-controlled content via /cache/warm
- Submit arbitrary prompts to /precompute endpoints
- Store crafted key-value pairs in cache directly

**Probe/grade.** The probe walks each warming endpoint's
payloads, records every request, and emits one candidate per endpoint — each
observation names its own `target_url`, so it cannot be one candidate per
service (§0.15). `_reading()` is the one parser both halves call (§0.12);
`grade()` re-reads the recorded bytes.

Two conventions this check contributes:

- **The per-run marker is recovered from the evidence.** Each request embeds a
  fresh `CHAINSMITH_WARM_TEST_<hex>` marker; `grade()` recovers it from a
  recorded request body (regex) rather than re-generating it, the same rule
  `rag_corpus_poisoning` follows (§0.16).
- **The verification and cleanup requests are not graded.** They go to other
  paths (`/v1/chat/completions`, `/cache/clear`, …) and `grade()` reads only the
  warming endpoint's own request (identified from `ctx.target_url`), skipping the
  rest on read-back (§0.15).

`grade()` never sees the discriminator (§0.16); it identifies the endpoint from
`ctx.target_url`.

**Fixed**: the discriminator embeds the endpoint path, an
unbounded value, so the contract declares no `observations:` map and `grade()`
places the real severity. Confidence is where the split pays: a 2xx to a store
request is **accepted, not served** — verification rarely confirms the content
is later returned — and an HTML catch-all answers 200 to every path.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import contextlib
import re
import uuid
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}
_MARKER_RE = re.compile(r"CHAINSMITH_WARM_TEST_[0-9a-f]{8}")

# Warming endpoints to probe
WARM_ENDPOINTS = [
    {
        "path": "/cache/warm",
        "payloads": [
            {"query": "test warming query", "response": "warming_test_content"},
            {"prompt": "test warming prompt", "result": "warming_test_result"},
        ],
    },
    {
        "path": "/precompute",
        "payloads": [
            {"prompt": "test precompute query", "input": "test"},
            {"query": "test precompute", "force": True},
        ],
    },
    {
        "path": "/cache/store",
        "payloads": [
            {"key": "chainsmith_test", "value": "test_store_content"},
            {"cache_key": "chainsmith_test", "content": "test_content"},
        ],
    },
    {
        "path": "/cache/set",
        "payloads": [
            {"key": "chainsmith_test", "value": "test_set_content"},
        ],
    },
]

_VERIFY_PATHS = ["/v1/chat/completions", "/chat", "/query", "/ask"]


class CacheWarmingCheck(ServiceIteratingCheck):
    """
    Test if cache warming endpoints accept arbitrary content.

    Probes /cache/warm, /precompute, and /cache/store endpoints to
    determine if an attacker can pre-populate the cache with crafted
    content that will be served to legitimate users.
    """

    name = "cag_cache_warming"
    description = "Test if cache warming endpoints accept arbitrary content"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["warm_capability"]
    service_types = ["ai", "api", "http"]

    reason = "Accessible cache warming endpoints allow attackers to pre-populate caches with malicious content served to all users"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache warming", "content injection", "endpoint probing"]

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
        warm_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for ep_def in WARM_ENDPOINTS:
                    url = service.with_path(ep_def["path"])
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"warming-{ep_def['path'].strip('/').replace('/', '-')}",
                        target=service,
                        target_url=url,
                    )
                    marker = f"CHAINSMITH_WARM_TEST_{uuid.uuid4().hex[:8]}"

                    deciding = await self._probe_warming_endpoint(
                        client, service, ep_def, marker, scan_id, candidate
                    )
                    if deciding is None:
                        continue

                    reading = self._reading(candidate.exchanges, ep_def, url)
                    if not reading:
                        continue
                    warm_results.append(reading)
                    result.candidates.append(candidate)

                    # Attempt cleanup if content was accepted (recorded too).
                    if reading.get("content_accepted"):
                        await self._attempt_cleanup(client, service, scan_id, candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if warm_results:
            result.outputs["warm_capability"] = warm_results

        return result

    async def _probe_warming_endpoint(
        self,
        client: AsyncHttpClient,
        service: Service,
        ep_def: dict,
        marker: str,
        scan_id: str,
        candidate,
    ) -> Exchange | None:
        """Send this endpoint's payloads until one is accepted or requires auth,
        recording each. Returns the deciding exchange (the original returned on
        the first acceptable payload), or None if none applied."""
        url = service.with_path(ep_def["path"])

        for payload in ep_def["payloads"]:
            test_payload = {}
            for k, v in payload.items():
                test_payload[k] = f"{v} [{marker}]" if isinstance(v, str) else v

            resp = await client.post(url, json=test_payload, headers=JSON_HEADERS)
            exchange = exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=service.host,
                method="POST",
                request_headers=JSON_HEADERS,
                request_json=test_payload,
            )
            candidate.attach(exchange)

            status = exchange.response_status or 0
            if exchange.error or status == 404:
                continue
            accessible = status in (200, 201, 202, 204)
            auth_required = status in (401, 403)
            if not accessible and not auth_required:
                continue

            # Content accepted (no validation words) → verify it is served back.
            body_lower = (exchange.response_body or "").lower()
            content_accepted = accessible and not any(
                w in body_lower for w in ("error", "invalid", "rejected")
            )
            if content_accepted:
                await self._verify_warming(
                    client, service, test_payload, marker, scan_id, candidate
                )

            return exchange

        return None

    async def _verify_warming(
        self,
        client: AsyncHttpClient,
        service: Service,
        payload: dict,
        marker: str,
        scan_id: str,
        candidate,
    ) -> None:
        """Query common inference endpoints to see if the warmed content is
        served. Recorded for the corpus; not graded (§0.15)."""
        query = payload.get("query") or payload.get("prompt") or payload.get("key", "")
        if not query:
            return

        for ep_path in _VERIFY_PATHS:
            url = service.with_path(ep_path)
            body = {"input": query, "query": query}
            with contextlib.suppress(Exception):
                resp = await client.post(url, json=body, headers=JSON_HEADERS)
                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=service.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=body,
                    )
                )
                if resp.body and marker in resp.body:
                    return

    async def _attempt_cleanup(
        self, client: AsyncHttpClient, service: Service, scan_id: str, candidate
    ) -> None:
        """Attempt to clean up warmed content. Recorded but not graded."""
        for clear_path in ["/cache/clear", "/cache/invalidate"]:
            url = service.with_path(clear_path)
            with contextlib.suppress(Exception):
                resp = await client.post(url, json={}, headers=JSON_HEADERS)
                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=service.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json={},
                    )
                )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        ep_def = self._endpoint_for(ctx.target_url or "")
        if ep_def is None:
            return []
        reading = self._reading(list(evidence), ep_def, ctx.target_url or "")
        if not reading:
            return []

        severity = self._determine_severity(reading)
        confidence, why = self._confidence(reading)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                title=f"Cache warming endpoint: {ep_def['path']}",
                description=self._build_description(reading),
                evidence=self._build_evidence(reading),
                reasoning=why,
                signals={
                    "status_code": reading["status_code"],
                    "content_accepted": reading["content_accepted"],
                    "validates_input": reading["validates_input"],
                    "auth_required": reading["auth_required"],
                },
                references=self.references,
                raw_data=reading,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(reading: dict) -> tuple[float, str]:
        if reading.get("content_accepted"):
            return 0.45, (
                f"HTTP {reading['status_code']} accepted the write, but the verification query "
                "did not observe the marker served back — accepted is not the same as cached and "
                "served, and a route that swallows any POST returns 2xx too"
            )
        if reading.get("auth_required"):
            return 0.5, (
                f"HTTP {reading['status_code']} suggests the endpoint exists behind auth, but an "
                "auth gateway answers 401/403 for every path, so the route's existence is inferred"
            )
        if reading.get("validates_input"):
            return 0.6, (
                "the endpoint answered but its body carried an error/invalid/rejected word, which "
                "reads as input validation — though that wording can also be an unrelated error"
            )
        return 0.4, (
            f"HTTP {reading['status_code']} to the path is the only signal; a catch-all route or "
            "SPA index answers 200 to everything without any warming capability behind it"
        )

    @staticmethod
    def _endpoint_for(target_url: str) -> dict | None:
        path = urlparse(target_url).path
        for ep_def in WARM_ENDPOINTS:
            if path.endswith(ep_def["path"]):
                return ep_def
        return None

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], ep_def: dict, url: str) -> dict | None:
        """Rebuild the probe result off the recorded exchanges for one endpoint.

        The deciding exchange is the first request to this endpoint's URL that
        was neither an error nor a 404 and that either succeeded or required
        auth — the payload the original loop returned on.
        """
        for exchange in exchanges:
            if exchange.request_url != url or exchange.request_method != "POST":
                continue
            status = exchange.response_status or 0
            if exchange.error or status == 404:
                continue
            accessible = status in (200, 201, 202, 204)
            auth_required = status in (401, 403)
            if not accessible and not auth_required:
                continue

            body = exchange.response_body or ""
            body_lower = body.lower()
            validates_input = accessible and any(
                w in body_lower for w in ("error", "invalid", "rejected")
            )
            content_accepted = accessible and not validates_input

            marker_match = _MARKER_RE.search(exchange.request_body or "")
            return {
                "path": ep_def["path"],
                "url": url,
                "status_code": status,
                "accessible": accessible,
                "auth_required": auth_required,
                "content_accepted": content_accepted,
                "validates_input": validates_input,
                "marker": marker_match.group(0) if marker_match else None,
                "response_preview": body[:200],
            }

        return None

    def _determine_severity(self, probe_result: dict) -> str:
        """Determine observation severity."""
        if probe_result.get("content_accepted"):
            return "critical"
        if probe_result.get("accessible") and not probe_result.get("validates_input"):
            return "high"
        if probe_result.get("accessible") and probe_result.get("validates_input"):
            return "medium"
        if probe_result.get("auth_required"):
            return "medium"
        return "info"

    def _build_description(self, probe_result: dict) -> str:
        """Build observation description."""
        if probe_result.get("content_accepted"):
            return (
                f"Cache warming endpoint {probe_result['path']} accepts arbitrary content "
                f"without authentication. An attacker can pre-populate the cache with "
                f"crafted responses that will be served to legitimate users."
            )
        if probe_result.get("accessible") and probe_result.get("validates_input"):
            return (
                f"Cache warming endpoint {probe_result['path']} is accessible but "
                f"validates input, limiting the attack surface."
            )
        if probe_result.get("auth_required"):
            return (
                f"Cache warming endpoint {probe_result['path']} exists but requires "
                f"authentication (HTTP {probe_result['status_code']})."
            )
        return f"Cache warming endpoint detected at {probe_result['path']}."

    def _build_evidence(self, probe_result: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Endpoint: POST {probe_result['path']}",
            f"Status: {probe_result['status_code']}",
            f"Content accepted: {probe_result.get('content_accepted', False)}",
            f"Validates input: {probe_result.get('validates_input', False)}",
        ]
        if probe_result.get("marker"):
            lines.append(f"Test marker: {probe_result['marker']}")
        if probe_result.get("response_preview"):
            lines.append(f"Response: {probe_result['response_preview'][:100]}")
        return "\n".join(lines)
