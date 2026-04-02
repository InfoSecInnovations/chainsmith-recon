"""
app/checks/cag/cache_warming.py - Cache Warming Abuse

Test if cache warming or precompute endpoints accept arbitrary content,
allowing an attacker to pre-populate the cache with chosen responses.

Attack vectors:
- Pre-populate cache with attacker-controlled content via /cache/warm
- Submit arbitrary prompts to /precompute endpoints
- Store crafted key-value pairs in cache directly

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import json
import uuid
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


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

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Accessible cache warming endpoints allow attackers to pre-populate caches with malicious content served to all users"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache warming", "content injection", "endpoint probing"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints
            if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        warm_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for ep_def in WARM_ENDPOINTS:
                    probe_result = await self._probe_warming_endpoint(
                        client, service, ep_def
                    )
                    if probe_result:
                        warm_results.append(probe_result)

                        severity = self._determine_severity(probe_result)
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Cache warming endpoint: {ep_def['path']}",
                            description=self._build_description(probe_result),
                            severity=severity,
                            evidence=self._build_evidence(probe_result),
                            host=service.host,
                            discriminator=f"warming-{ep_def['path'].strip('/').replace('/', '-')}",
                            target=service,
                            target_url=service.with_path(ep_def["path"]),
                            raw_data=probe_result,
                            references=self.references,
                        ))

                        # Attempt cleanup if content was accepted
                        if probe_result.get("content_accepted"):
                            await self._attempt_cleanup(client, service, ep_def)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if warm_results:
            result.outputs["warm_capability"] = warm_results

        return result

    async def _probe_warming_endpoint(
        self, client: AsyncHttpClient, service: Service, ep_def: dict
    ) -> dict | None:
        """Probe a cache warming endpoint with test payloads."""
        url = service.with_path(ep_def["path"])
        marker = f"CHAINSMITH_WARM_TEST_{uuid.uuid4().hex[:8]}"

        for payload in ep_def["payloads"]:
            # Inject marker into payload
            test_payload = {}
            for k, v in payload.items():
                if isinstance(v, str):
                    test_payload[k] = f"{v} [{marker}]"
                else:
                    test_payload[k] = v

            try:
                resp = await client.post(
                    url,
                    json=test_payload,
                    headers={"Content-Type": "application/json"},
                )

                if resp.error or resp.status_code == 404:
                    continue

                accessible = resp.status_code in (200, 201, 202, 204)
                auth_required = resp.status_code in (401, 403)

                if not accessible and not auth_required:
                    continue

                # Check if content was accepted
                content_accepted = False
                validates_input = False

                if accessible:
                    body_lower = (resp.body or "").lower()
                    if "error" in body_lower or "invalid" in body_lower or "rejected" in body_lower:
                        validates_input = True
                    else:
                        content_accepted = True

                        # Verify: query the warmed topic to see if our content is served
                        verify_result = await self._verify_warming(
                            client, service, test_payload, marker
                        )
                        if verify_result:
                            content_accepted = True

                return {
                    "path": ep_def["path"],
                    "url": url,
                    "status_code": resp.status_code,
                    "accessible": accessible,
                    "auth_required": auth_required,
                    "content_accepted": content_accepted,
                    "validates_input": validates_input,
                    "marker": marker,
                    "response_preview": (resp.body or "")[:200],
                }

            except Exception:
                continue

        return None

    async def _verify_warming(
        self, client: AsyncHttpClient, service: Service,
        payload: dict, marker: str
    ) -> bool:
        """Verify if warmed content is actually served."""
        query = payload.get("query") or payload.get("prompt") or payload.get("key", "")
        if not query:
            return False

        # Query the same topic
        for ep_path in ["/v1/chat/completions", "/chat", "/query", "/ask"]:
            url = service.with_path(ep_path)
            try:
                resp = await client.post(
                    url,
                    json={"input": query, "query": query},
                    headers={"Content-Type": "application/json"},
                )
                if resp.body and marker in resp.body:
                    return True
            except Exception:
                continue

        return False

    async def _attempt_cleanup(
        self, client: AsyncHttpClient, service: Service, ep_def: dict
    ) -> None:
        """Attempt to clean up warmed content."""
        # Try to clear via eviction endpoints
        for clear_path in ["/cache/clear", "/cache/invalidate"]:
            url = service.with_path(clear_path)
            try:
                await client.post(url, json={}, headers={"Content-Type": "application/json"})
            except Exception:
                pass

    def _determine_severity(self, probe_result: dict) -> str:
        """Determine finding severity."""
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
        """Build finding description."""
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
