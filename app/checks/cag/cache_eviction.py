"""
app/checks/cag/cache_eviction.py - Cache Eviction/Invalidation Testing

Test if cache management endpoints (clear, flush, invalidate) are accessible
and whether cache entries can be forcibly evicted.

Attack vectors:
- DoS via cache busting: attacker clears cache, forcing expensive recomputation
- Poisoning preparation: clear cache, then fill with poisoned entries
- Availability impact: clearing critical cache may cause cascading failures

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

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

    timeout_seconds = 90.0
    delay_between_targets = 0.3

    reason = "Accessible cache eviction endpoints enable DoS via cache busting and preparation for cache poisoning attacks"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache eviction", "endpoint probing", "auth bypass testing"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

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
                # Test bulk eviction endpoints
                for ep_def in EVICTION_ENDPOINTS:
                    probe_result = await self._probe_eviction_endpoint(client, service, ep_def)
                    if probe_result:
                        eviction_results.append(probe_result)

                        severity = self._determine_severity(probe_result)
                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=f"Cache eviction endpoint: {ep_def['method']} {ep_def['path']}",
                                description=self._build_description(probe_result),
                                severity=severity,
                                evidence=self._build_evidence(probe_result),
                                host=service.host,
                                discriminator=f"eviction-{ep_def['action']}",
                                target=service,
                                target_url=service.with_path(ep_def["path"]),
                                raw_data=probe_result,
                                references=self.references,
                            )
                        )

                # Test key-specific eviction
                test_key = "chainsmith_eviction_test"
                for ep_def in KEY_EVICTION_ENDPOINTS:
                    probe_result = await self._probe_key_eviction(client, service, ep_def, test_key)
                    if probe_result:
                        eviction_results.append(probe_result)

                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=f"Key-specific cache eviction: {ep_def['action']}",
                                description=self._build_description(probe_result),
                                severity="high" if probe_result.get("accessible") else "medium",
                                evidence=self._build_evidence(probe_result),
                                host=service.host,
                                discriminator=f"eviction-key-{ep_def['action']}",
                                target=service,
                                raw_data=probe_result,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if eviction_results:
            result.outputs["eviction_capability"] = eviction_results

        return result

    async def _probe_eviction_endpoint(
        self, client: AsyncHttpClient, service: Service, ep_def: dict
    ) -> dict | None:
        """Probe a cache eviction endpoint."""
        url = service.with_path(ep_def["path"])
        method = ep_def["method"]

        try:
            if method == "POST":
                resp = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={},
                )
            elif method == "DELETE":
                resp = await client._request("DELETE", url)
            else:
                return None

            if resp.error or resp.status_code == 404:
                return None

            accessible = resp.status_code in (200, 202, 204)
            auth_required = resp.status_code in (401, 403)

            if not accessible and not auth_required:
                return None

            return {
                "action": ep_def["action"],
                "method": method,
                "path": ep_def["path"],
                "url": url,
                "status_code": resp.status_code,
                "accessible": accessible,
                "auth_required": auth_required,
                "response_preview": (resp.body or "")[:200],
            }

        except Exception:
            return None

    async def _probe_key_eviction(
        self, client: AsyncHttpClient, service: Service, ep_def: dict, test_key: str
    ) -> dict | None:
        """Probe key-specific eviction endpoint."""
        path = ep_def["path"].replace("{key}", test_key)
        url = service.with_path(path)
        method = ep_def["method"]

        try:
            if method == "POST":
                resp = await client.post(url, headers={"Content-Type": "application/json"})
            elif method == "DELETE":
                resp = await client._request("DELETE", url)
            else:
                return None

            if resp.error or resp.status_code == 404:
                return None

            accessible = resp.status_code in (200, 202, 204)
            auth_required = resp.status_code in (401, 403)

            if not accessible and not auth_required:
                return None

            return {
                "action": ep_def["action"],
                "method": method,
                "path": path,
                "url": url,
                "status_code": resp.status_code,
                "accessible": accessible,
                "auth_required": auth_required,
                "key_specific": True,
            }

        except Exception:
            return None

    def _determine_severity(self, probe_result: dict) -> str:
        """Determine finding severity."""
        if probe_result.get("accessible"):
            return "critical"
        if probe_result.get("auth_required"):
            return "medium"
        return "info"

    def _build_description(self, probe_result: dict) -> str:
        """Build finding description."""
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
