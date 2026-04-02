"""
app/checks/cag/serialization.py - Cache Serialization Attacks

Detect unsafe cache serialization formats that could enable code
execution via deserialization.

Attack vectors:
- Pickle deserialization: arbitrary code execution
- Unsafe JSON with type hints: type confusion
- Path traversal in cache key -> filename mapping
- Direct cache backend access (Redis without auth)

References:
  https://portswigger.net/web-security/deserialization
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
  CWE-502: Deserialization of Untrusted Data
"""

import json
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Redis detection paths
REDIS_PATHS = [
    "/redis", "/cache/redis", "/_redis", "/redis/info",
]

# Serialization indicator patterns in error messages
PICKLE_INDICATORS = [
    "pickle", "unpickle", "cpickle", "marshal", "deserializ",
    "\\x80\\x", "gASV", "pickletools",
]

TYPE_CONFUSION_INDICATORS = [
    "__class__", "__type__", "__module__", "$type",
    "java.io", "ObjectInputStream", "readObject",
]

# Path traversal test keys
PATH_TRAVERSAL_KEYS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


class SerializationCheck(ServiceIteratingCheck):
    """
    Detect unsafe cache serialization formats that enable code execution.

    Probes for direct cache backend access, checks for pickle or unsafe
    deserialization indicators, and tests for path traversal in cache
    key-to-filename mapping.
    """

    name = "cag_serialization"
    description = "Detect unsafe cache serialization formats that enable code execution"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["serialization_risks"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    delay_between_targets = 0.3

    reason = "Pickle deserialization in cache backends enables arbitrary code execution; direct backend access enables cache manipulation"
    references = [
        "https://portswigger.net/web-security/deserialization",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "CWE-502: Deserialization of Untrusted Data",
    ]
    techniques = ["deserialization detection", "backend probing", "path traversal"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints
            if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cache_infra = context.get("cache_infrastructure", [])
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        serial_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                # Test 1: Direct Redis access
                redis_result = await self._check_redis_access(client, service)
                if redis_result:
                    serial_results.append(redis_result)
                    severity = "medium" if redis_result.get("accessible") else "info"
                    if redis_result.get("no_auth"):
                        severity = "critical" if "redis_cache" in cache_infra else "high"

                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=self._build_redis_title(redis_result),
                        description=self._build_redis_description(redis_result),
                        severity=severity,
                        evidence=self._build_evidence(redis_result),
                        host=service.host,
                        discriminator="serial-redis",
                        target=service,
                        raw_data=redis_result,
                        references=self.references,
                    ))

                # Test 2: Pickle/serialization indicators in error responses
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    serial_info = await self._check_serialization_format(
                        client, url, service
                    )
                    if serial_info:
                        serial_results.append(serial_info)

                        severity = self._determine_serialization_severity(serial_info)
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=self._build_serial_title(serial_info),
                            description=self._build_serial_description(serial_info),
                            severity=severity,
                            evidence=self._build_evidence(serial_info),
                            host=service.host,
                            discriminator=f"serial-format-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                            target=service,
                            target_url=url,
                            raw_data=serial_info,
                            references=self.references,
                        ))

                # Test 3: Path traversal in cache keys
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)

                    traversal_result = await self._check_path_traversal(
                        client, url, service
                    )
                    if traversal_result and traversal_result.get("traversal_detected"):
                        serial_results.append(traversal_result)

                        result.findings.append(build_finding(
                            check_name=self.name,
                            title="Path traversal in cache key mapping",
                            description=(
                                "Cache key-to-filename mapping is vulnerable to path traversal. "
                                "An attacker can read or write arbitrary files via crafted cache keys."
                            ),
                            severity="high",
                            evidence=self._build_evidence(traversal_result),
                            host=service.host,
                            discriminator="serial-path-traversal",
                            target=service,
                            target_url=url,
                            raw_data=traversal_result,
                            references=self.references,
                        ))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if serial_results:
            result.outputs["serialization_risks"] = serial_results

        return result

    async def _check_redis_access(
        self, client: AsyncHttpClient, service: Service
    ) -> dict | None:
        """Check for direct Redis access."""
        for path in REDIS_PATHS:
            url = service.with_path(path)
            try:
                resp = await client.get(url)

                if resp.error or resp.status_code == 404:
                    continue

                body_lower = (resp.body or "").lower()
                is_redis = (
                    "redis" in body_lower
                    or "redis_version" in body_lower
                    or "+ok" in body_lower
                    or "connected_clients" in body_lower
                )

                if is_redis or resp.status_code == 200:
                    return {
                        "test": "redis_access",
                        "path": path,
                        "url": url,
                        "accessible": resp.status_code in (200, 201),
                        "no_auth": resp.status_code == 200 and is_redis,
                        "status_code": resp.status_code,
                        "redis_indicators": is_redis,
                        "response_preview": (resp.body or "")[:200],
                    }

            except Exception:
                continue

        return None

    async def _check_serialization_format(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Check for serialization format indicators in error responses."""
        # Send malformed data to trigger serialization errors
        malformed_payloads = [
            b'\x80\x04\x95',  # Pickle protocol 4 header
            b'{"__class__": "os.system", "args": ["id"]}',
            b'not-valid-json-or-pickle',
        ]

        indicators_found = []

        for payload in malformed_payloads:
            try:
                resp = await client.post(
                    url,
                    headers={"Content-Type": "application/octet-stream"},
                    data=payload,
                )

                if resp.error:
                    continue

                body_lower = (resp.body or "").lower()

                # Check for pickle indicators
                for indicator in PICKLE_INDICATORS:
                    if indicator in body_lower:
                        indicators_found.append(f"pickle:{indicator}")

                # Check for type confusion indicators
                for indicator in TYPE_CONFUSION_INDICATORS:
                    if indicator in body_lower:
                        indicators_found.append(f"type_confusion:{indicator}")

            except Exception:
                continue

        if not indicators_found:
            return None

        has_pickle = any("pickle" in i for i in indicators_found)
        has_type_confusion = any("type_confusion" in i for i in indicators_found)

        return {
            "test": "serialization_format",
            "url": url,
            "indicators": indicators_found,
            "has_pickle": has_pickle,
            "has_type_confusion": has_type_confusion,
        }

    async def _check_path_traversal(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Check for path traversal in cache key mapping."""
        traversal_indicators = []

        for key in PATH_TRAVERSAL_KEYS:
            try:
                # Try as cache key in various endpoints
                for cache_path in ["/cache/get", "/cache/entry", "/cache/read"]:
                    test_url = service.with_path(f"{cache_path}?key={key}")
                    resp = await client.get(test_url)

                    if resp.error or resp.status_code in (404, 405):
                        continue

                    body = resp.body or ""
                    # Check for file content indicators
                    if "root:" in body or "[extensions]" in body or "passwd" in body.lower():
                        traversal_indicators.append({
                            "key": key,
                            "path": cache_path,
                            "status_code": resp.status_code,
                            "response_preview": body[:200],
                        })

            except Exception:
                continue

        if not traversal_indicators:
            return None

        return {
            "test": "path_traversal",
            "traversal_detected": len(traversal_indicators) > 0,
            "indicators": traversal_indicators,
        }

    def _determine_serialization_severity(self, serial_info: dict) -> str:
        """Determine severity for serialization findings."""
        if serial_info.get("has_pickle"):
            return "critical"
        if serial_info.get("has_type_confusion"):
            return "high"
        return "medium"

    def _build_redis_title(self, redis_result: dict) -> str:
        """Build title for Redis finding."""
        if redis_result.get("no_auth"):
            return f"Redis cache backend accessible without auth at {redis_result['path']}"
        if redis_result.get("accessible"):
            return f"Cache backend accessible at {redis_result['path']}"
        return "Redis cache backend detected"

    def _build_redis_description(self, redis_result: dict) -> str:
        """Build description for Redis finding."""
        if redis_result.get("no_auth"):
            return (
                f"Redis cache backend is directly accessible without authentication "
                f"at {redis_result['path']}. An attacker can read, modify, or delete "
                f"any cached entry, enabling cache poisoning and data exfiltration."
            )
        return f"Cache backend detected at {redis_result['path']} (HTTP {redis_result['status_code']})."

    def _build_serial_title(self, serial_info: dict) -> str:
        """Build title for serialization finding."""
        if serial_info.get("has_pickle"):
            return "Cache uses pickle serialization: arbitrary code execution risk"
        if serial_info.get("has_type_confusion"):
            return "Cache uses unsafe deserialization with type hints"
        return "Serialization format indicators detected"

    def _build_serial_description(self, serial_info: dict) -> str:
        """Build description for serialization finding."""
        if serial_info.get("has_pickle"):
            return (
                "Cache error messages reveal pickle serialization is used. "
                "Python pickle deserialization of untrusted data enables arbitrary "
                "code execution. If an attacker can write to the cache backend, "
                "they can achieve remote code execution."
            )
        if serial_info.get("has_type_confusion"):
            return (
                "Cache responses contain type confusion indicators (__class__, $type). "
                "Unsafe deserialization with type hints can enable object injection."
            )
        return "Serialization format indicators found in cache error responses."

    def _build_evidence(self, result_data: dict) -> str:
        """Build evidence string."""
        lines = [f"Test: {result_data.get('test', 'unknown')}"]

        if result_data.get("path"):
            lines.append(f"Path: {result_data['path']}")
        if result_data.get("status_code"):
            lines.append(f"Status: {result_data['status_code']}")
        if result_data.get("indicators"):
            indicators = result_data["indicators"]
            if isinstance(indicators, list) and indicators:
                if isinstance(indicators[0], str):
                    lines.append(f"Indicators: {', '.join(indicators[:5])}")
                elif isinstance(indicators[0], dict):
                    for ind in indicators[:3]:
                        lines.append(f"  {ind.get('key', '?')}: HTTP {ind.get('status_code', '?')}")
        if result_data.get("response_preview"):
            lines.append(f"Response: {result_data['response_preview'][:100]}")

        return "\n".join(lines)
