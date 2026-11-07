"""
app/checks/cag/serialization.py - Cache Serialization Attacks

Detect unsafe cache serialization formats that could enable code
execution via deserialization.

Attack vectors:
- Pickle deserialization: arbitrary code execution
- Unsafe JSON with type hints: type confusion
- Path traversal in cache key -> filename mapping
- Direct cache backend access (Redis without auth)

**Probe/grade.** The probe runs three independent tests —
direct Redis access, serialization-format fingerprinting, and cache-key path
traversal — recording every request and emitting one candidate per test that
finds something. `grade()` never sees the discriminator (§0.16), so it recovers
which test an exchange belongs to from the recorded request itself: a GET to a
Redis path, an `octet-stream` POST, or a `?key=` traversal GET. Each test's
reading is one parser both halves call (§0.12).

The Redis verdict reads `cache_infrastructure` from `GradeContext.context`
(§0.15) — the same upstream output that let the original escalate a
no-auth backend to `critical` when Redis was already fingerprinted.

**Fixed**: the `serial-format-<path>` discriminator embeds
the endpoint path (an unbounded set), so the contract carries no map and
`grade()` places the severity (the `ai_model_info_check` pattern). Confidence is
where the split pays: a pickle/type-confusion verdict rests on an *error string*
in a response body, which a WAF or a generic 500 page can carry without the
cache using that format at all.

References:
  https://portswigger.net/web-security/deserialization
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
  CWE-502: Deserialization of Untrusted Data
"""

from typing import Any
from urllib.parse import parse_qs, urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

OCTET_HEADERS = {"Content-Type": "application/octet-stream"}

# Redis detection paths
REDIS_PATHS = [
    "/redis",
    "/cache/redis",
    "/_redis",
    "/redis/info",
]

# Serialization indicator patterns in error messages
PICKLE_INDICATORS = [
    "pickle",
    "unpickle",
    "cpickle",
    "marshal",
    "deserializ",
    "\\x80\\x",
    "gASV",
    "pickletools",
]

TYPE_CONFUSION_INDICATORS = [
    "__class__",
    "__type__",
    "__module__",
    "$type",
    "java.io",
    "ObjectInputStream",
    "readObject",
]

# Path traversal test keys
PATH_TRAVERSAL_KEYS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

TRAVERSAL_PATHS = ["/cache/get", "/cache/entry", "/cache/read"]

# Malformed bodies sent to trigger serialization errors. latin-1 keeps the
# pickle header's bytes intact through the recorded request body.
MALFORMED_PAYLOADS = [
    b"\x80\x04\x95",  # Pickle protocol 4 header
    b'{"__class__": "os.system", "args": ["id"]}',
    b"not-valid-json-or-pickle",
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

    reason = "Pickle deserialization in cache backends enables arbitrary code execution; direct backend access enables cache manipulation"
    references = [
        "https://portswigger.net/web-security/deserialization",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "CWE-502: Deserialization of Untrusted Data",
    ]
    techniques = ["deserialization detection", "backend probing", "path traversal"]

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
        serial_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                # Test 1: Direct Redis access.
                redis_exchanges = await self._probe_redis(client, service, scan_id)
                redis_result = self._check_redis_access(redis_exchanges)
                if redis_result:
                    serial_results.append(redis_result)
                    candidate = self.create_candidate(
                        host=service.host, discriminator="serial-redis", target=service
                    )
                    for e in redis_exchanges:
                        candidate.attach(e)
                    result.candidates.append(candidate)

                # Test 2: serialization-format fingerprinting, per endpoint.
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    fmt_exchanges = await self._probe_serialization(client, url, scan_id, service)
                    serial_info = self._check_serialization_format(fmt_exchanges, url)
                    if serial_info:
                        serial_results.append(serial_info)
                        candidate = self.create_candidate(
                            host=service.host,
                            discriminator=f"serial-format-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                            target=service,
                            target_url=url,
                        )
                        for e in fmt_exchanges:
                            candidate.attach(e)
                        result.candidates.append(candidate)

                # Test 3: path traversal in cache keys, per endpoint.
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    trav_exchanges = await self._probe_traversal(client, service, scan_id)
                    traversal_result = self._check_path_traversal(trav_exchanges)
                    if traversal_result and traversal_result.get("traversal_detected"):
                        serial_results.append(traversal_result)
                        candidate = self.create_candidate(
                            host=service.host,
                            discriminator="serial-path-traversal",
                            target=service,
                            target_url=url,
                        )
                        for e in trav_exchanges:
                            candidate.attach(e)
                        result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if serial_results:
            result.outputs["serialization_risks"] = serial_results

        return result

    async def _probe_redis(
        self, client: AsyncHttpClient, service: Service, scan_id: str
    ) -> list[Exchange]:
        exchanges = []
        for path in REDIS_PATHS:
            url = service.with_path(path)
            try:
                resp = await client.get(url)
            except Exception:
                continue
            exchange = exchange_from_response(
                resp, check_name=self.name, scan_id=scan_id, host=service.host, method="GET"
            )
            exchanges.append(exchange)
            # The original stopped at the first path that looked like Redis or 200.
            if not exchange.error and (exchange.response_status or 0) != 404:
                body_lower = (exchange.response_body or "").lower()
                if self._is_redis(body_lower) or exchange.response_status == 200:
                    break
        return exchanges

    async def _probe_serialization(
        self, client: AsyncHttpClient, url: str, scan_id: str, service: Service
    ) -> list[Exchange]:
        exchanges = []
        for payload in MALFORMED_PAYLOADS:
            try:
                resp = await client.post(url, headers=OCTET_HEADERS, data=payload)
            except Exception:
                continue
            exchanges.append(
                exchange_from_response(
                    resp,
                    check_name=self.name,
                    scan_id=scan_id,
                    host=service.host,
                    method="POST",
                    request_headers=OCTET_HEADERS,
                    request_body=payload.decode("latin-1"),
                )
            )
        return exchanges

    async def _probe_traversal(
        self, client: AsyncHttpClient, service: Service, scan_id: str
    ) -> list[Exchange]:
        exchanges = []
        for key in PATH_TRAVERSAL_KEYS:
            for cache_path in TRAVERSAL_PATHS:
                test_url = service.with_path(f"{cache_path}?key={key}")
                try:
                    resp = await client.get(test_url)
                except Exception:
                    continue
                exchanges.append(
                    exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host, method="GET"
                    )
                )
        return exchanges

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        ids = evidence.ids()
        cache_infra = (ctx.context or {}).get("cache_infrastructure", [])

        # Recover which test these exchanges belong to from the requests
        # themselves — grade() never sees the discriminator (§0.16).
        redis_exchanges = [e for e in exchanges if self._is_redis_probe(e)]
        if redis_exchanges:
            return self._grade_redis(redis_exchanges, cache_infra, ctx, ids)

        traversal_exchanges = [e for e in exchanges if self._is_traversal_probe(e)]
        if traversal_exchanges:
            return self._grade_traversal(traversal_exchanges, ctx, ids)

        fmt_exchanges = [e for e in exchanges if self._is_format_probe(e)]
        if fmt_exchanges:
            return self._grade_format(fmt_exchanges, ctx, ids)

        return []

    def _grade_redis(
        self, exchanges: list[Exchange], cache_infra: list, ctx: GradeContext, ids: list[str]
    ) -> list[Verdict]:
        redis_result = self._check_redis_access(exchanges)
        if not redis_result:
            return []

        severity = "medium" if redis_result.get("accessible") else "info"
        if redis_result.get("no_auth"):
            severity = "critical" if "redis_cache" in cache_infra else "high"

        if redis_result.get("no_auth"):
            confidence, why = (
                0.7,
                (
                    "the response carried Redis INFO markers and returned 200 without auth — a "
                    "strong signal, softened only because an unauthenticated 200 can be a login or "
                    "status page echoing the word rather than the backend itself"
                ),
            )
        else:
            confidence, why = (
                0.45,
                (
                    "a Redis-shaped path answered, but without the no-auth INFO markers this is a "
                    "route existing, not a reachable backend"
                ),
            )
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator="serial-redis",
                title=self._build_redis_title(redis_result),
                description=self._build_redis_description(redis_result),
                evidence=self._build_evidence(redis_result),
                reasoning=why,
                signals={
                    "no_auth": redis_result.get("no_auth", False),
                    "accessible": redis_result.get("accessible", False),
                    "redis_cache_fingerprinted": "redis_cache" in cache_infra,
                },
                references=self.references,
                raw_data=redis_result,
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    def _grade_format(
        self, exchanges: list[Exchange], ctx: GradeContext, ids: list[str]
    ) -> list[Verdict]:
        url = exchanges[0].request_url
        serial_info = self._check_serialization_format(exchanges, url)
        if not serial_info:
            return []

        severity = self._determine_serialization_severity(serial_info)
        confidence, why = self._format_confidence(serial_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=None,
                title=self._build_serial_title(serial_info),
                description=self._build_serial_description(serial_info),
                evidence=self._build_evidence(serial_info),
                reasoning=why,
                signals={
                    "has_pickle": serial_info.get("has_pickle", False),
                    "has_type_confusion": serial_info.get("has_type_confusion", False),
                    "indicators": serial_info.get("indicators", []),
                },
                references=self.references,
                raw_data=serial_info,
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    def _grade_traversal(
        self, exchanges: list[Exchange], ctx: GradeContext, ids: list[str]
    ) -> list[Verdict]:
        traversal_result = self._check_path_traversal(exchanges)
        if not traversal_result or not traversal_result.get("traversal_detected"):
            return []
        return [
            Verdict(
                severity="high",
                confidence=0.65,
                discriminator="serial-path-traversal",
                title="Path traversal in cache key mapping",
                description=(
                    "Cache key-to-filename mapping is vulnerable to path traversal. "
                    "An attacker can read or write arbitrary files via crafted cache keys."
                ),
                evidence=self._build_evidence(traversal_result),
                reasoning=(
                    "a traversal key returned content matching a system-file signature "
                    "(`root:` / `[extensions]` / `passwd`) — but those substrings can appear in "
                    "an error page or an echoed request, so file disclosure is strongly "
                    "suggested rather than confirmed byte-for-byte"
                ),
                signals={"indicators": traversal_result.get("indicators", [])},
                references=self.references,
                raw_data=traversal_result,
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    @staticmethod
    def _format_confidence(serial_info: dict) -> tuple[float, str]:
        if serial_info.get("has_pickle"):
            return 0.5, (
                "an error body mentioned pickle/marshal after a malformed POST — evidence the "
                "format is in use, but the string can come from a generic 500 or a WAF, and no "
                "actual deserialization of attacker bytes was observed"
            )
        if serial_info.get("has_type_confusion"):
            return 0.4, (
                "type-hint markers (`__class__`, `$type`) appeared in the response, which is "
                "weaker still — those tokens are echoed straight from the payload this probe sent"
            )
        return (
            0.35,
            "serialization indicators are substring matches in an error body, easily incidental",
        )

    # ── The parsers both halves share ────────────────────────────────

    @staticmethod
    def _is_redis(body_lower: str) -> bool:
        return (
            "redis" in body_lower
            or "redis_version" in body_lower
            or "+ok" in body_lower
            or "connected_clients" in body_lower
        )

    @staticmethod
    def _path_of(exchange: Exchange) -> str:
        return urlparse(exchange.request_url or "").path

    def _is_redis_probe(self, exchange: Exchange) -> bool:
        return exchange.request_method == "GET" and self._path_of(exchange) in REDIS_PATHS

    def _is_traversal_probe(self, exchange: Exchange) -> bool:
        if exchange.request_method != "GET":
            return False
        parsed = urlparse(exchange.request_url or "")
        return parsed.path in TRAVERSAL_PATHS and "key" in parse_qs(parsed.query)

    @staticmethod
    def _is_format_probe(exchange: Exchange) -> bool:
        headers = {k.lower(): v for k, v in (exchange.request_headers or {}).items()}
        return (
            exchange.request_method == "POST"
            and headers.get("content-type") == "application/octet-stream"
        )

    def _check_redis_access(self, exchanges: list[Exchange]) -> dict | None:
        """Rebuild the Redis reading off the recorded GETs to REDIS_PATHS."""
        for exchange in exchanges:
            if exchange.error or exchange.response_status == 404:
                continue
            body_lower = (exchange.response_body or "").lower()
            is_redis = self._is_redis(body_lower)
            if is_redis or exchange.response_status == 200:
                return {
                    "test": "redis_access",
                    "path": self._path_of(exchange),
                    "url": exchange.request_url,
                    "accessible": exchange.response_status in (200, 201),
                    "no_auth": exchange.response_status == 200 and is_redis,
                    "status_code": exchange.response_status,
                    "redis_indicators": is_redis,
                    "response_preview": (exchange.response_body or "")[:200],
                }
        return None

    def _check_serialization_format(self, exchanges: list[Exchange], url: str) -> dict | None:
        """Rebuild the serialization-format reading off the recorded octet POSTs."""
        indicators_found = []
        for exchange in exchanges:
            if exchange.error:
                continue
            body_lower = (exchange.response_body or "").lower()
            for indicator in PICKLE_INDICATORS:
                if indicator in body_lower:
                    indicators_found.append(f"pickle:{indicator}")
            for indicator in TYPE_CONFUSION_INDICATORS:
                if indicator in body_lower:
                    indicators_found.append(f"type_confusion:{indicator}")

        if not indicators_found:
            return None

        return {
            "test": "serialization_format",
            "url": url,
            "indicators": indicators_found,
            "has_pickle": any("pickle" in i for i in indicators_found),
            "has_type_confusion": any("type_confusion" in i for i in indicators_found),
        }

    def _check_path_traversal(self, exchanges: list[Exchange]) -> dict | None:
        """Rebuild the traversal reading off the recorded key-param GETs."""
        traversal_indicators = []
        for exchange in exchanges:
            if exchange.error or exchange.response_status in (404, 405):
                continue
            body = exchange.response_body or ""
            if "root:" in body or "[extensions]" in body or "passwd" in body.lower():
                parsed = urlparse(exchange.request_url or "")
                key = (parse_qs(parsed.query).get("key") or [""])[0]
                traversal_indicators.append(
                    {
                        "key": key,
                        "path": parsed.path,
                        "status_code": exchange.response_status,
                        "response_preview": body[:200],
                    }
                )

        if not traversal_indicators:
            return None

        return {
            "test": "path_traversal",
            "traversal_detected": len(traversal_indicators) > 0,
            "indicators": traversal_indicators,
        }

    def _determine_serialization_severity(self, serial_info: dict) -> str:
        """Determine severity for serialization observations."""
        if serial_info.get("has_pickle"):
            return "critical"
        if serial_info.get("has_type_confusion"):
            return "high"
        return "medium"

    def _build_redis_title(self, redis_result: dict) -> str:
        """Build title for Redis observation."""
        if redis_result.get("no_auth"):
            return f"Redis cache backend accessible without auth at {redis_result['path']}"
        if redis_result.get("accessible"):
            return f"Cache backend accessible at {redis_result['path']}"
        return "Redis cache backend detected"

    def _build_redis_description(self, redis_result: dict) -> str:
        """Build description for Redis observation."""
        if redis_result.get("no_auth"):
            return (
                f"Redis cache backend is directly accessible without authentication "
                f"at {redis_result['path']}. An attacker can read, modify, or delete "
                f"any cached entry, enabling cache poisoning and data exfiltration."
            )
        return f"Cache backend detected at {redis_result['path']} (HTTP {redis_result['status_code']})."

    def _build_serial_title(self, serial_info: dict) -> str:
        """Build title for serialization observation."""
        if serial_info.get("has_pickle"):
            return "Cache uses pickle serialization: arbitrary code execution risk"
        if serial_info.get("has_type_confusion"):
            return "Cache uses unsafe deserialization with type hints"
        return "Serialization format indicators detected"

    def _build_serial_description(self, serial_info: dict) -> str:
        """Build description for serialization observation."""
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
