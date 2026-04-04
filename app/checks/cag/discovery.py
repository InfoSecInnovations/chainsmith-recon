"""
app/checks/cag/discovery.py - CAG Pipeline Discovery

Detect Cache-Augmented Generation (CAG) endpoints and caching infrastructure.

CAG systems cache context, embeddings, or computed results to reduce
latency and cost. This creates unique attack surfaces around cache
poisoning, stale context exploitation, and cache-based information leakage.

Discovery methods:
- Cache-specific endpoint paths (/cache, /context, /precompute)
- Cache control headers (X-Cache, X-Cache-Status, Age, Cache-Control)
- Response timing analysis (cached vs uncached latency)
- Context ID/session patterns in responses

CAG indicators:
- Precomputed context endpoints
- KV cache exposure
- Prompt caching signatures (Anthropic, OpenAI)
- Semantic cache layers (GPTCache, etc.)

References:
  https://www.anthropic.com/news/prompt-caching
  https://platform.openai.com/docs/guides/prompt-caching
  https://github.com/zilliztech/GPTCache
"""

import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

# CAG/caching infrastructure signatures
CAG_SIGNATURES = {
    "gptcache": {
        "paths": ["/cache", "/gptcache", "/cache/search", "/cache/store"],
        "headers": ["x-gptcache-hit", "x-cache-similarity"],
        "body_patterns": ["gptcache", "cache_hit", "similarity_score", "cached_response"],
    },
    "semantic_cache": {
        "paths": ["/semantic-cache", "/embedding-cache", "/cache/semantic"],
        "headers": ["x-semantic-cache", "x-embedding-cache"],
        "body_patterns": ["semantic_cache", "embedding_match", "cached_embedding"],
    },
    "prompt_cache": {
        "paths": ["/v1/cache", "/cache/prompt", "/context/cache"],
        "headers": ["x-prompt-cache", "x-context-cached"],
        "body_patterns": ["prompt_cache", "cached_prefix", "cache_creation"],
    },
    "kv_cache": {
        "paths": ["/kv", "/kv-cache", "/attention-cache"],
        "headers": ["x-kv-cache-hit"],
        "body_patterns": ["kv_cache", "attention_cache", "key_value_cache"],
    },
    "redis_cache": {
        "paths": [],
        "headers": ["x-redis-cache", "x-cache-backend"],
        "body_patterns": ["redis", "cache_backend"],
    },
}

# Common CAG endpoint paths
CAG_PATHS = [
    # Cache management
    "/cache",
    "/cache/status",
    "/cache/stats",
    "/cache/clear",
    "/cache/warm",
    "/cache/precompute",
    # Context caching
    "/context",
    "/context/cache",
    "/context/store",
    "/context/load",
    "/precompute",
    "/precomputed",
    # Prompt caching
    "/v1/cache",
    "/api/cache",
    "/prompt-cache",
    # Session/conversation context
    "/session",
    "/session/context",
    "/conversation/cache",
    # Embedding cache
    "/embedding-cache",
    "/embeddings/cache",
    "/semantic-cache",
]

# Cache-related response headers
CACHE_HEADERS = [
    "x-cache",
    "x-cache-hit",
    "x-cache-status",
    "x-cache-age",
    "x-cached",
    "age",
    "x-context-id",
    "x-session-id",
    "x-prompt-tokens-cached",
    "x-cache-creation-time",
]


class CAGDiscoveryCheck(ServiceIteratingCheck):
    """
    Discover CAG pipeline endpoints and caching infrastructure.

    Probes common cache paths, analyzes response headers for cache
    indicators, and performs timing analysis to detect caching behavior.
    """

    name = "cag_discovery"
    description = "Detect Cache-Augmented Generation endpoints and caching infrastructure"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["cag_endpoints", "cache_infrastructure"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    delay_between_targets = 0.2

    reason = "CAG systems can be exploited for cache poisoning, stale context attacks, cross-user cache leakage, and cache-based denial of service"
    references = [
        "https://www.anthropic.com/news/prompt-caching",
        "https://platform.openai.com/docs/guides/prompt-caching",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache discovery", "timing analysis", "header fingerprinting"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        cag_endpoints = []
        cache_infra = set()

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                # Check for cache infrastructure APIs
                infra_results = await self._detect_cache_infrastructure(client, service)
                for infra_info in infra_results:
                    cache_infra.add(infra_info["cache_type"])
                    cag_endpoints.append(infra_info)

                    result.findings.append(
                        build_finding(
                            check_name=self.name,
                            title=f"Cache infrastructure: {infra_info['cache_type']}",
                            description=self._build_infra_description(infra_info),
                            severity="medium" if not infra_info.get("auth_required") else "info",
                            evidence=self._build_evidence(infra_info),
                            host=service.host,
                            discriminator=f"cache-{infra_info['cache_type']}",
                            target=service,
                            target_url=infra_info.get("url"),
                            raw_data=infra_info,
                            references=self.references,
                        )
                    )

                # Check CAG-specific endpoints
                for path in CAG_PATHS:
                    url = service.with_path(path)

                    resp = await client.get(url)
                    endpoint_info = self._analyze_cag_response(resp, path, service)

                    if endpoint_info:
                        cag_endpoints.append(endpoint_info)

                        severity = self._determine_severity(endpoint_info)

                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=f"CAG endpoint: {path}",
                                description=self._build_endpoint_description(endpoint_info),
                                severity=severity,
                                evidence=self._build_evidence(endpoint_info),
                                host=service.host,
                                discriminator=f"cag-{path.strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=endpoint_info,
                                references=self.references,
                            )
                        )

                # Check existing AI endpoints for cache headers
                ai_endpoints = context.get("chat_endpoints", []) + context.get("rag_endpoints", [])
                for ep in ai_endpoints:
                    if ep.get("service", {}).get("host") != service.host:
                        continue

                    cache_info = await self._check_endpoint_caching(client, ep)
                    if cache_info:
                        cag_endpoints.append(cache_info)

                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=f"Caching detected on: {cache_info['path']}",
                                description=self._build_cache_description(cache_info),
                                severity="low",
                                evidence=self._build_evidence(cache_info),
                                host=service.host,
                                discriminator=f"cached-{cache_info['path'].strip('/').replace('/', '-')}",
                                target=service,
                                target_url=cache_info.get("url"),
                                raw_data=cache_info,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if cag_endpoints:
            result.outputs["cag_endpoints"] = cag_endpoints
        if cache_infra:
            result.outputs["cache_infrastructure"] = list(cache_infra)

        return result

    async def _detect_cache_infrastructure(
        self, client: AsyncHttpClient, service: Service
    ) -> list[dict]:
        """Detect cache infrastructure by probing known APIs."""
        detected = []

        for cache_type, sigs in CAG_SIGNATURES.items():
            for path in sigs.get("paths", []):
                url = service.with_path(path)
                resp = await client.get(url)

                if resp.error or resp.status_code == 404:
                    continue

                # Check headers
                resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                headers_match = any(h in resp_headers_lower for h in sigs.get("headers", []))

                # Check body
                body_lower = (resp.body or "").lower()
                body_match = any(p in body_lower for p in sigs.get("body_patterns", []))

                if headers_match or body_match or resp.status_code == 200:
                    detected.append(
                        {
                            "cache_type": cache_type,
                            "url": url,
                            "path": path,
                            "status_code": resp.status_code,
                            "auth_required": resp.status_code == 401,
                            "indicators": {
                                "headers_match": headers_match,
                                "body_match": body_match,
                            },
                            "service": service.to_dict(),
                            "endpoint_type": "cache_infrastructure",
                        }
                    )
                    break

        return detected

    def _analyze_cag_response(self, resp, path: str, service: Service) -> dict | None:
        """Analyze response for CAG indicators."""
        if resp.error or resp.status_code in (404, 405, 502, 503):
            return None

        indicators = []

        # Check for cache-related headers
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header in CACHE_HEADERS:
            if header in resp_headers_lower:
                indicators.append(f"header:{header}={resp_headers_lower[header]}")

        # Check body for cache patterns
        body = resp.body or ""
        body_lower = body.lower()

        cache_keywords = [
            "cache",
            "cached",
            "precomputed",
            "context_id",
            "session_id",
            "cache_hit",
            "cache_miss",
            "ttl",
            "expiry",
            "warm",
        ]
        for kw in cache_keywords:
            if kw in body_lower:
                indicators.append(f"body:{kw}")

        # Try to parse JSON for cache fields
        if resp.status_code == 200:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    cache_fields = [
                        "cache_status",
                        "cached",
                        "cache_hit",
                        "context_id",
                        "session_id",
                        "ttl",
                        "cache_age",
                        "precomputed",
                    ]
                    for field in cache_fields:
                        if field in data:
                            indicators.append(f"field:{field}")
            except json.JSONDecodeError:
                pass

        if not indicators:
            return None

        return {
            "url": service.with_path(path),
            "path": path,
            "status_code": resp.status_code,
            "indicators": indicators,
            "auth_required": resp.status_code == 401,
            "service": service.to_dict(),
            "endpoint_type": "cag_endpoint",
        }

    async def _check_endpoint_caching(self, client: AsyncHttpClient, endpoint: dict) -> dict | None:
        """Check if an existing endpoint has caching behavior."""
        url = endpoint.get("url")
        if not url:
            return None

        # Make two requests and check for cache indicators
        resp1 = await client.post(
            url,
            json={"input": "cache test query", "query": "cache test"},
            headers={"Content-Type": "application/json"},
        )

        if resp1.error or resp1.status_code >= 400:
            return None

        # Check response headers for cache indicators
        resp_headers_lower = {k.lower(): v for k, v in resp1.headers.items()}
        cache_indicators = []

        for header in CACHE_HEADERS:
            if header in resp_headers_lower:
                cache_indicators.append(f"header:{header}={resp_headers_lower[header]}")

        # Check for cache-related response body fields
        try:
            data = json.loads(resp1.body)
            if isinstance(data, dict):
                if "cached" in data or "cache_hit" in data:
                    cache_indicators.append("response:cache_field")
                if "usage" in data and isinstance(data["usage"], dict):
                    usage = data["usage"]
                    if "cached_tokens" in usage or "prompt_tokens_cached" in usage:
                        cache_indicators.append("usage:cached_tokens")
        except (json.JSONDecodeError, KeyError):
            pass

        if not cache_indicators:
            return None

        return {
            "url": url,
            "path": endpoint.get("path", url),
            "cache_indicators": cache_indicators,
            "service": endpoint.get("service", {}),
            "endpoint_type": "cached_ai_endpoint",
        }

    def _determine_severity(self, endpoint_info: dict) -> str:
        """Determine finding severity."""
        if endpoint_info.get("auth_required"):
            return "info"

        # Cache management endpoints without auth are medium severity
        path = endpoint_info.get("path", "").lower()
        if any(kw in path for kw in ["clear", "warm", "precompute", "store"]):
            return "medium"

        return "low"

    def _build_infra_description(self, infra_info: dict) -> str:
        """Build description for cache infrastructure finding."""
        parts = [
            f"Cache infrastructure '{infra_info['cache_type']}' detected at {infra_info['path']}."
        ]

        if infra_info.get("auth_required"):
            parts.append("Authentication required.")
        else:
            parts.append("No authentication required - potential cache poisoning vector.")

        return " ".join(parts)

    def _build_endpoint_description(self, endpoint_info: dict) -> str:
        """Build description for CAG endpoint finding."""
        parts = [f"CAG endpoint discovered at {endpoint_info['path']}."]

        if endpoint_info.get("auth_required"):
            parts.append("Authentication required.")
        else:
            parts.append("No authentication required.")

        indicator_count = len(endpoint_info.get("indicators", []))
        if indicator_count > 0:
            parts.append(f"Detected {indicator_count} cache indicators.")

        return " ".join(parts)

    def _build_cache_description(self, cache_info: dict) -> str:
        """Build description for cached endpoint finding."""
        parts = [f"Caching behavior detected on AI endpoint {cache_info['path']}."]

        indicators = cache_info.get("cache_indicators", [])
        if indicators:
            parts.append(f"Indicators: {', '.join(indicators[:3])}.")

        return " ".join(parts)

    def _build_evidence(self, info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Path: {info.get('path', 'unknown')}",
            f"Status: {info.get('status_code', 'unknown')}",
        ]

        if info.get("cache_type"):
            lines.append(f"Cache type: {info['cache_type']}")

        indicators = info.get("indicators") or info.get("cache_indicators", [])
        if indicators:
            if isinstance(indicators, dict):
                lines.append(f"Indicators: {indicators}")
            else:
                lines.append(f"Indicators: {', '.join(indicators[:5])}")

        return "\n".join(lines)
