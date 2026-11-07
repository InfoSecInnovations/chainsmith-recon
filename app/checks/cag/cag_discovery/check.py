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

**Probe/grade.** The probe GETs every signature and CAG
path and POSTs the known AI endpoints, recording each; it emits one candidate
per probed URL (the `web_path_probe` / `rag_collection_enumeration` pattern, so
each observation keeps its own `target_url`). `grade()` never sees the
discriminator (§0.16): it recovers which family an exchange belongs to from the
recorded *request* — a signature-path GET is graded for infrastructure, a
CAG-path GET for an endpoint (one GET to a shared path such as `/cache` can
yield both verdicts), an AI-endpoint POST for caching behaviour. The infra,
endpoint and caching readings are each one parser both halves call (§0.12).

**Fixed**: the `cag-<path>` / `cached-<path>` discriminators
embed the path (an unbounded set), so the contract carries no map and `grade()`
places the severity (the `ai_model_info_check` pattern). Confidence is
signal-kind graded (§0.15/§0.16 `agent_discovery`, `rag_discovery`): a
signature-specific header is worth far more than a keyword substring in a body,
which recurs in unrelated JSON.

References:
  https://www.anthropic.com/news/prompt-caching
  https://platform.openai.com/docs/guides/prompt-caching
  https://github.com/zilliztech/GPTCache
"""

import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

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

# Ordered signature paths, first type wins — used to key an infra GET back to
# its cache type at grade time (grade never sees the discriminator).
_PATH_TO_TYPE = {
    path: cache_type
    for cache_type, sigs in CAG_SIGNATURES.items()
    for path in sigs.get("paths", [])
}


class CAGDiscoveryCheck(ServiceIteratingCheck):
    """
    Discover CAG pipeline endpoints and caching infrastructure.

    Probes common cache paths, analyzes response headers for cache
    indicators, and performs timing analysis to detect caching behavior.
    """

    name = "cag_discovery"
    description = "Detect Cache-Augmented Generation endpoints and caching infrastructure"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["cag_endpoints", "cache_infrastructure"]
    service_types = ["ai", "api", "http"]

    reason = "CAG systems can be exploited for cache poisoning, stale context attacks, cross-user cache leakage, and cache-based denial of service"
    references = [
        "https://www.anthropic.com/news/prompt-caching",
        "https://platform.openai.com/docs/guides/prompt-caching",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache discovery", "timing analysis", "header fingerprinting"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        cag_endpoints: list[dict] = []
        cache_infra: set[str] = set()

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                # GET every signature path and CAG path once.
                get_paths = list(dict.fromkeys(list(_PATH_TO_TYPE) + CAG_PATHS))
                for path in get_paths:
                    url = service.with_path(path)
                    try:
                        resp = await client.get(url)
                    except Exception:
                        continue
                    exchange = exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host, method="GET"
                    )
                    candidate = self.create_candidate(
                        host=service.host, target=service, target_url=url
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)

                    # Build the produced outputs off the same exchange.
                    listed = False
                    if path in _PATH_TO_TYPE:
                        infra_info = self._infra_from(exchange, service)
                        if infra_info and infra_info["cache_type"] not in cache_infra:
                            cache_infra.add(infra_info["cache_type"])
                            cag_endpoints.append(infra_info)
                            listed = True
                    # Five paths are in both tables (`/cache`, `/v1/cache`, ...).
                    # One URL is one endpoint for the downstream CAG checks, so
                    # list it once; otherwise they probe it twice (lab backport 3d).
                    if path in CAG_PATHS and not listed:
                        endpoint_info = self._analyze_cag_response(exchange, path, service)
                        if endpoint_info:
                            cag_endpoints.append(endpoint_info)

                # POST the known AI endpoints to check for caching behaviour.
                ai_endpoints = context.get("chat_endpoints", []) + context.get("rag_endpoints", [])
                for ep in ai_endpoints:
                    if ep.get("service", {}).get("host") != service.host:
                        continue
                    url = ep.get("url")
                    if not url:
                        continue
                    try:
                        resp = await client.post(
                            url,
                            json={"input": "cache test query", "query": "cache test"},
                            headers=JSON_HEADERS,
                        )
                    except Exception:
                        continue
                    exchange = exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=service.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json={"input": "cache test query", "query": "cache test"},
                    )
                    candidate = self.create_candidate(
                        host=service.host, target=service, target_url=url, raw_data={"ep": ep}
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)

                    cache_info = self._check_endpoint_caching(exchange, ep)
                    if cache_info:
                        cag_endpoints.append(cache_info)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if cag_endpoints:
            result.outputs["cag_endpoints"] = cag_endpoints
        if cache_infra:
            result.outputs["cache_infrastructure"] = list(cache_infra)

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        verdicts: list[Verdict] = []
        service = ctx.target
        for exchange in evidence:
            path = urlparse(exchange.request_url or "").path
            if exchange.request_method == "GET":
                if path in _PATH_TO_TYPE:
                    verdicts.extend(self._grade_infra(exchange, service, ctx))
                if path in CAG_PATHS:
                    verdicts.extend(self._grade_endpoint(exchange, path, service, ctx))
            elif exchange.request_method == "POST":
                # The endpoint identity is on the recorded request, not the
                # scan context — grade() reconstructs it from the URL (§0.16).
                ep = {"url": exchange.request_url, "path": path}
                verdicts.extend(self._grade_cached(exchange, ep, ctx))
        return verdicts

    def _grade_infra(self, exchange: Exchange, service, ctx: GradeContext) -> list[Verdict]:
        infra_info = self._infra_from(exchange, service)
        if not infra_info:
            return []
        severity = "medium" if not infra_info.get("auth_required") else "info"
        confidence, why = self._infra_confidence(infra_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=f"cache-{infra_info['cache_type']}",
                title=f"Cache infrastructure: {infra_info['cache_type']}",
                description=self._build_infra_description(infra_info),
                evidence=self._build_evidence(infra_info),
                reasoning=why,
                signals={"indicators": infra_info.get("indicators", {})},
                references=self.references,
                raw_data=infra_info,
                tier=ctx.tier,
                evidence_ids=[exchange.id],
            )
        ]

    def _grade_endpoint(
        self, exchange: Exchange, path: str, service, ctx: GradeContext
    ) -> list[Verdict]:
        endpoint_info = self._analyze_cag_response(exchange, path, service)
        if not endpoint_info:
            return []
        severity = self._determine_severity(endpoint_info)
        confidence, why = self._endpoint_confidence(endpoint_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=f"cag-{path.strip('/').replace('/', '-')}",
                title=f"CAG endpoint: {path}",
                description=self._build_endpoint_description(endpoint_info),
                evidence=self._build_evidence(endpoint_info),
                reasoning=why,
                signals={"indicators": endpoint_info.get("indicators", [])},
                references=self.references,
                raw_data=endpoint_info,
                tier=ctx.tier,
                evidence_ids=[exchange.id],
            )
        ]

    def _grade_cached(self, exchange: Exchange, ep: dict, ctx: GradeContext) -> list[Verdict]:
        cache_info = self._check_endpoint_caching(exchange, ep)
        if not cache_info:
            return []
        indicators = cache_info.get("cache_indicators", [])
        header_signal = any(i.startswith("header:") for i in indicators)
        confidence = 0.85 if header_signal else 0.45
        why = (
            "an AI-specific cache header is present, a strong signal of intentional caching"
            if header_signal
            else "the only signal is a cache field in the response body, which many APIs emit "
            "regardless of whether a cache is actually in the path"
        )
        return [
            Verdict(
                severity="low",
                confidence=confidence,
                discriminator=f"cached-{cache_info['path'].strip('/').replace('/', '-')}",
                title=f"Caching detected on: {cache_info['path']}",
                description=self._build_cache_description(cache_info),
                evidence=self._build_evidence(cache_info),
                reasoning=why,
                signals={"cache_indicators": indicators},
                references=self.references,
                raw_data=cache_info,
                tier=ctx.tier,
                evidence_ids=[exchange.id],
            )
        ]

    @staticmethod
    def _infra_confidence(infra_info: dict) -> tuple[float, str]:
        indicators = infra_info.get("indicators", {})
        if indicators.get("headers_match"):
            return 0.9, (
                "a signature-specific cache header identified the backend — the strongest kind of "
                "signal, since these headers are near-unique to the product"
            )
        if indicators.get("body_match"):
            return 0.55, (
                "the backend was named by a substring in the response body; product names recur "
                "in unrelated JSON, so this is softer than a header"
            )
        return 0.4, (
            "the only signal is a non-404 status on a signature path, which any catch-all route "
            "returns; the cache type is inferred from the path alone"
        )

    @staticmethod
    def _endpoint_confidence(endpoint_info: dict) -> tuple[float, str]:
        indicators = endpoint_info.get("indicators", [])
        if any(i.startswith("header:") for i in indicators):
            return 0.85, "a cache-control header on the path is a strong, intentional signal"
        if any(i.startswith("field:") for i in indicators):
            return 0.7, "a structured cache field in the JSON body indicates cache-aware responses"
        return 0.45, (
            "the signal is only a cache keyword in the body text, which appears in documentation "
            "and unrelated responses as readily as in a real cache endpoint"
        )

    # ── The parsers both halves share ────────────────────────────────

    def _infra_from(self, exchange: Exchange, service) -> dict | None:
        """Rebuild one infrastructure reading off a recorded signature-path GET."""
        if exchange.error or exchange.response_status == 404:
            return None
        path = urlparse(exchange.request_url or "").path
        cache_type = _PATH_TO_TYPE.get(path)
        if not cache_type:
            return None
        sigs = CAG_SIGNATURES[cache_type]

        resp_headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        headers_match = any(h in resp_headers_lower for h in sigs.get("headers", []))
        body_lower = (exchange.response_body or "").lower()
        body_match = any(p in body_lower for p in sigs.get("body_patterns", []))

        if not (headers_match or body_match or exchange.response_status == 200):
            return None

        return {
            "cache_type": cache_type,
            "url": exchange.request_url,
            "path": path,
            "status_code": exchange.response_status,
            "auth_required": exchange.response_status == 401,
            "indicators": {"headers_match": headers_match, "body_match": body_match},
            "service": service.to_dict() if service else {},
            "endpoint_type": "cache_infrastructure",
        }

    def _analyze_cag_response(self, exchange: Exchange, path: str, service) -> dict | None:
        """Analyze a recorded CAG-path GET for cache indicators."""
        if exchange.error or exchange.response_status in (404, 405, 502, 503):
            return None

        indicators = []

        resp_headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        for header in CACHE_HEADERS:
            if header in resp_headers_lower:
                indicators.append(f"header:{header}={resp_headers_lower[header]}")

        body = exchange.response_body or ""
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

        if exchange.response_status == 200:
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
            "url": service.with_path(path) if service else exchange.request_url,
            "path": path,
            "status_code": exchange.response_status,
            "indicators": indicators,
            "auth_required": exchange.response_status == 401,
            "service": service.to_dict() if service else {},
            "endpoint_type": "cag_endpoint",
        }

    def _check_endpoint_caching(self, exchange: Exchange, endpoint: dict) -> dict | None:
        """Rebuild the caching reading off a recorded AI-endpoint POST."""
        if exchange.error or (exchange.response_status or 0) >= 400:
            return None

        resp_headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        cache_indicators = []
        for header in CACHE_HEADERS:
            if header in resp_headers_lower:
                cache_indicators.append(f"header:{header}={resp_headers_lower[header]}")

        try:
            data = json.loads(exchange.response_body or "")
            if isinstance(data, dict):
                if "cached" in data or "cache_hit" in data:
                    cache_indicators.append("response:cache_field")
                if "usage" in data and isinstance(data["usage"], dict):
                    usage = data["usage"]
                    if "cached_tokens" in usage or "prompt_tokens_cached" in usage:
                        cache_indicators.append("usage:cached_tokens")
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        if not cache_indicators:
            return None

        url = endpoint.get("url") or exchange.request_url
        return {
            "url": url,
            "path": endpoint.get("path", url),
            "cache_indicators": cache_indicators,
            "service": endpoint.get("service", {}),
            "endpoint_type": "cached_ai_endpoint",
        }

    def _determine_severity(self, endpoint_info: dict) -> str:
        """Determine observation severity."""
        if endpoint_info.get("auth_required"):
            return "info"

        # Cache management endpoints without auth are medium severity
        path = endpoint_info.get("path", "").lower()
        if any(kw in path for kw in ["clear", "warm", "precompute", "store"]):
            return "medium"

        return "low"

    def _build_infra_description(self, infra_info: dict) -> str:
        """Build description for cache infrastructure observation."""
        parts = [
            f"Cache infrastructure '{infra_info['cache_type']}' detected at {infra_info['path']}."
        ]

        if infra_info.get("auth_required"):
            parts.append("Authentication required.")
        else:
            parts.append("No authentication required - potential cache poisoning vector.")

        return " ".join(parts)

    def _build_endpoint_description(self, endpoint_info: dict) -> str:
        """Build description for CAG endpoint observation."""
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
        """Build description for cached endpoint observation."""
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
