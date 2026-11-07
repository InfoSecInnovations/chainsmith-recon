"""
app/checks/rag/embedding_fingerprint.py - Embedding Model Fingerprinting

Identify which embedding model the RAG uses by analyzing vector
dimensionality, response headers, and collection metadata.

Dimensionality map:
  1536  = OpenAI ada-002
  3072  = OpenAI text-embedding-3-large
  768   = BERT / RoBERTa / e5-base
  384   = MiniLM / all-MiniLM-L6
  1024  = Cohere embed-v3
  4096  = OpenAI text-embedding-3-large (alt config)
  512   = e5-small / bge-small
  256   = Nomic embed-text-v1 (256d variant)

**Probe/grade.** The probe runs all four fingerprinting
signals and records every exchange; `grade()` re-reads them, rebuilds the
`model_info`, and emits one verdict — identified or not. `_reading()` is the one
parser both halves call (§0.12): each signal's exchange is found by its recorded
request URL/body, and the collection-config signal (which comes from an upstream
check, not a response) is read from `GradeContext.context` at grade time (§0.15).

**Fixed**: the discriminators are a closed two-value set, so
the contract carries the full `observations:` map. Confidence is where the split
pays: a *dimension* of 1536 is shared by OpenAI ada-002, many fine-tunes, and any
model configured to that width, so the model name is a best guess from a lookup
table — whereas an `x-embedding-model` header is the service naming itself. The
check's own `model_info["confidence"]` string (none/low/medium/high) becomes the
verdict's float.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

DIMENSION_MAP = {
    1536: ("OpenAI ada-002", "high"),
    3072: ("OpenAI text-embedding-3-large", "high"),
    768: ("BERT / RoBERTa / e5-base", "medium"),
    384: ("MiniLM / all-MiniLM-L6", "high"),
    1024: ("Cohere embed-v3 / e5-large", "medium"),
    4096: ("OpenAI text-embedding-3-large (4096)", "medium"),
    512: ("e5-small / bge-small", "medium"),
    256: ("Nomic embed-text-v1 (256d)", "medium"),
}

# The three payloads the embedding-endpoint probe tries, and the header probe /
# embedding-API probe bodies — declared once so both halves agree on them.
EMBED_PROBE_PAYLOADS = [
    {"input": "test", "text": "test"},
    {"texts": ["test"]},
    {"input": ["test"]},
]
HEADER_PROBE_BODY = {"query": "test", "question": "test"}
EMBED_API_BODY = {"input": "test", "model": "default"}
EMBED_API_PATHS = ["/v1/embeddings", "/embeddings", "/embed", "/api/embed"]

# Detection-confidence string → a float for the Verdict. The check already grades
# its own certainty; this just moves it onto the 0–1 scale the LLM tier will escalate on.
CONFIDENCE_FLOAT = {"high": 0.85, "medium": 0.6, "low": 0.35, "none": 0.2}


class RAGEmbeddingFingerprintCheck(ServiceIteratingCheck):
    """
    Identify the embedding model used by the RAG pipeline via vector
    dimensionality, response headers, and collection metadata.
    """

    name = "rag_embedding_fingerprint"
    description = "Fingerprint the RAG embedding model via dimensionality and metadata"

    conditions = [CheckCondition("rag_endpoints", "truthy")]
    produces = ["embedding_model"]
    service_types = ["ai", "api", "http"]

    reason = (
        "Knowing the embedding model enables targeted adversarial embedding "
        "attacks and helps estimate chunk sizes for boundary exploitation"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["embedding fingerprinting", "model identification", "dimensionality analysis"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        rag_endpoints = context.get("rag_endpoints", [])

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        candidate = self.create_candidate(host=service.host, target=service, target_url=service.url)

        def record(resp, body: dict) -> None:
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

        try:
            async with AsyncHttpClient(cfg) as client:
                # Signal 1: embedding endpoints directly.
                for ep in rag_endpoints:
                    if ep.get("service", {}).get("host") != service.host:
                        continue
                    if "embed" in ep.get("path", "").lower():
                        url = ep.get("url", service.url)
                        for payload in EMBED_PROBE_PAYLOADS:
                            record(
                                await client.post(url, json=payload, headers=JSON_HEADERS), payload
                            )

                # Signal 2: response headers on a plain query.
                for ep in rag_endpoints:
                    if ep.get("service", {}).get("host") != service.host:
                        continue
                    url = ep.get("url", service.url)
                    record(
                        await client.post(url, json=HEADER_PROBE_BODY, headers=JSON_HEADERS),
                        HEADER_PROBE_BODY,
                    )

                # Signal 4: common embedding API paths (signal 3 is context-only).
                base = self._base_url(service)
                for path in EMBED_API_PATHS:
                    url = f"{base}{path}"
                    record(
                        await client.post(url, json=EMBED_API_BODY, headers=JSON_HEADERS),
                        EMBED_API_BODY,
                    )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        model_info = self._reading(candidate.exchanges, context, service)
        if model_info["dimensions"] or model_info["model_name"]:
            result.outputs["embedding_model"] = model_info

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        service = ctx.target
        if service is None:
            return []
        model_info = self._reading(list(evidence), ctx.context or {}, service)
        ids = evidence.ids()

        if not (model_info["dimensions"] or model_info["model_name"]):
            return [
                Verdict(
                    severity="info",
                    confidence=0.5,
                    discriminator="embedding-unknown",
                    title="Embedding model not identified",
                    description="Could not determine the embedding model in use.",
                    evidence="No dimensionality or model signals detected",
                    reasoning=(
                        "no signal placed a dimension or a model name — no embedding endpoint "
                        "returned a vector, no header declared a model, and no collection config "
                        "carried dimensions. A pipeline that simply does not expose its embedder "
                        "looks identical to one this probe could not reach"
                    ),
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        has_header = any(s.startswith("header:") for s in model_info["signals"])
        name_from_dim_only = bool(model_info["model_name"]) and not has_header
        confidence = CONFIDENCE_FLOAT.get(model_info["confidence"], 0.4)
        if name_from_dim_only:
            # A name read off DIMENSION_MAP is a lookup, not a declaration; cap it.
            confidence = min(confidence, 0.5)
            why = (
                f"the model name is inferred from the vector width alone "
                f"({model_info['dimensions']}d → {model_info['model_name']}), and that width is "
                "shared by the base model, its fine-tunes, and anything configured to it — so the "
                "dimension is solid but the name is the most likely tenant of it, not a fact"
            )
        elif has_header:
            why = (
                "a response header named the model directly — the service identifying itself, "
                "corroborated by "
                f"{len(model_info['signals'])} signal(s) in total"
            )
        else:
            why = (
                f"identification rests on {len(model_info['signals'])} signal(s); the dimension is "
                "measured but unmapped, so only the width is known, not the model"
            )

        title = f"Embedding model identified: {model_info['model_name'] or 'unknown'}"
        if model_info["dimensions"]:
            title += f" ({model_info['dimensions']}d)"

        return [
            Verdict(
                severity="low",
                confidence=confidence,
                discriminator="embedding-model",
                title=title,
                description=(
                    f"Embedding model fingerprinted via {len(model_info['signals'])} signal(s). "
                    f"Confidence: {model_info['confidence']}."
                ),
                evidence=self._build_evidence(model_info),
                reasoning=why,
                signals={
                    "model_name": model_info["model_name"],
                    "dimensions": model_info["dimensions"],
                    "detection_confidence": model_info["confidence"],
                    "fingerprint_signals": model_info["signals"],
                },
                references=self.references,
                raw_data=model_info,
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(
        self, exchanges: list[Exchange], context: dict[str, Any], service: Service
    ) -> dict[str, Any]:
        """Rebuild `model_info` off the recorded exchanges + upstream context.

        Replays the four signals in the original order: whichever signal sets
        `dimensions` last wins, and signal 4 runs only when nothing earlier did,
        so the outcome matches the probe that recorded these exchanges.
        """
        rag_endpoints = context.get("rag_endpoints", [])
        accessible_stores = context.get("accessible_stores", [])
        kb_structure = context.get("knowledge_base_structure", [])

        model_info: dict[str, Any] = {
            "model_name": None,
            "dimensions": None,
            "confidence": "none",
            "signals": [],
        }

        # Signal 1: embedding endpoints.
        for ep in rag_endpoints:
            if ep.get("service", {}).get("host") != service.host:
                continue
            if "embed" in ep.get("path", "").lower():
                dims = self._dims_from_probe(exchanges, ep.get("url", service.url))
                if dims:
                    model_info["dimensions"] = dims
                    model_info["signals"].append(f"embedding_endpoint:{dims}d")

        # Signal 2: response headers.
        for ep in rag_endpoints:
            if ep.get("service", {}).get("host") != service.host:
                continue
            ex = self._find_body(exchanges, ep.get("url", service.url), HEADER_PROBE_BODY)
            if ex is None or ex.error:
                continue
            headers_lower = {k.lower(): v for k, v in (ex.response_headers or {}).items()}
            for hdr in ("x-embedding-model", "x-model", "x-embedding-dimensions"):
                if hdr in headers_lower:
                    model_info["signals"].append(f"header:{hdr}={headers_lower[hdr]}")
                    if "dimensions" in hdr:
                        with contextlib.suppress(ValueError):
                            model_info["dimensions"] = int(headers_lower[hdr])
                    elif model_info["model_name"] is None:
                        model_info["model_name"] = headers_lower[hdr]

        # Signal 3: vector store collection config (upstream output, not a response).
        for _store in accessible_stores or []:
            for coll in kb_structure or []:
                for c in coll.get("collections", []):
                    if c.get("dimensions"):
                        model_info["dimensions"] = c["dimensions"]
                        model_info["signals"].append(f"collection_config:{c['dimensions']}d")

        # Signal 4: embedding API paths, only when nothing placed dimensions.
        if not model_info["dimensions"]:
            base = self._base_url(service)
            for path in EMBED_API_PATHS:
                ex = self._find_body(exchanges, f"{base}{path}", EMBED_API_BODY)
                if ex is None or ex.error or ex.response_status != 200:
                    continue
                dims = self._dims_from_openai(ex.response_body)
                if dims:
                    model_info["dimensions"] = dims
                    model_info["signals"].append(f"embedding_api:{dims}d")
                    break

        # Resolve model name from dimensions.
        if model_info["dimensions"] and not model_info["model_name"]:
            dim_match = DIMENSION_MAP.get(model_info["dimensions"])
            if dim_match:
                model_info["model_name"] = dim_match[0]
                model_info["confidence"] = dim_match[1]
            else:
                model_info["confidence"] = "low"

        if model_info["model_name"]:
            model_info["confidence"] = "high" if len(model_info["signals"]) > 1 else "medium"
        elif model_info["dimensions"]:
            model_info["confidence"] = "low"

        return model_info

    def _dims_from_probe(self, exchanges: list[Exchange], url: str) -> int | None:
        """Vector width from the embedding-endpoint probe (first of 3 payloads that worked)."""
        for payload in EMBED_PROBE_PAYLOADS:
            ex = self._find_body(exchanges, url, payload)
            if ex is None or ex.error or ex.response_status != 200:
                continue
            dims = self._dims_from_embedding_body(ex.response_body)
            if dims:
                return dims
        return None

    @staticmethod
    def _dims_from_embedding_body(body: str | None) -> int | None:
        try:
            data = json.loads(body or "{}")
            emb_list = data.get("data", [])
            if emb_list and isinstance(emb_list[0], dict):
                vec = emb_list[0].get("embedding", [])
                if isinstance(vec, list) and len(vec) > 0:
                    return len(vec)
            emb = data.get("embedding", data.get("embeddings", []))
            if isinstance(emb, list):
                if emb and isinstance(emb[0], list):
                    return len(emb[0])
                if emb and isinstance(emb[0], (int, float)):
                    return len(emb)
        except (json.JSONDecodeError, IndexError, TypeError):
            return None
        return None

    @staticmethod
    def _dims_from_openai(body: str | None) -> int | None:
        try:
            data = json.loads(body or "{}")
            emb_list = data.get("data", [])
            if emb_list and isinstance(emb_list[0], dict):
                vec = emb_list[0].get("embedding", [])
                if isinstance(vec, list) and len(vec) > 0:
                    return len(vec)
        except (json.JSONDecodeError, IndexError, TypeError):
            return None
        return None

    @staticmethod
    def _base_url(service: Service) -> str:
        base = service.url
        if "://" in base:
            base = "/".join(base.split("/")[:3])
        return base

    @staticmethod
    def _find_body(exchanges: list[Exchange], url: str, body: dict) -> Exchange | None:
        """The recorded POST to `url` whose request body equals `body`."""
        want_path = urlparse(url).path
        for exchange in exchanges:
            if exchange.request_method != "POST":
                continue
            if urlparse(exchange.request_url or "").path != want_path:
                continue
            try:
                got = json.loads(exchange.request_body or "{}")
            except (ValueError, TypeError):
                continue
            if got == body:
                return exchange
        return None

    def _build_evidence(self, model_info: dict) -> str:
        lines = []
        if model_info["model_name"]:
            lines.append(f"Model: {model_info['model_name']}")
        if model_info["dimensions"]:
            lines.append(f"Dimensions: {model_info['dimensions']}")
        lines.append(f"Confidence: {model_info['confidence']}")
        if model_info["signals"]:
            lines.append(f"Signals: {', '.join(model_info['signals'])}")
        return "\n".join(lines)
