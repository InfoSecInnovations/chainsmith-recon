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

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


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

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = (
        "Knowing the embedding model enables targeted adversarial embedding "
        "attacks and helps estimate chunk sizes for boundary exploitation"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["embedding fingerprinting", "model identification", "dimensionality analysis"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        rag_endpoints = context.get("rag_endpoints", [])
        accessible_stores = context.get("accessible_stores", [])
        kb_structure = context.get("knowledge_base_structure", [])

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        model_info: dict[str, Any] = {
            "model_name": None,
            "dimensions": None,
            "confidence": "none",
            "signals": [],
        }

        try:
            async with AsyncHttpClient(cfg) as client:
                # Signal 1: Check embedding endpoints directly
                for ep in rag_endpoints:
                    if ep.get("service", {}).get("host") != service.host:
                        continue
                    if "embed" in ep.get("path", "").lower():
                        dims = await self._probe_embedding_endpoint(
                            client, ep, service
                        )
                        if dims:
                            model_info["dimensions"] = dims
                            model_info["signals"].append(f"embedding_endpoint:{dims}d")

                # Signal 2: Check response headers
                for ep in rag_endpoints:
                    if ep.get("service", {}).get("host") != service.host:
                        continue
                    url = ep.get("url", service.url)
                    resp = await client.post(
                        url,
                        json={"query": "test", "question": "test"},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.error:
                        continue
                    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                    for hdr in ("x-embedding-model", "x-model", "x-embedding-dimensions"):
                        if hdr in headers_lower:
                            model_info["signals"].append(f"header:{hdr}={headers_lower[hdr]}")
                            if "dimensions" in hdr:
                                try:
                                    model_info["dimensions"] = int(headers_lower[hdr])
                                except ValueError:
                                    pass
                            elif model_info["model_name"] is None:
                                model_info["model_name"] = headers_lower[hdr]

                # Signal 3: Check vector store collection config
                for store in (accessible_stores or []):
                    for coll in (kb_structure or []):
                        for c in coll.get("collections", []):
                            if c.get("dimensions"):
                                model_info["dimensions"] = c["dimensions"]
                                model_info["signals"].append(f"collection_config:{c['dimensions']}d")

                # Signal 4: Try to get dimensions from embedding API if we have one
                if not model_info["dimensions"]:
                    dims = await self._try_embedding_api(client, service, context)
                    if dims:
                        model_info["dimensions"] = dims
                        model_info["signals"].append(f"embedding_api:{dims}d")

                # Resolve model name from dimensions
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

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate finding
        if model_info["dimensions"] or model_info["model_name"]:
            title = f"Embedding model identified: {model_info['model_name'] or 'unknown'}"
            if model_info["dimensions"]:
                title += f" ({model_info['dimensions']}d)"

            result.findings.append(build_finding(
                check_name=self.name,
                title=title,
                description=(
                    f"Embedding model fingerprinted via {len(model_info['signals'])} signal(s). "
                    f"Confidence: {model_info['confidence']}."
                ),
                severity="low",
                evidence=self._build_evidence(model_info),
                host=service.host,
                discriminator="embedding-model",
                target=service,
                raw_data=model_info,
                references=self.references,
            ))

            result.outputs["embedding_model"] = model_info
        else:
            result.findings.append(build_finding(
                check_name=self.name,
                title="Embedding model not identified",
                description="Could not determine the embedding model in use.",
                severity="info",
                evidence="No dimensionality or model signals detected",
                host=service.host,
                discriminator="embedding-unknown",
                target=service,
            ))

        return result

    async def _probe_embedding_endpoint(
        self, client: AsyncHttpClient, endpoint: dict, service: Service,
    ) -> int | None:
        """Send a test embedding and measure vector dimensions."""
        url = endpoint.get("url", service.url)
        for payload in [
            {"input": "test", "text": "test"},
            {"texts": ["test"]},
            {"input": ["test"]},
        ]:
            resp = await client.post(
                url, json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.error or resp.status_code != 200:
                continue
            try:
                data = json.loads(resp.body or "{}")
                # OpenAI-style
                emb_list = data.get("data", [])
                if emb_list and isinstance(emb_list[0], dict):
                    vec = emb_list[0].get("embedding", [])
                    if isinstance(vec, list) and len(vec) > 0:
                        return len(vec)
                # Direct array style
                emb = data.get("embedding", data.get("embeddings", []))
                if isinstance(emb, list):
                    if emb and isinstance(emb[0], list):
                        return len(emb[0])
                    if emb and isinstance(emb[0], (int, float)):
                        return len(emb)
            except (json.JSONDecodeError, IndexError, TypeError):
                continue
        return None

    async def _try_embedding_api(
        self, client: AsyncHttpClient, service: Service, context: dict,
    ) -> int | None:
        """Try common embedding API paths."""
        base = service.url
        if "://" in base:
            base = "/".join(base.split("/")[:3])

        for path in ["/v1/embeddings", "/embeddings", "/embed", "/api/embed"]:
            url = f"{base}{path}"
            resp = await client.post(
                url,
                json={"input": "test", "model": "default"},
                headers={"Content-Type": "application/json"},
            )
            if resp.error or resp.status_code != 200:
                continue
            try:
                data = json.loads(resp.body or "{}")
                emb_list = data.get("data", [])
                if emb_list and isinstance(emb_list[0], dict):
                    vec = emb_list[0].get("embedding", [])
                    if isinstance(vec, list) and len(vec) > 0:
                        return len(vec)
            except (json.JSONDecodeError, IndexError, TypeError):
                continue
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
