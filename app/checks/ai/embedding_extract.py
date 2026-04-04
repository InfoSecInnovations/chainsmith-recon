"""
app/checks/ai/embedding_extract.py - Embedding Extraction/Inversion

For discovered embedding endpoints: send known text, capture embedding
vectors, test similarity relationships, and check for information leakage.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json


class EmbeddingExtractionCheck(BaseCheck):
    """Analyze embedding endpoints for model identification and metadata leakage."""

    name = "embedding_extraction"
    description = "Analyze embedding endpoints for vector dimensions, model identification, and metadata leakage"
    intrusive = False

    conditions = [CheckCondition("embedding_endpoints", "truthy")]
    produces = ["embedding_analysis"]

    timeout_seconds = 60.0
    sequential = True
    requests_per_second = 2.0

    reason = (
        "Embedding endpoints reveal model architecture via vector dimensions and may leak metadata"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["embedding analysis", "model fingerprinting"]

    # Known dimensionality -> model mapping
    DIMENSION_MAP = {
        384: "MiniLM / all-MiniLM-L6-v2",
        512: "BERT-base (512) / BGE-small",
        768: "BERT-base / all-mpnet-base-v2",
        1024: "Cohere embed / BGE-large",
        1536: "OpenAI text-embedding-ada-002",
        3072: "OpenAI text-embedding-3-small",
        4096: "OpenAI text-embedding-3-large",
    }

    # Test text pairs — similar texts should produce high cosine similarity
    TEST_TEXTS = [
        "The cat sat on the mat.",
        "A kitten rested on the rug.",
        "Quantum computing uses qubits for computation.",
    ]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("embedding_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                er = await self._analyze_endpoint(url, service, api_format)
                result.findings.extend(er.findings)
                result.outputs.update(er.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _analyze_endpoint(
        self,
        url: str,
        service: Service,
        api_format: str,
    ) -> CheckResult:
        result = CheckResult(success=True)
        host = service.host
        vectors = []
        extra_fields = []

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for text in self.TEST_TEXTS:
                    await self._rate_limit()

                    body = self._build_embedding_request(text, api_format)
                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error or resp.status_code != 200:
                        continue

                    parsed = safe_json(resp.body) or {}
                    vec, fields = self._extract_vector(parsed, api_format)
                    if vec:
                        vectors.append(vec)
                    if fields:
                        extra_fields.extend(fields)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        if not vectors:
            return result

        # Analyze dimensionality
        dimensions = len(vectors[0])
        model_guess = self.DIMENSION_MAP.get(dimensions, "unknown")

        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"Embedding endpoint functional: {dimensions}-dimensional vectors",
                description=f"Embedding endpoint returns {dimensions}-dimensional vectors",
                severity="info",
                evidence=f"Dimensions: {dimensions}, vectors captured: {len(vectors)}",
                host=host,
                discriminator="embedding-dimensions",
                target=service,
                target_url=url,
                raw_data={"dimensions": dimensions, "vectors_captured": len(vectors)},
            )
        )

        if model_guess != "unknown":
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Embedding model identified: {model_guess}",
                    description=f"Vector dimensionality ({dimensions}) matches known model: {model_guess}",
                    severity="low",
                    evidence=f"Dimensions: {dimensions} -> {model_guess}",
                    host=host,
                    discriminator="embedding-model-id",
                    target=service,
                    target_url=url,
                    raw_data={"dimensions": dimensions, "model_guess": model_guess},
                )
            )

        # Check for extra metadata beyond vectors
        unique_fields = list(set(extra_fields))
        if unique_fields:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Embedding endpoint returns metadata beyond vectors: {', '.join(unique_fields[:5])}",
                    description="Extra fields in embedding response may reveal configuration or usage data",
                    severity="medium",
                    evidence=f"Extra fields: {', '.join(unique_fields)}",
                    host=host,
                    discriminator="embedding-metadata",
                    target=service,
                    target_url=url,
                    raw_data={"extra_fields": unique_fields},
                )
            )

        # Check similarity if we have enough vectors
        if len(vectors) >= 2:
            sim = self._cosine_similarity(vectors[0], vectors[1])
            if sim > 0.5:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="Embedding similarity confirms real model",
                        description=f"Similar texts produce cosine similarity {sim:.3f} (> 0.5 threshold)",
                        severity="info",
                        evidence=f"Cosine similarity between similar texts: {sim:.3f}",
                        host=host,
                        discriminator="embedding-similarity",
                        target=service,
                        target_url=url,
                        raw_data={"cosine_similarity": round(sim, 4)},
                    )
                )

        analysis = {
            "dimensions": dimensions,
            "model_guess": model_guess,
            "vectors_captured": len(vectors),
            "extra_fields": unique_fields,
        }
        result.outputs[f"embedding_analysis_{service.port}"] = analysis
        return result

    def _build_embedding_request(self, text: str, api_format: str) -> dict:
        if api_format == "openai":
            return {"model": "text-embedding-ada-002", "input": text}
        elif api_format == "ollama":
            return {"model": "nomic-embed-text", "prompt": text}
        else:
            return {"input": text}

    def _extract_vector(self, body: dict, api_format: str) -> tuple[list | None, list[str]]:
        """Extract embedding vector and note any extra fields."""
        vec = None
        extra = []

        # OpenAI format
        if "data" in body and isinstance(body["data"], list):
            if body["data"] and "embedding" in body["data"][0]:
                vec = body["data"][0]["embedding"]
            # Check for extra fields beyond standard
            standard = {"object", "data", "model", "usage"}
            extra = [k for k in body if k not in standard]
        # Ollama format
        elif "embedding" in body:
            vec = body["embedding"]
            standard = {"embedding"}
            extra = [k for k in body if k not in standard]
        # Generic
        elif "embeddings" in body and isinstance(body["embeddings"], list):
            if body["embeddings"]:
                vec = body["embeddings"][0]

        if vec and not isinstance(vec, list):
            vec = None

        return vec, extra

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity without numpy."""
        if len(a) != len(b) or not a:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = sum(x * x for x in a) ** 0.5
        mag_b = sum(x * x for x in b) ** 0.5
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)
