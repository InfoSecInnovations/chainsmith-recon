"""
app/checks/ai/ai_embedding_extraction/check.py - Embedding Extraction/Inversion

For discovered embedding endpoints: send known text, capture embedding
vectors, test similarity relationships, and check for information leakage.

**Probe/grade.** The probe sends three known texts to an
embedding endpoint and records the vector responses; `grade()` re-reads them and
returns up to four independent verdicts — dimensionality, model identification,
metadata leakage, and a similarity sanity check. `_reading()` is the one parser
both halves call (§0.12); it pulls the vectors and extra fields out of the
recorded bodies, keyed on the request dialect read back off each request.
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import dialect_from_request
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json

JSON_HEADERS = {"Content-Type": "application/json"}


class EmbeddingExtractionCheck(BaseCheck):
    """Analyze embedding endpoints for model identification and metadata leakage."""

    name = "ai_embedding_extraction"
    description = "Analyze embedding endpoints for vector dimensions, model identification, and metadata leakage"
    intrusive = False

    conditions = [CheckCondition("embedding_endpoints", "truthy")]
    produces = ["embedding_analysis"]

    sequential = True

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

    SIMILARITY_THRESHOLD = 0.5

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        for endpoint_info in context.get("embedding_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                candidate = self.create_candidate(host=service.host, target=service, target_url=url)
                await self._probe_embeddings(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                reading = self._reading(candidate.exchanges)
                if reading["vectors"]:
                    result.outputs[f"embedding_analysis_{service.port}"] = {
                        "dimensions": reading["dimensions"],
                        "model_guess": reading["model_guess"],
                        "vectors_captured": len(reading["vectors"]),
                        "extra_fields": reading["extra_fields"],
                    }
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _probe_embeddings(
        self, url: str, api_format: str, candidate: Candidate, scan_id: str
    ) -> None:
        """Send each known text, recording every response."""
        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for text in self.TEST_TEXTS:
                await self._rate_limit()

                body = self._build_embedding_request(text, api_format)
                resp = await client.post(url, json=body, headers=JSON_HEADERS)

                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=candidate.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=body,
                    )
                )

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Up to four independent verdicts over the recorded vectors."""
        reading = self._reading(list(evidence))
        vectors = reading["vectors"]
        if not vectors:
            return []

        ids = evidence.ids()
        dimensions = reading["dimensions"]
        verdicts: list[Verdict] = []

        # ── Dimensionality (always, when a vector came back) ──
        verdicts.append(
            Verdict(
                severity="info",
                # A vector's own length is not open to interpretation.
                confidence=0.98,
                discriminator="embedding-dimensions",
                title=f"Embedding endpoint functional: {dimensions}-dimensional vectors",
                description=f"Embedding endpoint returns {dimensions}-dimensional vectors",
                evidence=f"Dimensions: {dimensions}, vectors captured: {len(vectors)}",
                reasoning="the returned vector's length is counted directly",
                signals={"dimensions": dimensions, "vectors_captured": len(vectors)},
                raw_data={"dimensions": dimensions, "vectors_captured": len(vectors)},
                evidence_ids=ids,
            )
        )

        # ── Model identification from dimensionality ──
        if reading["model_guess"] != "unknown":
            verdicts.append(
                Verdict(
                    severity="low",
                    # Dimensionality narrows the model but never names it: 768 is
                    # BERT-base AND all-mpnet AND a dozen others, and the map
                    # lists two guesses per size for exactly that reason.
                    confidence=0.5,
                    discriminator="embedding-model-id",
                    title=f"Embedding model identified: {reading['model_guess']}",
                    description=(
                        f"Vector dimensionality ({dimensions}) matches known model: "
                        f"{reading['model_guess']}"
                    ),
                    evidence=f"Dimensions: {dimensions} -> {reading['model_guess']}",
                    reasoning=(
                        f"{dimensions} dimensions is a family of models, not one — the guess "
                        "names the most common members but many models share a vector size"
                    ),
                    signals={"dimensions": dimensions, "model_guess": reading["model_guess"]},
                    raw_data={"dimensions": dimensions, "model_guess": reading["model_guess"]},
                    evidence_ids=ids,
                )
            )

        # ── Metadata beyond the vector ──
        if reading["extra_fields"]:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # The fields are named in the body; the doubt is whether they
                    # are sensitive, and `usage` is already excluded as standard.
                    confidence=0.7,
                    discriminator="embedding-metadata",
                    title=(
                        "Embedding endpoint returns metadata beyond vectors: "
                        + ", ".join(reading["extra_fields"][:5])
                    ),
                    description=(
                        "Extra fields in embedding response may reveal configuration or usage data"
                    ),
                    evidence=f"Extra fields: {', '.join(reading['extra_fields'])}",
                    reasoning=(
                        f"{len(reading['extra_fields'])} field(s) beyond the standard envelope; "
                        "whether any is sensitive depends on the field, so this is reported for "
                        "review rather than asserted as a leak"
                    ),
                    signals={"extra_fields": reading["extra_fields"]},
                    raw_data={"extra_fields": reading["extra_fields"]},
                    evidence_ids=ids,
                )
            )

        # ── Similarity sanity check ──
        if len(vectors) >= 2:
            sim = self._cosine_similarity(vectors[0], vectors[1])
            if sim > self.SIMILARITY_THRESHOLD:
                verdicts.append(
                    Verdict(
                        severity="info",
                        confidence=0.9,
                        discriminator="embedding-similarity",
                        title="Embedding similarity confirms real model",
                        description=(
                            f"Similar texts produce cosine similarity {sim:.3f} "
                            f"(> {self.SIMILARITY_THRESHOLD} threshold)"
                        ),
                        evidence=f"Cosine similarity between similar texts: {sim:.3f}",
                        reasoning=(
                            "two semantically similar texts embedded close together, which a real "
                            "model does and a stub returning fixed or random vectors does not"
                        ),
                        signals={"cosine_similarity": round(sim, 4)},
                        raw_data={"cosine_similarity": round(sim, 4)},
                        evidence_ids=ids,
                    )
                )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Pull vectors and extra fields out of the recorded responses."""
        vectors: list[list] = []
        extra_fields: list[str] = []

        for exchange in exchanges:
            if exchange.error or exchange.response_status != 200:
                continue

            api_format = dialect_from_request(exchange.request_body or "")
            parsed = safe_json(exchange.response_body or "") or {}
            vec, fields = self._extract_vector(parsed, api_format)
            if vec:
                vectors.append(vec)
            if fields:
                extra_fields.extend(fields)

        dimensions = len(vectors[0]) if vectors else 0
        return {
            "vectors": vectors,
            "dimensions": dimensions,
            "model_guess": self.DIMENSION_MAP.get(dimensions, "unknown"),
            "extra_fields": sorted(set(extra_fields)),
        }

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
