"""
app/checks/rag/fusion_reranker.py - RAG Fusion / Re-ranker Probing

Detect re-ranking stages in the RAG pipeline and test if they amplify
or suppress injection-containing documents.

**Probe/grade.** The probe sends the ranking query at three
`k` values and records all three exchanges; `grade()` re-reads them, rebuilds the
reranker reading, and returns exactly one verdict — headers, scores, or neither.
`_reading()` is the one parser both halves call (§0.12), and each exchange is
attributed to its `k` by the recorded request body, not by loop position.

**Fixed**: the discriminators are a closed three-value set,
so the contract carries the full `observations:` map. Confidence is where the
split pays: a reranker *header* is the pipeline naming its own stage, while the
score-shape inference is weak — scores normalised into [0,1] describe plain
cosine similarity just as well as a cross-encoder.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

RERANKER_HEADERS = [
    "x-reranker",
    "x-fusion-score",
    "x-cross-encoder",
    "x-rerank-model",
    "x-relevance-score",
]

RANK_QUERY = "What is the most important information available?"

K_VALUES = [1, 3, 10]


class RAGFusionRerankerCheck(ServiceIteratingCheck):
    """
    Detect re-ranking stages and test if they amplify or suppress
    injection-containing documents.
    """

    name = "rag_fusion_reranker"
    description = "Detect RAG re-ranking stages and injection amplification"

    conditions = [CheckCondition("rag_endpoints", "truthy")]
    produces = ["reranker_info"]
    service_types = ["ai", "api", "http"]

    reason = (
        "Re-rankers may amplify injection documents by ranking them higher "
        "due to instruction-like content receiving higher relevance scores"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["reranker detection", "score analysis", "ranking manipulation"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        rag_endpoints = context.get("rag_endpoints", [])
        service_endpoints = [
            ep
            for ep in rag_endpoints
            if ep.get("service", {}).get("host") == service.host
            and ep.get("endpoint_type") == "rag_query"
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=12.0, verify_ssl=False)
        ep = service_endpoints[0]
        url = ep.get("url", service.url)
        candidate = self.create_candidate(host=service.host, target=service, target_url=url)

        try:
            async with AsyncHttpClient(cfg) as client:
                # Test with different k values to observe score behavior
                for k in K_VALUES:
                    body = self._request_body(k)
                    resp = await client.post(url, json=body, headers=JSON_HEADERS)
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
        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # One candidate per service: all three discriminators describe the same
        # endpoint, and the check emits exactly one of them. It is appended even
        # when every request failed, because "no re-ranking detected" is a real
        # answer this check has always reported.
        result.candidates.append(candidate)
        result.outputs["reranker_info"] = self._reading(candidate.exchanges)
        return result

    @staticmethod
    def _request_body(k: int) -> dict:
        return {
            "query": RANK_QUERY,
            "question": RANK_QUERY,
            "input": RANK_QUERY,
            "k": k,
            "top_k": k,
        }

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        info = self._reading(list(evidence))
        ids = evidence.ids()

        if info["reranker_detected"] and info["headers"]:
            return [
                Verdict(
                    severity="low",
                    confidence=0.9,
                    discriminator="reranker-headers",
                    title="Re-ranking detected via response headers",
                    description=(
                        f"Re-ranking stage detected. Headers: {', '.join(info['headers'].keys())}."
                    ),
                    evidence=self._build_evidence(info),
                    reasoning=(
                        "an x-reranker / x-rerank-model / x-cross-encoder header is the pipeline "
                        "naming its own re-ranking stage, not an inference from output shape"
                    ),
                    signals={
                        "headers": list(info["headers"].keys()),
                        "score_patterns": info["score_patterns"],
                    },
                    references=self.references,
                    raw_data=info,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        if info["reranker_detected"]:
            return [
                Verdict(
                    severity="info",
                    confidence=0.35,
                    discriminator="reranker-scores",
                    title="Re-ranking inferred from score patterns",
                    description="Score analysis suggests a re-ranking stage.",
                    evidence=self._build_evidence(info),
                    reasoning=(
                        "inferred only from the shape of the returned scores: normalisation into "
                        "[0,1], a wide spread, or a top-1 score that holds across k. Plain cosine "
                        "similarity over a single vector index produces all three, so a "
                        "re-ranking stage is one explanation among several"
                    ),
                    signals={"score_patterns": info["score_patterns"]},
                    references=self.references,
                    raw_data=info,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        answered = [e for e in evidence if self._usable(e)]
        if answered:
            confidence, why = (
                0.5,
                "the endpoint answered but returned neither reranker headers nor any parsable "
                "relevance scores — a re-ranker that simply does not publish its scores is "
                "indistinguishable from none at all here",
            )
        else:
            confidence, why = (
                0.2,
                "no request produced a usable response, so this is the absence of evidence "
                "rather than evidence of absence",
            )

        return [
            Verdict(
                severity="info",
                confidence=confidence,
                discriminator="no-reranker",
                title="No re-ranking detected",
                description="No re-ranking stage detected in RAG pipeline.",
                evidence="No reranker headers or score patterns detected",
                reasoning=why,
                signals={"responses_read": len(answered)},
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict[str, Any]:
        """Rebuild the reranker reading off the recorded exchanges.

        `k` is recovered from each exchange's own request body, so the score
        series is keyed by what was actually asked rather than by the order the
        probe happened to send.
        """
        info: dict[str, Any] = {
            "reranker_detected": False,
            "headers": {},
            "score_patterns": [],
        }
        scores_by_k: dict[int, list[float]] = {}

        for exchange in exchanges:
            if not self._usable(exchange):
                continue

            resp_hdrs = {h.lower(): v for h, v in (exchange.response_headers or {}).items()}
            for hdr in RERANKER_HEADERS:
                if hdr in resp_hdrs:
                    info["headers"][hdr] = resp_hdrs[hdr]
                    info["reranker_detected"] = True

            scores = self._extract_scores(exchange.response_body)
            if scores:
                k = self._k_of(exchange)
                if k is not None:
                    scores_by_k[k] = scores

        if scores_by_k:
            info["score_patterns"] = self._analyze_scores(scores_by_k)
            if not info["reranker_detected"] and info["score_patterns"]:
                info["reranker_detected"] = True

        return info

    @staticmethod
    def _usable(exchange: Exchange) -> bool:
        """The original skipped errors and 4xx/5xx before reading anything."""
        return not exchange.error and (exchange.response_status or 0) < 400

    @staticmethod
    def _k_of(exchange: Exchange) -> int | None:
        """Which `k` this exchange asked for, off its recorded request."""
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return None
        if not isinstance(body, dict):
            return None
        for key in ("top_k", "k"):
            value = body.get(key)
            if isinstance(value, int):
                return value
        return None

    def _extract_scores(self, body: str | None) -> list[float]:
        """Extract relevance scores from response."""
        if not body:
            return []
        scores = []
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                items = (
                    data.get("results", [])
                    or data.get("matches", [])
                    or data.get("documents", [])
                    or data.get("hits", [])
                )
                for item in items:
                    if isinstance(item, dict):
                        for key in [
                            "score",
                            "relevance_score",
                            "rerank_score",
                            "distance",
                            "_score",
                            "similarity",
                        ]:
                            if key in item:
                                with contextlib.suppress(ValueError, TypeError):
                                    scores.append(float(item[key]))
                                break
        except json.JSONDecodeError:
            pass
        return scores

    def _analyze_scores(self, scores_by_k: dict[int, list[float]]) -> list[str]:
        """Analyze score patterns for reranker indicators."""
        patterns = []

        # Check if scores are in [0,1] range (typical of rerankers)
        all_scores = [s for slist in scores_by_k.values() for s in slist]
        if all_scores and all(0 <= s <= 1 for s in all_scores):
            patterns.append("scores_normalized_0_1")

        # Check if score distribution changes with k
        for k, scores in scores_by_k.items():
            if len(scores) >= 2:
                spread = max(scores) - min(scores)
                if spread > 0.3:
                    patterns.append(f"high_score_spread_k{k}")

        # Check if top-1 score stays constant across k values
        top_scores = [scores[0] for scores in scores_by_k.values() if scores]
        if len(top_scores) >= 2 and len({round(s, 3) for s in top_scores}) == 1:
            patterns.append("stable_top_score")

        return patterns

    def _build_evidence(self, info: dict) -> str:
        lines = [f"Reranker detected: {info['reranker_detected']}"]
        if info["headers"]:
            for h, v in info["headers"].items():
                lines.append(f"  {h}: {v}")
        if info["score_patterns"]:
            lines.append(f"Score patterns: {', '.join(info['score_patterns'])}")
        return "\n".join(lines)
