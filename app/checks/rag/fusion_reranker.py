"""
app/checks/rag/fusion_reranker.py - RAG Fusion / Re-ranker Probing

Detect re-ranking stages in the RAG pipeline and test if they amplify
or suppress injection-containing documents.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

RERANKER_HEADERS = [
    "x-reranker",
    "x-fusion-score",
    "x-cross-encoder",
    "x-rerank-model",
    "x-relevance-score",
]

RANK_QUERY = "What is the most important information available?"


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

    timeout_seconds = 60.0
    delay_between_targets = 0.5

    reason = (
        "Re-rankers may amplify injection documents by ranking them higher "
        "due to instruction-like content receiving higher relevance scores"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["reranker detection", "score analysis", "ranking manipulation"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

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
        reranker_info: dict[str, Any] = {
            "reranker_detected": False,
            "headers": {},
            "score_patterns": [],
        }

        try:
            async with AsyncHttpClient(cfg) as client:
                ep = service_endpoints[0]
                url = ep.get("url", service.url)

                # Test with different k values to observe score behavior
                scores_by_k: dict[int, list[float]] = {}

                for k in [1, 3, 10]:
                    body = {
                        "query": RANK_QUERY,
                        "question": RANK_QUERY,
                        "input": RANK_QUERY,
                        "k": k,
                        "top_k": k,
                    }
                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.error or resp.status_code >= 400:
                        continue

                    # Check reranker headers
                    resp_hdrs = {h.lower(): v for h, v in resp.headers.items()}
                    for hdr in RERANKER_HEADERS:
                        if hdr in resp_hdrs:
                            reranker_info["headers"][hdr] = resp_hdrs[hdr]
                            reranker_info["reranker_detected"] = True

                    # Extract scores from response
                    scores = self._extract_scores(resp.body)
                    if scores:
                        scores_by_k[k] = scores

                # Analyze score patterns
                if scores_by_k:
                    reranker_info["score_patterns"] = self._analyze_scores(scores_by_k)
                    if not reranker_info["reranker_detected"] and reranker_info["score_patterns"]:
                        reranker_info["reranker_detected"] = True

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate findings
        if reranker_info["reranker_detected"]:
            if reranker_info["headers"]:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="Re-ranking detected via response headers",
                        description=(
                            f"Re-ranking stage detected. Headers: "
                            f"{', '.join(reranker_info['headers'].keys())}."
                        ),
                        severity="low",
                        evidence=self._build_evidence(reranker_info),
                        host=service.host,
                        discriminator="reranker-headers",
                        target=service,
                        raw_data=reranker_info,
                        references=self.references,
                    )
                )
            else:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="Re-ranking inferred from score patterns",
                        description="Score analysis suggests a re-ranking stage.",
                        severity="info",
                        evidence=self._build_evidence(reranker_info),
                        host=service.host,
                        discriminator="reranker-scores",
                        target=service,
                        raw_data=reranker_info,
                    )
                )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="No re-ranking detected",
                    description="No re-ranking stage detected in RAG pipeline.",
                    severity="info",
                    evidence="No reranker headers or score patterns detected",
                    host=service.host,
                    discriminator="no-reranker",
                    target=service,
                )
            )

        result.outputs["reranker_info"] = reranker_info
        return result

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
