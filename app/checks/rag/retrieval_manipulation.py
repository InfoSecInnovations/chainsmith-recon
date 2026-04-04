"""
app/checks/rag/retrieval_manipulation.py - Retrieval Manipulation

Test if RAG retrieval parameters can be overridden by the client
(top_k, filters, similarity thresholds) to expand the attack surface
or steer retrieval towards sensitive content.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

# Parameters to try overriding
TOPK_VALUES = [1, 5, 20, 50, 100]

# Parameter name variants for top_k
TOPK_PARAMS = ["top_k", "k", "n_results", "limit", "topK", "num_results", "max_results"]

# Filter override attempts
FILTER_OVERRIDES = [
    {"filter": {}},
    {"filter": None},
    {"where": {}},
    {"metadata_filter": {}},
]


class RAGRetrievalManipulationCheck(ServiceIteratingCheck):
    """
    Test if RAG retrieval parameters (top_k, filters, thresholds)
    accept client-side overrides that expand the attack surface.
    """

    name = "rag_retrieval_manipulation"
    description = "Test for client-side retrieval parameter override"
    intrusive = True

    conditions = [CheckCondition("rag_endpoints", "truthy")]
    produces = ["retrieval_control"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    delay_between_targets = 0.5

    reason = (
        "If clients can override top_k or disable filters, they can expand "
        "the retrieval surface to include more documents — increasing the "
        "chance of retrieving sensitive or injection-containing content"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["retrieval parameter manipulation", "top_k override", "filter bypass"]

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
        control_results: dict[str, Any] = {
            "topk_overridable": False,
            "topk_param": None,
            "max_topk_accepted": 0,
            "filter_bypassable": False,
            "retrieval_counts": {},
        }

        try:
            async with AsyncHttpClient(cfg) as client:
                ep = service_endpoints[0]
                url = ep.get("url", service.url)
                test_query = "test information retrieval"

                # Test 1: top_k parameter override
                for param_name in TOPK_PARAMS:
                    counts = await self._test_topk(client, url, ep, test_query, param_name)
                    if counts and len(set(counts.values())) > 1:
                        # Different k values yielded different result counts
                        control_results["topk_overridable"] = True
                        control_results["topk_param"] = param_name
                        control_results["max_topk_accepted"] = max(counts.values())
                        control_results["retrieval_counts"] = counts
                        break

                # Test 2: Filter/where clause override
                for override in FILTER_OVERRIDES:
                    body = {
                        "query": test_query,
                        "question": test_query,
                        "input": test_query,
                    }
                    body.update(override)
                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.error or resp.status_code >= 400:
                        continue
                    # If the filter param was accepted without error, it may be bypassable
                    if resp.status_code == 200 and resp.body:
                        control_results["filter_bypassable"] = True
                        break

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate findings
        if control_results["topk_overridable"]:
            max_k = control_results["max_topk_accepted"]
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Retrieval manipulation: {control_results['topk_param']} accepts client override",
                    description=(
                        f"Client-supplied '{control_results['topk_param']}' parameter controls "
                        f"retrieval count. Maximum accepted: {max_k}. "
                        f"Expanded retrieval increases attack surface for indirect injection."
                    ),
                    severity="high",
                    evidence=self._build_topk_evidence(control_results),
                    host=service.host,
                    discriminator="topk-override",
                    target=service,
                    raw_data=control_results,
                    references=self.references,
                )
            )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="top_k parameter bounded by server",
                    description="Client override of retrieval parameters was rejected or had no effect.",
                    severity="low",
                    evidence="Tested parameters: " + ", ".join(TOPK_PARAMS),
                    host=service.host,
                    discriminator="topk-bounded",
                    target=service,
                )
            )

        if control_results["filter_bypassable"]:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Retrieval filter override accepted",
                    description=(
                        "Filter/where clause parameters accepted from client — "
                        "metadata-based access controls may be bypassable."
                    ),
                    severity="medium",
                    evidence="Empty filter/where clause accepted without error",
                    host=service.host,
                    discriminator="filter-bypass",
                    target=service,
                    raw_data={"filter_bypassable": True},
                )
            )

        result.outputs["retrieval_control"] = control_results
        return result

    async def _test_topk(
        self,
        client: AsyncHttpClient,
        url: str,
        endpoint: dict,
        query: str,
        param_name: str,
    ) -> dict[int, int] | None:
        """Test different top_k values and count results."""
        counts: dict[int, int] = {}

        for k in [1, 10, 50]:
            body = {
                "query": query,
                "question": query,
                "input": query,
                param_name: k,
            }
            resp = await client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"},
            )
            if resp.error or resp.status_code >= 400:
                return None

            count = self._count_results(resp.body)
            if count is not None:
                counts[k] = count

        return counts if len(counts) >= 2 else None

    def _count_results(self, body: str | None) -> int | None:
        """Count the number of results in a RAG response."""
        if not body:
            return None
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key in [
                    "results",
                    "documents",
                    "sources",
                    "matches",
                    "chunks",
                    "hits",
                    "source_documents",
                ]:
                    if key in data and isinstance(data[key], list):
                        return len(data[key])
            if isinstance(data, list):
                return len(data)
        except json.JSONDecodeError:
            pass
        return None

    def _build_topk_evidence(self, control: dict) -> str:
        lines = [f"Parameter: {control['topk_param']}"]
        for k, count in sorted(control.get("retrieval_counts", {}).items()):
            lines.append(f"  k={k} -> {count} results")
        lines.append(f"Max accepted: {control['max_topk_accepted']}")
        return "\n".join(lines)
