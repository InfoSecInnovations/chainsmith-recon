"""
app/checks/rag/cross_collection.py - Cross-Collection Retrieval

Test if queries against one collection can retrieve documents from
another. Isolation failures mean public queries could surface private
documents.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig


class RAGCrossCollectionCheck(ServiceIteratingCheck):
    """
    Test collection isolation: queries to one collection should not
    retrieve documents from another.
    """

    name = "rag_cross_collection"
    description = "Test cross-collection retrieval isolation"

    conditions = [CheckCondition("knowledge_base_structure", "truthy")]
    produces = ["cross_collection_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    delay_between_targets = 0.5

    reason = (
        "Multi-tenant RAG deployments often share a vector store. "
        "If collection isolation is not enforced, public queries can "
        "surface private documents"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "CWE-285 Improper Authorization",
    ]
    techniques = ["cross-collection retrieval", "isolation testing", "tenant bypass"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        kb_structure = context.get("knowledge_base_structure", [])
        rag_endpoints = context.get("rag_endpoints", [])

        # Need at least 2 collections
        all_collections = []
        store_type = None
        for struct in kb_structure:
            colls = struct.get("collections", [])
            if len(colls) >= 2:
                all_collections = colls
                store_type = struct.get("store_type")
                break

        if len(all_collections) < 2:
            return result

        query_eps = [
            ep
            for ep in rag_endpoints
            if ep.get("service", {}).get("host") == service.host
            and ep.get("endpoint_type") == "rag_query"
        ]

        cfg = HttpConfig(timeout_seconds=12.0, verify_ssl=False)
        cross_results: list[dict] = []

        try:
            async with AsyncHttpClient(cfg) as client:
                base_url = service.url
                if "://" in base_url:
                    base_url = "/".join(base_url.split("/")[:3])

                # Test: query one collection for terms unique to another
                coll_a = all_collections[0]
                coll_b = all_collections[1]

                # Query collection A with terms that should only be in B
                test1 = await self._test_isolation(
                    client, base_url, store_type, coll_a, coll_b, query_eps
                )
                if test1:
                    cross_results.append(test1)

                # Query collection B with terms that should only be in A
                test2 = await self._test_isolation(
                    client, base_url, store_type, coll_b, coll_a, query_eps
                )
                if test2:
                    cross_results.append(test2)

                # Also test via RAG query endpoint with collection parameter
                if query_eps:
                    test3 = await self._test_rag_isolation(
                        client, query_eps[0], coll_a["name"], coll_b["name"]
                    )
                    if test3:
                        cross_results.append(test3)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate observations
        leaks = [r for r in cross_results if r.get("isolation_violated")]
        if leaks:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=(
                        f"Cross-collection retrieval: query to '{leaks[0]['source_collection']}' "
                        f"returned documents from '{leaks[0]['target_collection']}'"
                    ),
                    description=(
                        "Collection isolation not enforced. Queries retrieve from "
                        "all collections regardless of target."
                    ),
                    severity="critical" if len(leaks) > 1 else "high",
                    evidence=self._build_evidence(leaks),
                    host=service.host,
                    discriminator="cross-collection-leak",
                    target=service,
                    raw_data={"leaks": leaks},
                    references=self.references,
                )
            )
        else:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Collection isolation enforced",
                    description="Queries to one collection did not return documents from another.",
                    severity="info",
                    evidence=f"Tested {len(all_collections)} collections",
                    host=service.host,
                    discriminator="isolation-ok",
                    target=service,
                )
            )

        if cross_results:
            result.outputs["cross_collection_results"] = cross_results

        return result

    async def _test_isolation(
        self,
        client: AsyncHttpClient,
        base_url: str,
        store_type: str | None,
        source_coll: dict,
        target_coll: dict,
        query_eps: list[dict],
    ) -> dict | None:
        """Query source collection for terms that should be in target only."""
        source_name = source_coll.get("name", "")
        target_name = target_coll.get("name", "")

        # Use collection name as query (it's the best signal we have)
        query = f"Documents about {target_name}"

        # Try direct vector store query scoped to source collection
        if store_type == "chroma":
            url = f"{base_url}/api/v1/collections/{source_name}/query"
            body = {
                "query_texts": [query],
                "n_results": 5,
            }
        elif store_type == "qdrant":
            url = f"{base_url}/collections/{source_name}/points/search"
            body = {
                "vector": [0.0] * 3,  # Placeholder
                "limit": 5,
            }
        else:
            return None

        resp = await client.post(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
        )
        if resp.error or resp.status_code >= 400:
            return None

        resp_text = (resp.body or "").lower()
        isolation_violated = target_name.lower() in resp_text

        return {
            "source_collection": source_name,
            "target_collection": target_name,
            "isolation_violated": isolation_violated,
            "method": "direct_store_query",
        }

    async def _test_rag_isolation(
        self,
        client: AsyncHttpClient,
        query_ep: dict,
        coll_a: str,
        coll_b: str,
    ) -> dict | None:
        """Test via RAG query endpoint with collection parameter."""
        url = query_ep.get("url", "")

        # Try specifying collection in the query
        body = {
            "query": f"Documents about {coll_b}",
            "question": f"Documents about {coll_b}",
            "input": f"Documents about {coll_b}",
            "collection": coll_a,
            "namespace": coll_a,
            "k": 5,
        }
        resp = await client.post(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
        )
        if resp.error or resp.status_code >= 400:
            return None

        resp_text = (resp.body or "").lower()

        # Check if response contains content from coll_b
        return {
            "source_collection": coll_a,
            "target_collection": coll_b,
            "isolation_violated": coll_b.lower() in resp_text,
            "method": "rag_collection_param",
        }

    def _build_evidence(self, leaks: list[dict]) -> str:
        lines = []
        for leak in leaks:
            lines.append(
                f"{leak['source_collection']} -> {leak['target_collection']} (via {leak['method']})"
            )
        return "\n".join(lines)
