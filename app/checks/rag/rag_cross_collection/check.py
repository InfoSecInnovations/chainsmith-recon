"""
app/checks/rag/cross_collection.py - Cross-Collection Retrieval

Test if queries against one collection can retrieve documents from
another. Isolation failures mean public queries could surface private
documents.

**Probe/grade.** The probe runs the two direct-store
isolation queries and the RAG-parameter query, recording each exchange;
`grade()` re-reads them, rebuilds the leak list, and emits one verdict.
`_reading()` is the one parser both halves call (§0.12): each isolation test is
attributed to its (source, target) pair by its recorded request URL and body, and
the collection names come from the upstream `knowledge_base_structure` output read
at grade time (§0.15), not a probe-time flag.

**Contextual**: whether a cross-collection leak is a real
authorization failure is the attack-compliance question, so the rule logic runs
at `GradingTier.RULE` and defers to the planned LLM grading tier. Confidence states the gap plainly:
the leak signal is the *target collection's name* appearing in the response to a
query scoped to a different collection — but the query text itself contains that
name ("Documents about <target>"), so a model that simply echoes the question, or
a store that ranks by the shared term, looks like an isolation break without one.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}


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

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        plan = self._plan(context, service)
        if plan is None:
            return result
        base_url, store_type, coll_a, coll_b, query_eps = plan

        cfg = HttpConfig(timeout_seconds=12.0, verify_ssl=False)
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
                for source, target in ((coll_a, coll_b), (coll_b, coll_a)):
                    probe = self._direct_query(base_url, store_type, source, target)
                    if probe is not None:
                        url, body = probe
                        record(await client.post(url, json=body, headers=JSON_HEADERS), body)

                if query_eps:
                    url, body = self._rag_query(query_eps[0], coll_a["name"], coll_b["name"])
                    record(await client.post(url, json=body, headers=JSON_HEADERS), body)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        cross_results = self._reading(candidate.exchanges, context, service)
        if cross_results:
            result.outputs["cross_collection_results"] = cross_results

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        service = ctx.target
        if service is None:
            return []
        cross_results = self._reading(list(evidence), ctx.context or {}, service)
        ids = evidence.ids()
        leaks = [r for r in cross_results if r.get("isolation_violated")]

        if leaks:
            return [
                Verdict(
                    severity="critical" if len(leaks) > 1 else "high",
                    confidence=0.4,
                    discriminator="cross-collection-leak",
                    title=(
                        f"Cross-collection retrieval: query to '{leaks[0]['source_collection']}' "
                        f"returned documents from '{leaks[0]['target_collection']}'"
                    ),
                    description=(
                        "Collection isolation not enforced. Queries retrieve from "
                        "all collections regardless of target."
                    ),
                    evidence=self._build_evidence(leaks),
                    reasoning=(
                        "the target collection's name appeared in a response to a query scoped to a "
                        "different collection — but the query text itself asks 'Documents about "
                        "<target>', so an echo of the question, or a store ranking on the shared "
                        "term, reproduces this signal without an actual isolation break; a real "
                        "leak needs content unique to the target, which needs model-based grading (not yet available)"
                    ),
                    signals={"leaks": leaks},
                    references=self.references,
                    raw_data={"leaks": leaks},
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        return [
            Verdict(
                severity="info",
                confidence=0.4,
                discriminator="isolation-ok",
                title="Collection isolation enforced",
                description="Queries to one collection did not return documents from another.",
                evidence=f"Tested {len(cross_results)} isolation queries",
                reasoning=(
                    "no query surfaced the other collection's name; the negative is only as strong "
                    "as the probe, which uses the collection name as the discriminator — a store "
                    "that isolates correctly and one that returned nothing for an unrelated query "
                    "look the same here"
                ),
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    # ── Shared plan + parser ──────────────────────────────────────────

    def _plan(
        self, context: dict[str, Any], service: Service
    ) -> tuple[str, str | None, dict, dict, list[dict]] | None:
        """The collections, store type, and endpoints both halves work from.

        Read from the upstream `knowledge_base_structure` and `rag_endpoints`
        outputs, so the probe and a later re-grade agree on which pair of
        collections was tested.
        """
        kb_structure = context.get("knowledge_base_structure", [])
        rag_endpoints = context.get("rag_endpoints", [])

        all_collections: list[dict] = []
        store_type = None
        for struct in kb_structure:
            colls = struct.get("collections", [])
            if len(colls) >= 2:
                all_collections = colls
                store_type = struct.get("store_type")
                break
        if len(all_collections) < 2:
            return None

        base_url = service.url
        if "://" in base_url:
            base_url = "/".join(base_url.split("/")[:3])

        query_eps = [
            ep
            for ep in rag_endpoints
            if ep.get("service", {}).get("host") == service.host
            and ep.get("endpoint_type") == "rag_query"
        ]
        return base_url, store_type, all_collections[0], all_collections[1], query_eps

    def _reading(
        self, exchanges: list[Exchange], context: dict[str, Any], service: Service
    ) -> list[dict]:
        """Rebuild the cross-collection results off the recorded exchanges."""
        plan = self._plan(context, service)
        if plan is None:
            return []
        base_url, store_type, coll_a, coll_b, query_eps = plan
        cross_results: list[dict] = []

        for source, target in ((coll_a, coll_b), (coll_b, coll_a)):
            probe = self._direct_query(base_url, store_type, source, target)
            if probe is None:
                continue
            url, body = probe
            ex = self._find(exchanges, url, body)
            if ex is None or ex.error or (ex.response_status or 0) >= 400:
                continue
            target_name = target.get("name", "")
            resp_text = (ex.response_body or "").lower()
            cross_results.append(
                {
                    "source_collection": source.get("name", ""),
                    "target_collection": target_name,
                    "isolation_violated": target_name.lower() in resp_text,
                    "method": "direct_store_query",
                }
            )

        if query_eps:
            url, body = self._rag_query(query_eps[0], coll_a["name"], coll_b["name"])
            ex = self._find(exchanges, url, body)
            if ex is not None and not ex.error and (ex.response_status or 0) < 400:
                resp_text = (ex.response_body or "").lower()
                cross_results.append(
                    {
                        "source_collection": coll_a["name"],
                        "target_collection": coll_b["name"],
                        "isolation_violated": coll_b["name"].lower() in resp_text,
                        "method": "rag_collection_param",
                    }
                )

        return cross_results

    @staticmethod
    def _direct_query(
        base_url: str, store_type: str | None, source_coll: dict, target_coll: dict
    ) -> tuple[str, dict] | None:
        """The URL+body of a direct store isolation query, or None for an
        unsupported store type (matching the original)."""
        source_name = source_coll.get("name", "")
        target_name = target_coll.get("name", "")
        query = f"Documents about {target_name}"
        if store_type == "chroma":
            return (
                f"{base_url}/api/v1/collections/{source_name}/query",
                {"query_texts": [query], "n_results": 5},
            )
        if store_type == "qdrant":
            return (
                f"{base_url}/collections/{source_name}/points/search",
                {"vector": [0.0] * 3, "limit": 5},
            )
        return None

    @staticmethod
    def _rag_query(query_ep: dict, coll_a: str, coll_b: str) -> tuple[str, dict]:
        url = query_ep.get("url", "")
        body = {
            "query": f"Documents about {coll_b}",
            "question": f"Documents about {coll_b}",
            "input": f"Documents about {coll_b}",
            "collection": coll_a,
            "namespace": coll_a,
            "k": 5,
        }
        return url, body

    @staticmethod
    def _find(exchanges: list[Exchange], url: str, body: dict) -> Exchange | None:
        """The recorded POST to `url`'s path whose request body equals `body`."""
        want_path = urlparse(url).path
        for exchange in exchanges:
            if exchange.request_method != "POST":
                continue
            if urlparse(exchange.request_url or "").path != want_path:
                continue
            try:
                got = json.loads(exchange.request_body or "null")
            except (ValueError, TypeError):
                continue
            if got == body:
                return exchange
        return None

    def _build_evidence(self, leaks: list[dict]) -> str:
        lines = []
        for leak in leaks:
            lines.append(
                f"{leak['source_collection']} -> {leak['target_collection']} (via {leak['method']})"
            )
        return "\n".join(lines)
