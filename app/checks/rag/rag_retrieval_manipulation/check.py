"""
app/checks/rag/retrieval_manipulation.py - Retrieval Manipulation

Test if RAG retrieval parameters can be overridden by the client
(top_k, filters, similarity thresholds) to expand the attack surface
or steer retrieval towards sensitive content.

**Probe/grade.** The probe sweeps the top_k parameter names
and the filter overrides, recording every exchange; `grade()` re-reads them,
rebuilds the retrieval-control reading, and emits the override/bounded verdict
plus the filter verdict. `_reading()` is the one parser both halves call (§0.12):
each request is attributed to its (parameter, k) or filter override by its
recorded request body, never a remembered list.

**Contextual**: whether a client-controllable `top_k` or an
accepted empty filter is a real weakness depends on what the expanded retrieval
exposes — the attack-compliance question — so the rule logic runs at
`GradingTier.RULE` and the real call defers to the planned LLM grading tier. Confidence states the
gap: differing result counts prove the client *controls* retrieval breadth, but
not that the extra documents are sensitive or injection-bearing; an accepted
empty filter proves the parameter was *not rejected*, which an endpoint that
silently ignores unknown fields also does.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Parameter name variants for top_k
TOPK_PARAMS = ["top_k", "k", "n_results", "limit", "topK", "num_results", "max_results"]

# k values the probe sends per parameter name
TOPK_K_VALUES = [1, 10, 50]

# Filter override attempts
FILTER_OVERRIDES = [
    {"filter": {}},
    {"filter": None},
    {"where": {}},
    {"metadata_filter": {}},
]

TEST_QUERY = "test information retrieval"


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

    reason = (
        "If clients can override top_k or disable filters, they can expand "
        "the retrieval surface to include more documents — increasing the "
        "chance of retrieving sensitive or injection-containing content"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["retrieval parameter manipulation", "top_k override", "filter bypass"]

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
                # Test 1: top_k parameter override.
                for param_name in TOPK_PARAMS:
                    counts: dict[int, int] = {}
                    failed = False
                    for k in TOPK_K_VALUES:
                        body = self._topk_body(param_name, k)
                        resp = await client.post(url, json=body, headers=JSON_HEADERS)
                        record(resp, body)
                        if resp.error or resp.status_code >= 400:
                            failed = True
                            break
                        count = self._count_results(resp.body)
                        if count is not None:
                            counts[k] = count
                    # Decide on the exchanges just recorded (§6.2).
                    if not failed and len(counts) >= 2 and len(set(counts.values())) > 1:
                        break

                # Test 2: filter/where clause override.
                for override in FILTER_OVERRIDES:
                    body = self._filter_body(override)
                    resp = await client.post(url, json=body, headers=JSON_HEADERS)
                    record(resp, body)
                    if resp.error or resp.status_code >= 400:
                        continue
                    if resp.status_code == 200 and resp.body:
                        break

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        result.outputs["retrieval_control"] = self._reading(candidate.exchanges)
        return result

    @staticmethod
    def _topk_body(param_name: str, k: int) -> dict:
        return {"query": TEST_QUERY, "question": TEST_QUERY, "input": TEST_QUERY, param_name: k}

    @staticmethod
    def _filter_body(override: dict) -> dict:
        body = {"query": TEST_QUERY, "question": TEST_QUERY, "input": TEST_QUERY}
        body.update(override)
        return body

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        control = self._reading(list(evidence))
        ids = evidence.ids()
        verdicts: list[Verdict] = []

        if control["topk_overridable"]:
            max_k = control["max_topk_accepted"]
            verdicts.append(
                Verdict(
                    severity="high",
                    confidence=0.5,
                    discriminator="topk-override",
                    title=f"Retrieval manipulation: {control['topk_param']} accepts client override",
                    description=(
                        f"Client-supplied '{control['topk_param']}' parameter controls "
                        f"retrieval count. Maximum accepted: {max_k}. "
                        f"Expanded retrieval increases attack surface for indirect injection."
                    ),
                    evidence=self._build_topk_evidence(control),
                    reasoning=(
                        "different k values returned different result counts, which proves the "
                        "client controls retrieval breadth — a real precondition. It does not show "
                        "the extra documents are sensitive or injection-bearing, which is the "
                        "attack-compliance question that needs model-based grading (not yet available)"
                    ),
                    signals={
                        "topk_param": control["topk_param"],
                        "max_topk_accepted": max_k,
                        "retrieval_counts": control["retrieval_counts"],
                    },
                    references=self.references,
                    raw_data=control,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            )
        else:
            verdicts.append(
                Verdict(
                    severity="low",
                    confidence=0.4,
                    discriminator="topk-bounded",
                    title="top_k parameter bounded by server",
                    description="Client override of retrieval parameters was rejected or had no effect.",
                    evidence="Tested parameters: " + ", ".join(TOPK_PARAMS),
                    reasoning=(
                        "no parameter name made the result count vary; the negative is weak because "
                        "a server that caps k silently, or returns a constant small corpus, looks "
                        "identical to one that honours the parameter up to a bound"
                    ),
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            )

        if control["filter_bypassable"]:
            verdicts.append(
                Verdict(
                    severity="medium",
                    confidence=0.35,
                    discriminator="filter-bypass",
                    title="Retrieval filter override accepted",
                    description=(
                        "Filter/where clause parameters accepted from client — "
                        "metadata-based access controls may be bypassable."
                    ),
                    evidence="Empty filter/where clause accepted without error",
                    reasoning=(
                        "an empty filter/where clause was accepted without a 4xx, but that only "
                        "shows the field was not rejected — an endpoint that silently ignores "
                        "unknown JSON fields returns 200 too, so whether the metadata ACL was "
                        "actually bypassed is not shown here"
                    ),
                    signals={"filter_bypassable": True},
                    references=self.references,
                    raw_data={"filter_bypassable": True},
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict[str, Any]:
        """Rebuild the retrieval-control reading off the recorded exchanges."""
        control: dict[str, Any] = {
            "topk_overridable": False,
            "topk_param": None,
            "max_topk_accepted": 0,
            "filter_bypassable": False,
            "retrieval_counts": {},
        }

        for param_name in TOPK_PARAMS:
            counts: dict[int, int] = {}
            failed = False
            any_seen = False
            for k in TOPK_K_VALUES:
                ex = self._find_body(exchanges, self._topk_body(param_name, k))
                if ex is None:
                    continue
                any_seen = True
                if ex.error or (ex.response_status or 0) >= 400:
                    failed = True
                    break
                count = self._count_results(ex.response_body)
                if count is not None:
                    counts[k] = count
            if not any_seen:
                continue
            if not failed and len(counts) >= 2 and len(set(counts.values())) > 1:
                control["topk_overridable"] = True
                control["topk_param"] = param_name
                control["max_topk_accepted"] = max(counts.values())
                control["retrieval_counts"] = counts
                break

        for override in FILTER_OVERRIDES:
            ex = self._find_body(exchanges, self._filter_body(override))
            if ex is None or ex.error or (ex.response_status or 0) >= 400:
                continue
            if ex.response_status == 200 and ex.response_body:
                control["filter_bypassable"] = True
                break

        return control

    @staticmethod
    def _find_body(exchanges: list[Exchange], body: dict) -> Exchange | None:
        """The recorded POST whose request body equals `body`."""
        for exchange in exchanges:
            if exchange.request_method != "POST":
                continue
            try:
                got = json.loads(exchange.request_body or "null")
            except (ValueError, TypeError):
                continue
            if got == body:
                return exchange
        return None

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
