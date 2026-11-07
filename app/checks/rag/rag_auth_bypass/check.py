"""
app/checks/rag/auth_bypass.py - Vector Store Authentication Bypass

Go beyond 401 detection — test actual auth enforcement on vector store
APIs with default credentials, common API keys, and header spoofing.

**Probe/grade.** For each detected store the probe sends a
baseline request, then — if that returned 401/403 — the default-credential,
common-header and IP-spoof attempts, recording every exchange onto one candidate
per store; `grade()` re-reads them and emits one verdict per outcome.
`_reading()` is the one parser both halves call (§0.12): each auth attempt is
attributed to its outcome by the recorded *request headers* (every attempt is a
GET to the same URL, so the headers are the only thing that tells them apart),
never a remembered list, and which store the evidence belongs to is recovered
from the upstream `vector_stores` output read at grade time (§0.15) plus those
same recorded headers.

**Fixed**: the discriminator embeds the store type and the
credential kind (`default-qdrant-default_key`), so — like `ai_model_info_check`
— the contract declares **no `observations:` map**, `provisional_for()` falls to
`default: info`, and `grade()` places the real severity. Confidence is where the
split pays: a 200 to an unauthenticated request is direct proof of no auth,
whereas an *IP-spoof* header returning 200 can equally be an endpoint that never
checked the header at all, and a "default key accepted" rests on the key genuinely
being the gate rather than the store ignoring an unknown header and answering
anyway.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

# Per-store default credential attempts
STORE_AUTH_ATTEMPTS = {
    "chroma": {
        "test_path": "/api/v1/collections",
        "credentials": [
            {"type": "none", "headers": {}},
            {"type": "bearer_empty", "headers": {"Authorization": "Bearer "}},
            {"type": "token_header", "headers": {"X-Chroma-Token": ""}},
        ],
    },
    "qdrant": {
        "test_path": "/collections",
        "credentials": [
            {"type": "none", "headers": {}},
            {"type": "default_key", "headers": {"api-key": "qdrant"}},
            {"type": "empty_key", "headers": {"api-key": ""}},
            {"type": "default_word", "headers": {"api-key": "default"}},
        ],
    },
    "weaviate": {
        "test_path": "/v1/schema",
        "credentials": [
            {"type": "none", "headers": {}},
            {"type": "bearer_anonymous", "headers": {"Authorization": "Bearer anonymous"}},
        ],
    },
    "pinecone": {
        "test_path": "/describe_index_stats",
        "credentials": [
            {"type": "none", "headers": {}},
            {"type": "empty_api_key", "headers": {"Api-Key": ""}},
        ],
    },
    "milvus": {
        "test_path": "/api/v1/collections",
        "credentials": [
            {"type": "none", "headers": {}},
        ],
    },
}

# IP-based bypass headers
IP_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/"},
]

# Common auth headers to try
COMMON_AUTH_HEADERS = [
    {"type": "bearer_test", "headers": {"Authorization": "Bearer test"}},
    {"type": "x_api_key_empty", "headers": {"X-Api-Key": ""}},
    {"type": "x_api_key_default", "headers": {"X-Api-Key": "default"}},
]


class RAGAuthBypassCheck(ServiceIteratingCheck):
    """
    Test vector store authentication enforcement with default
    credentials, common API keys, and header-based bypasses.
    """

    name = "rag_auth_bypass"
    description = "Test vector store authentication bypass with default credentials"
    intrusive = True

    conditions = [CheckCondition("vector_stores", "truthy")]
    produces = ["auth_bypass_results"]
    service_types = ["ai", "api", "http"]

    reason = (
        "Many vector store deployments use no authentication or default keys. "
        "Auth bypass gives full read/write access to the knowledge base"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "CWE-287 Improper Authentication",
    ]
    techniques = ["default credential testing", "auth bypass", "header spoofing"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        detected_stores = context.get("vector_stores", [])
        store_urls = self._store_urls(context, service)

        cfg = HttpConfig(timeout_seconds=8.0, verify_ssl=False)
        bypass_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for store_type in detected_stores:
                    store_cfg = STORE_AUTH_ATTEMPTS.get(store_type)
                    if not store_cfg:
                        continue

                    base_url = store_urls.get(store_type, service.url)
                    url = f"{base_url}{store_cfg['test_path']}"
                    candidate = self.create_candidate(
                        host=service.host, target=service, target_url=url
                    )

                    async def probe(headers, _c=candidate, _u=url):
                        resp = (
                            await client.get(_u, headers=headers)
                            if headers
                            else await client.get(_u)
                        )
                        _c.attach(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=service.host,
                                method="GET",
                                request_headers=headers,
                            )
                        )
                        return resp

                    # Baseline.
                    baseline = await probe({})
                    if not baseline.error and baseline.status_code == 200:
                        result.candidates.append(candidate)
                        bypass_results.append(
                            {
                                "store_type": store_type,
                                "bypass_type": "no_auth_required",
                                "path": store_cfg["test_path"],
                            }
                        )
                        continue
                    if baseline.status_code not in (401, 403):
                        # Nothing was emitted here historically; keep the recorded
                        # baseline as evidence but grade() will emit no verdict.
                        result.candidates.append(candidate)
                        continue

                    # Store-specific default credentials (stop after first success).
                    for cred in store_cfg["credentials"]:
                        if cred["type"] == "none":
                            continue
                        resp = await probe(cred["headers"])
                        if not resp.error and resp.status_code == 200:
                            break

                    # Common auth headers (independent loop, as before).
                    for cred in COMMON_AUTH_HEADERS:
                        resp = await probe(cred["headers"])
                        if not resp.error and resp.status_code == 200:
                            break

                    # IP-based bypasses.
                    for ip_headers in IP_BYPASS_HEADERS:
                        resp = await probe(ip_headers)
                        if not resp.error and resp.status_code == 200:
                            break

                    result.candidates.append(candidate)
                    for reading in self._reading(candidate.exchanges, store_type):
                        if reading.get("_bypass"):
                            bypass_results.append(reading["_bypass"])

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if bypass_results:
            result.outputs["auth_bypass_results"] = bypass_results

        return result

    @staticmethod
    def _store_urls(context: dict[str, Any], service: Service) -> dict[str, str]:
        store_urls: dict[str, str] = {}
        for ep in context.get("rag_endpoints", []):
            if (
                ep.get("endpoint_type") == "vector_store"
                and ep.get("service", {}).get("host") == service.host
            ):
                url = ep.get("url", service.url)
                if "://" in url:
                    store_urls.setdefault(ep["store_type"], "/".join(url.split("/")[:3]))
        return store_urls

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        detected_stores = (ctx.context or {}).get("vector_stores", [])
        store_type = self._infer_store(exchanges, ctx.target_url or "", detected_stores)
        if not store_type:
            return []

        ids = evidence.ids()
        verdicts: list[Verdict] = []
        for reading in self._reading(exchanges, store_type):
            verdicts.append(self._verdict_from(reading, ctx, ids))
        return [v for v in verdicts if v is not None]

    def _verdict_from(self, reading: dict, ctx: GradeContext, ids: list[str]) -> Verdict | None:
        kind = reading["kind"]
        store_type = reading["store_type"]
        test_path = reading["test_path"]
        url = reading.get("url")

        if kind == "noauth":
            return Verdict(
                severity="critical",
                confidence=0.95,
                discriminator=f"noauth-{store_type}",
                title=f"Vector store requires no authentication: {store_type}",
                description=(
                    f"Vector store '{store_type}' at {test_path} requires "
                    f"no authentication. Full API access available."
                ),
                evidence=f"GET {url} -> HTTP {reading['status']}",
                reasoning=(
                    "the unauthenticated baseline request returned 200 — direct, unambiguous proof "
                    "the API is open; the only residual doubt is whether the 200 body is real data "
                    "or an empty/permission-shaped response"
                ),
                signals={"store_type": store_type, "status": reading["status"]},
                references=self.references,
                raw_data={"store_type": store_type, "status": reading["status"]},
                tier=ctx.tier,
                evidence_ids=ids,
            )
        if kind == "default":
            cred = reading["cred"]
            return Verdict(
                severity="high",
                confidence=0.7,
                discriminator=f"default-{store_type}-{cred['type']}",
                title=f"Vector store default key accepted: {store_type}",
                description=(
                    f"Default credential '{cred['type']}' grants access "
                    f"to {store_type} at {test_path}."
                ),
                evidence=f"Auth type: {cred['type']}\nPath: {test_path}",
                reasoning=(
                    "the baseline was refused (401/403) and this default credential drew a 200, so "
                    "the key changed the outcome — strong. Held below certainty because a store that "
                    "ignores an unknown auth header and answers anyway would look identical, and the "
                    "200 body was not confirmed to be real data"
                ),
                signals=reading["_bypass"],
                references=self.references,
                raw_data=reading["_bypass"],
                tier=ctx.tier,
                evidence_ids=ids,
            )
        if kind == "common":
            cred = reading["cred"]
            return Verdict(
                severity="high",
                confidence=0.65,
                discriminator=f"common-{store_type}-{cred['type']}",
                title=f"Vector store auth bypass via common header: {store_type}",
                description=(
                    f"Common auth header '{cred['type']}' bypasses authentication on {store_type}."
                ),
                evidence=f"Auth type: {cred['type']}\nHeaders: {cred['headers']}",
                reasoning=(
                    "a generic auth header flipped a 401 to a 200; that the specific header was the "
                    "gate is likely but not shown — an endpoint that stops enforcing after any "
                    "Authorization header is present would behave the same"
                ),
                signals=reading["_bypass"],
                references=self.references,
                raw_data=reading["_bypass"],
                tier=ctx.tier,
                evidence_ids=ids,
            )
        if kind == "ip":
            ip_headers = reading["headers"]
            return Verdict(
                severity="medium",
                confidence=0.4,
                discriminator=f"ip-{store_type}",
                title=f"Vector store auth bypass via IP spoofing: {store_type}",
                description=(
                    f"IP-based header bypass accepted on {store_type}. Headers: {ip_headers}"
                ),
                evidence=f"Headers: {ip_headers}\nPath: {test_path}",
                reasoning=(
                    "an X-Forwarded-For / X-Real-IP header preceded a 200, but the header is trivial "
                    "to send and an endpoint that never consults it returns 200 regardless — so this "
                    "reads as a bypass only if the store actually trusts client-supplied IP headers, "
                    "which is not established here"
                ),
                signals=reading["_bypass"],
                references=self.references,
                raw_data=reading["_bypass"],
                tier=ctx.tier,
                evidence_ids=ids,
            )
        if kind == "auth-ok":
            return Verdict(
                severity="info",
                confidence=0.6,
                discriminator=f"auth-ok-{store_type}",
                title=f"Vector store authentication enforced: {store_type}",
                description=f"Authentication on {store_type} appears properly enforced.",
                evidence="All bypass attempts returned 401/403",
                reasoning=(
                    "every credential, common-header and IP-spoof attempt was refused, which is good "
                    "evidence of enforcement — bounded only by the attempt list being finite, so a "
                    "default key outside it would be missed"
                ),
                signals={"store_type": store_type},
                tier=ctx.tier,
                evidence_ids=ids,
            )
        return None

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], store_type: str) -> list[dict]:
        """Rebuild one store's auth-bypass outcomes off the recorded exchanges.

        Every attempt is a GET to the same URL, so each is identified by its
        recorded request headers. Returns the list of outcomes `grade()` turns
        into verdicts; an empty list means nothing was emitted (baseline neither
        open nor auth-guarded).
        """
        store_cfg = STORE_AUTH_ATTEMPTS.get(store_type)
        if not store_cfg:
            return []
        test_path = store_cfg["test_path"]

        baseline = self._by_headers(exchanges, {})
        if baseline is None:
            return []
        url = baseline.request_url
        if not baseline.error and baseline.response_status == 200:
            return [
                {
                    "kind": "noauth",
                    "store_type": store_type,
                    "test_path": test_path,
                    "url": url,
                    "status": baseline.response_status,
                    "_bypass": {
                        "store_type": store_type,
                        "bypass_type": "no_auth_required",
                        "path": test_path,
                    },
                }
            ]
        if baseline.response_status not in (401, 403):
            return []

        outcomes: list[dict] = []

        for cred in store_cfg["credentials"]:
            if cred["type"] == "none":
                continue
            ex = self._by_headers(exchanges, cred["headers"])
            if ex is None:
                continue
            if not ex.error and ex.response_status == 200:
                outcomes.append(
                    {
                        "kind": "default",
                        "store_type": store_type,
                        "test_path": test_path,
                        "url": url,
                        "cred": cred,
                        "_bypass": self._bypass(store_type, cred["type"], cred["headers"], ex),
                    }
                )
                break

        for cred in COMMON_AUTH_HEADERS:
            ex = self._by_headers(exchanges, cred["headers"])
            if ex is None:
                continue
            if not ex.error and ex.response_status == 200:
                outcomes.append(
                    {
                        "kind": "common",
                        "store_type": store_type,
                        "test_path": test_path,
                        "url": url,
                        "cred": cred,
                        "_bypass": self._bypass(store_type, cred["type"], cred["headers"], ex),
                    }
                )
                break

        for ip_headers in IP_BYPASS_HEADERS:
            ex = self._by_headers(exchanges, ip_headers)
            if ex is None:
                continue
            if not ex.error and ex.response_status == 200:
                auth_type = f"ip_bypass_{list(ip_headers.keys())[0]}"
                outcomes.append(
                    {
                        "kind": "ip",
                        "store_type": store_type,
                        "test_path": test_path,
                        "url": url,
                        "headers": ip_headers,
                        "_bypass": self._bypass(store_type, auth_type, ip_headers, ex),
                    }
                )
                break

        if not outcomes:
            outcomes.append(
                {"kind": "auth-ok", "store_type": store_type, "test_path": test_path, "url": url}
            )
        return outcomes

    @staticmethod
    def _bypass(store_type: str, auth_type: str, headers: dict, ex: Exchange) -> dict:
        return {
            "store_type": store_type,
            "bypass_type": auth_type,
            "headers": headers,
            "status": ex.response_status,
            "preview": (ex.response_body or "")[:200],
        }

    @staticmethod
    def _by_headers(exchanges: list[Exchange], headers: dict) -> Exchange | None:
        """The recorded GET whose request headers exactly match `headers`."""
        for exchange in exchanges:
            if exchange.request_method != "GET":
                continue
            if dict(exchange.request_headers or {}) == dict(headers):
                return exchange
        return None

    def _infer_store(
        self, exchanges: list[Exchange], target_url: str, detected_stores: list[str]
    ) -> str:
        """Which store this candidate's evidence is for.

        The candidate's `target_url` ends in one store's `test_path`; where two
        stores share a path (chroma and milvus both use `/api/v1/collections`),
        a store-specific credential header in the evidence breaks the tie, and
        otherwise the first such detected store is used.
        """
        candidates = [
            s
            for s in detected_stores
            if s in STORE_AUTH_ATTEMPTS and target_url.endswith(STORE_AUTH_ATTEMPTS[s]["test_path"])
        ]
        if not candidates:
            return ""
        if len(candidates) == 1:
            return candidates[0]
        for store_type in candidates:
            for cred in STORE_AUTH_ATTEMPTS[store_type]["credentials"]:
                if cred["type"] == "none":
                    continue
                if self._by_headers(exchanges, cred["headers"]) is not None:
                    return store_type
        return candidates[0]
