"""
app/checks/rag/auth_bypass.py - Vector Store Authentication Bypass

Go beyond 401 detection — test actual auth enforcement on vector store
APIs with default credentials, common API keys, and header spoofing.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = (
        "Many vector store deployments use no authentication or default keys. "
        "Auth bypass gives full read/write access to the knowledge base"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "CWE-287 Improper Authentication",
    ]
    techniques = ["default credential testing", "auth bypass", "header spoofing"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        detected_stores = context.get("vector_stores", [])
        rag_endpoints = context.get("rag_endpoints", [])

        # Build store base URLs
        store_urls: dict[str, str] = {}
        for ep in rag_endpoints:
            if (
                ep.get("endpoint_type") == "vector_store"
                and ep.get("service", {}).get("host") == service.host
            ):
                url = ep.get("url", service.url)
                if "://" in url:
                    store_urls.setdefault(ep["store_type"], "/".join(url.split("/")[:3]))

        cfg = HttpConfig(timeout_seconds=8.0, verify_ssl=False)
        bypass_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for store_type in detected_stores:
                    store_cfg = STORE_AUTH_ATTEMPTS.get(store_type)
                    if not store_cfg:
                        continue

                    base_url = store_urls.get(store_type, service.url)
                    test_path = store_cfg["test_path"]
                    url = f"{base_url}{test_path}"

                    # First check if endpoint requires auth at all
                    baseline_resp = await client.get(url)
                    if not baseline_resp.error and baseline_resp.status_code == 200:
                        bypass_results.append(
                            {
                                "store_type": store_type,
                                "bypass_type": "no_auth_required",
                                "path": test_path,
                            }
                        )
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Vector store requires no authentication: {store_type}",
                                description=(
                                    f"Vector store '{store_type}' at {test_path} requires "
                                    f"no authentication. Full API access available."
                                ),
                                severity="critical",
                                evidence=f"GET {url} -> HTTP {baseline_resp.status_code}",
                                host=service.host,
                                discriminator=f"noauth-{store_type}",
                                target=service,
                                target_url=url,
                                raw_data={
                                    "store_type": store_type,
                                    "status": baseline_resp.status_code,
                                },
                                references=self.references,
                            )
                        )
                        continue

                    if baseline_resp.status_code not in (401, 403):
                        continue

                    # Try store-specific default credentials
                    for cred in store_cfg["credentials"]:
                        if cred["type"] == "none":
                            continue
                        bypass = await self._try_auth(
                            client, url, cred["headers"], store_type, cred["type"]
                        )
                        if bypass:
                            bypass_results.append(bypass)
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Vector store default key accepted: {store_type}",
                                    description=(
                                        f"Default credential '{cred['type']}' grants access "
                                        f"to {store_type} at {test_path}."
                                    ),
                                    severity="high",
                                    evidence=f"Auth type: {cred['type']}\nPath: {test_path}",
                                    host=service.host,
                                    discriminator=f"default-{store_type}-{cred['type']}",
                                    target=service,
                                    target_url=url,
                                    raw_data=bypass,
                                    references=self.references,
                                )
                            )
                            break  # Found working cred, stop

                    # Try common auth headers
                    for cred in COMMON_AUTH_HEADERS:
                        bypass = await self._try_auth(
                            client, url, cred["headers"], store_type, cred["type"]
                        )
                        if bypass:
                            bypass_results.append(bypass)
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Vector store auth bypass via common header: {store_type}",
                                    description=(
                                        f"Common auth header '{cred['type']}' bypasses "
                                        f"authentication on {store_type}."
                                    ),
                                    severity="high",
                                    evidence=f"Auth type: {cred['type']}\nHeaders: {cred['headers']}",
                                    host=service.host,
                                    discriminator=f"common-{store_type}-{cred['type']}",
                                    target=service,
                                    target_url=url,
                                    raw_data=bypass,
                                    references=self.references,
                                )
                            )
                            break

                    # Try IP-based bypasses
                    for ip_headers in IP_BYPASS_HEADERS:
                        bypass = await self._try_auth(
                            client,
                            url,
                            ip_headers,
                            store_type,
                            f"ip_bypass_{list(ip_headers.keys())[0]}",
                        )
                        if bypass:
                            bypass_results.append(bypass)
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Vector store auth bypass via IP spoofing: {store_type}",
                                    description=(
                                        f"IP-based header bypass accepted on {store_type}. "
                                        f"Headers: {ip_headers}"
                                    ),
                                    severity="medium",
                                    evidence=f"Headers: {ip_headers}\nPath: {test_path}",
                                    host=service.host,
                                    discriminator=f"ip-{store_type}",
                                    target=service,
                                    target_url=url,
                                    raw_data=bypass,
                                    references=self.references,
                                )
                            )
                            break

                    # If no bypass found
                    if not any(b["store_type"] == store_type for b in bypass_results):
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Vector store authentication enforced: {store_type}",
                                description=f"Authentication on {store_type} appears properly enforced.",
                                severity="info",
                                evidence="All bypass attempts returned 401/403",
                                host=service.host,
                                discriminator=f"auth-ok-{store_type}",
                                target=service,
                                target_url=url,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if bypass_results:
            result.outputs["auth_bypass_results"] = bypass_results

        return result

    async def _try_auth(
        self,
        client: AsyncHttpClient,
        url: str,
        headers: dict[str, str],
        store_type: str,
        auth_type: str,
    ) -> dict | None:
        """Try an auth attempt and return result if successful."""
        try:
            resp = await client.get(url, headers=headers)
            if not resp.error and resp.status_code == 200:
                return {
                    "store_type": store_type,
                    "bypass_type": auth_type,
                    "headers": headers,
                    "status": resp.status_code,
                    "preview": (resp.body or "")[:200],
                }
        except Exception:
            pass
        return None
