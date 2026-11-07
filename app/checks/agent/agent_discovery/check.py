"""
app/checks/agent/discovery.py - Agent Framework Discovery

Detect AI agent orchestration endpoints and identify frameworks.

Supported frameworks (MVP):
- LangChain / LangGraph
- LangServe

Backlog (future expansion):
- AutoGen
- CrewAI
- AgentGPT
- Semantic Kernel
- Haystack Agents
- SuperAGI
- BabyAGI
- MetaGPT

Discovery methods:
- Common agent endpoint paths (/agent, /run, /invoke, /stream)
- Framework-specific signatures in responses
- Header fingerprinting (X-LangServe-*, etc.)
- Error message patterns

**Probe/grade.** The probe walks the candidate paths (GET,
then POST on a miss) and the capability paths, recording every exchange;
`grade()` re-reads them, rebuilds the endpoint list, and emits one verdict per
discovered endpoint. `_reading()` is the one parser both halves call (§0.12):
each exchange is attributed to its path by the recorded request URL (an exact
path match, so `/run` is never confused with `/agent/run`), not a remembered
list.

**Fixed**: severity is categorical — `high` for an
unauthenticated execution endpoint, `medium` for an unauthenticated
schema/discovery one, `info` when auth is required — so no grader above the rule
tier is called. No `observations:` map: the discriminator embeds the path
(`agent-<path>`), so `provisional_for()` falls to `default: info` and `grade()`
places the real severity. Confidence is where the split pays: framework
attribution is a weighted vote over headers/paths/body/error strings, and the
signal *kind* decides how sure it is — a version header is proof, a shared path
like `/invoke` barely narrows it.

References:
  https://python.langchain.com/docs/langserve
  https://langchain-ai.github.io/langgraph/
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

# Framework detection signatures
FRAMEWORK_SIGNATURES = {
    "langserve": {
        "headers": ["x-langserve-version", "x-langsmith-trace"],
        "paths": ["/invoke", "/stream", "/batch", "/input_schema", "/output_schema"],
        "body_patterns": [
            "langserve",
            "langchain",
            "input_schema",
            "output_schema",
            "configurable",
        ],
        "error_patterns": ["langserve", "langchain.chains", "langchain.agents"],
    },
    "langgraph": {
        "headers": ["x-langgraph-version"],
        "paths": ["/invoke", "/stream", "/state", "/history", "/threads"],
        "body_patterns": ["langgraph", "graph", "nodes", "edges", "state", "checkpoint"],
        "error_patterns": ["langgraph", "StateGraph", "CompiledGraph"],
    },
    "langchain": {
        "headers": [],
        "paths": ["/chain/invoke", "/chain/stream", "/agent/run"],
        "body_patterns": ["langchain", "chain", "agent", "tools", "memory"],
        "error_patterns": ["langchain", "AgentExecutor", "LLMChain", "ConversationChain"],
    },
    "autogen": {
        "headers": [],
        "paths": ["/autogen", "/chat", "/agents"],
        "body_patterns": ["autogen", "assistant", "user_proxy", "groupchat"],
        "error_patterns": ["autogen", "AssistantAgent", "UserProxyAgent"],
    },
    "crewai": {
        "headers": [],
        "paths": ["/crew", "/kickoff", "/tasks"],
        "body_patterns": ["crewai", "crew", "agents", "tasks", "kickoff"],
        "error_patterns": ["crewai", "Crew", "Agent", "Task"],
    },
}

# Common agent endpoint paths
AGENT_PATHS = [
    # LangServe / LangGraph
    "/invoke",
    "/stream",
    "/batch",
    "/input_schema",
    "/output_schema",
    "/config_schema",
    "/state",
    "/history",
    "/threads",
    # Generic agent paths
    "/agent",
    "/agent/run",
    "/agent/invoke",
    "/agent/stream",
    "/agent/chat",
    "/agent/execute",
    "/agent/memory",
    "/agent/tools",
    # Chain paths
    "/chain",
    "/chain/invoke",
    "/chain/run",
    # Run paths
    "/run",
    "/execute",
    "/chat",
    "/completion",
    # API versioned
    "/v1/agent",
    "/v1/invoke",
    "/v1/run",
    "/api/agent",
    "/api/invoke",
]

MEMORY_PATHS = ["/agent/memory", "/memory", "/history"]
TOOLS_PATHS = ["/agent/tools", "/tools", "/input_schema"]
STATE_PATHS = ["/state", "/threads"]


class AgentDiscoveryCheck(ServiceIteratingCheck):
    """
    Discover AI agent orchestration endpoints and identify frameworks.

    Probes common agent paths and fingerprints responses to identify
    the underlying agent framework (LangChain, LangGraph, etc.).
    """

    name = "agent_discovery"
    description = "Detect AI agent orchestration endpoints and identify frameworks"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["agent_endpoints", "agent_frameworks"]
    service_types = ["ai", "api", "http"]

    reason = "Agent endpoints expose autonomous AI systems that can execute multi-step tasks, access tools, and maintain state - high-value targets for goal injection and privilege escalation"
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = ["endpoint discovery", "framework fingerprinting", "API enumeration"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        candidate = self.create_candidate(host=service.host, target=service, target_url=service.url)

        def record(resp, method: str) -> None:
            kwargs = {"method": method}
            if method == "POST":
                kwargs["request_headers"] = JSON_HEADERS
                kwargs["request_json"] = {"input": "test"}
            candidate.attach(
                exchange_from_response(
                    resp, check_name=self.name, scan_id=scan_id, host=service.host, **kwargs
                )
            )

        try:
            async with AsyncHttpClient(cfg) as client:
                for path in AGENT_PATHS:
                    url = service.with_path(path)
                    get_resp = await client.get(url)
                    record(get_resp, "GET")
                    # Original tries POST only when the GET was not agent-like.
                    if (
                        self._analyze_exchange_resp(
                            get_resp.status_code,
                            get_resp.error,
                            dict(get_resp.headers or {}),
                            get_resp.body or "",
                            path,
                        )
                        is None
                    ):
                        post_resp = await client.post(
                            url, json={"input": "test"}, headers=JSON_HEADERS
                        )
                        record(post_resp, "POST")

                # Only probe capabilities when the discovery pass found something.
                if self._has_endpoint(candidate.exchanges, service):
                    for cap_path in MEMORY_PATHS + TOOLS_PATHS + STATE_PATHS:
                        # Skip paths already fetched in the discovery loop.
                        if cap_path in AGENT_PATHS:
                            continue
                        record(await client.get(service.with_path(cap_path)), "GET")

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if candidate.exchanges:
            result.candidates.append(candidate)
            reading = self._reading(candidate.exchanges, service)
            if reading["agent_endpoints"]:
                result.outputs["agent_endpoints"] = reading["agent_endpoints"]
            if reading["frameworks"]:
                result.outputs["agent_frameworks"] = reading["frameworks"]

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        service = ctx.target
        if service is None:
            return []
        reading = self._reading(list(evidence), service)
        ids = evidence.ids()
        verdicts: list[Verdict] = []

        for info in reading["agent_endpoints"]:
            path = info["path"]
            severity = self._determine_severity(info)
            confidence, why = self._confidence(info)
            verdicts.append(
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator=f"agent-{path.strip('/').replace('/', '-')}",
                    title=f"Agent endpoint: {path}",
                    description=self._build_description(info),
                    evidence=self._build_evidence(info),
                    reasoning=why,
                    signals={
                        "framework": info.get("framework"),
                        "framework_confidence": info.get("framework_confidence"),
                        "indicators": info.get("indicators"),
                        "auth_required": info.get("auth_required"),
                    },
                    references=self.references,
                    raw_data=info,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            )
        return verdicts

    def _confidence(self, info: dict) -> tuple[float, str]:
        """How sure the framework attribution / endpoint call is, by signal kind."""
        indicators = info.get("indicators", [])
        if any(i.startswith("header:") for i in indicators):
            return 0.9, "a framework version/trace header is a direct declaration, not an inference"
        if any(i.startswith("error:") for i in indicators):
            return 0.8, (
                "a framework class name leaked in an error body (e.g. AgentExecutor, StateGraph) — "
                "strong, though an error can be echoed rather than raised"
            )
        if any(i.startswith("body:") for i in indicators):
            return 0.55, (
                "framework attribution rests on body substrings (langserve, configurable, …); these "
                "recur across tools and generic JSON, so the framework is a best guess"
            )
        if any(i.startswith("path:") for i in indicators) or info.get("framework"):
            return 0.4, (
                "only a shared path like /invoke or /stream matched; it marks an agent-shaped "
                "endpoint but barely narrows which framework serves it"
            )
        return 0.35, (
            "the endpoint answered with agent-like keywords but no framework signature — an agent "
            "endpoint is likely, its identity unknown"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], service: Service) -> dict:
        """Rebuild the endpoint list + frameworks + capabilities off exchanges."""
        agent_endpoints: list[dict] = []
        detected: set[str] = set()

        for path in AGENT_PATHS:
            get_ex = self._first(exchanges, "GET", path)
            info = self._analyze_exchange(get_ex, path, "GET", service) if get_ex else None
            if info is None:
                post_ex = self._first(exchanges, "POST", path)
                info = self._analyze_exchange(post_ex, path, "POST", service) if post_ex else None
            if info:
                agent_endpoints.append(info)
                if info.get("framework"):
                    detected.add(info["framework"])

        if agent_endpoints:
            capabilities = self._capabilities_from(exchanges, agent_endpoints)
            if capabilities:
                for endpoint in agent_endpoints:
                    endpoint["capabilities"] = capabilities

        return {"agent_endpoints": agent_endpoints, "frameworks": list(detected)}

    def _has_endpoint(self, exchanges: list[Exchange], service: Service) -> bool:
        for path in AGENT_PATHS:
            get_ex = self._first(exchanges, "GET", path)
            if get_ex and self._analyze_exchange(get_ex, path, "GET", service):
                return True
            post_ex = self._first(exchanges, "POST", path)
            if post_ex and self._analyze_exchange(post_ex, path, "POST", service):
                return True
        return False

    def _capabilities_from(self, exchanges: list[Exchange], endpoints: list[dict]) -> dict:
        capabilities = {
            "memory": False,
            "tools": False,
            "streaming": False,
            "state": False,
            "threads": False,
        }
        for mem_path in MEMORY_PATHS:
            ex = self._first(exchanges, "GET", mem_path)
            if ex and ex.response_status not in (404, 405):
                capabilities["memory"] = True
                break
        for tools_path in TOOLS_PATHS:
            ex = self._first(exchanges, "GET", tools_path)
            if ex and ex.response_status == 200:
                capabilities["tools"] = True
                break
        for endpoint in endpoints:
            if "stream" in endpoint.get("path", "").lower():
                capabilities["streaming"] = True
                break
        for state_path in STATE_PATHS:
            ex = self._first(exchanges, "GET", state_path)
            if ex and ex.response_status not in (404, 405):
                if "state" in state_path:
                    capabilities["state"] = True
                else:
                    capabilities["threads"] = True
        return capabilities

    def _analyze_exchange(
        self, exchange: Exchange | None, path: str, method: str, service: Service
    ) -> dict | None:
        if exchange is None:
            return None
        base = self._analyze_exchange_resp(
            exchange.response_status,
            exchange.error,
            exchange.response_headers or {},
            exchange.response_body or "",
            path,
        )
        if base is None:
            return None
        base["url"] = service.with_path(path)
        base["method"] = method
        base["service"] = service.to_dict()
        return base

    def _analyze_exchange_resp(
        self, status_code, error, headers: dict, body: str, path: str
    ) -> dict | None:
        """The framework/indicator analysis, over recorded response fields."""
        if error or status_code in (404, 405, 502, 503):
            return None
        if status_code == 200 and len(body) < 10:
            return None

        indicators: list[str] = []
        framework = None
        framework_confidence = 0

        resp_headers_lower = {k.lower(): v for k, v in headers.items()}

        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            header_matches = sum(1 for h in sigs["headers"] if h in resp_headers_lower)
            if header_matches > 0:
                indicators.append(f"header:{fw_name}")
                if header_matches > framework_confidence:
                    framework = fw_name
                    framework_confidence = header_matches + 2

        path_lower = path.lower()
        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            for sig_path in sigs["paths"]:
                if sig_path in path_lower:
                    indicators.append(f"path:{sig_path}")
                    if framework_confidence < 1:
                        framework = fw_name
                        framework_confidence = 1

        body_lower = body.lower()
        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            body_matches = sum(1 for p in sigs["body_patterns"] if p in body_lower)
            if body_matches > 0:
                indicators.append(f"body:{fw_name}({body_matches})")
                if body_matches > framework_confidence:
                    framework = fw_name
                    framework_confidence = body_matches

        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            for pattern in sigs["error_patterns"]:
                if pattern in body:
                    indicators.append(f"error:{pattern}")
                    framework = fw_name
                    framework_confidence = max(framework_confidence, 3)

        if status_code == 200 and "application/json" in resp_headers_lower.get("content-type", ""):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    if "properties" in data or "type" in data:
                        indicators.append("json-schema")
                    if "state" in data or "history" in data or "messages" in data:
                        indicators.append("stateful-agent")
                    if "tools" in data:
                        indicators.append("tools-available")
            except json.JSONDecodeError:
                pass

        if not indicators:
            agent_keywords = ["agent", "assistant", "task", "execute", "invoke", "chain"]
            if any(kw in body_lower for kw in agent_keywords):
                indicators.append("agent-keywords")
            else:
                return None

        return {
            "path": path,
            "status_code": status_code,
            "framework": framework,
            "framework_confidence": framework_confidence,
            "indicators": indicators,
            "auth_required": status_code == 401,
        }

    @staticmethod
    def _first(exchanges: list[Exchange], method: str, path: str) -> Exchange | None:
        for exchange in exchanges:
            if exchange.request_method != method:
                continue
            if urlparse(exchange.request_url or "").path == path:
                return exchange
        return None

    def _determine_severity(self, endpoint_info: dict) -> str:
        if not endpoint_info.get("auth_required", True):
            exec_keywords = ["invoke", "run", "execute", "stream", "batch"]
            if any(kw in endpoint_info.get("path", "").lower() for kw in exec_keywords):
                return "high"
            return "medium"
        return "info"

    def _build_description(self, endpoint_info: dict) -> str:
        parts = [f"Agent endpoint discovered at {endpoint_info['path']}."]
        if endpoint_info.get("framework"):
            parts.append(f"Framework: {endpoint_info['framework']}.")
        if endpoint_info.get("auth_required"):
            parts.append("Authentication required.")
        else:
            parts.append("No authentication required - potential unauthorized access.")
        if endpoint_info.get("capabilities"):
            caps = endpoint_info["capabilities"]
            active = [k for k, v in caps.items() if v]
            if active:
                parts.append(f"Capabilities: {', '.join(active)}.")
        return " ".join(parts)

    def _build_evidence(self, endpoint_info: dict) -> str:
        lines = [
            f"Path: {endpoint_info['path']}",
            f"Method: {endpoint_info['method']}",
            f"Status: {endpoint_info['status_code']}",
        ]
        if endpoint_info.get("framework"):
            lines.append(
                f"Framework: {endpoint_info['framework']} "
                f"(confidence: {endpoint_info.get('framework_confidence', 0)})"
            )
        if endpoint_info.get("indicators"):
            lines.append(f"Indicators: {', '.join(endpoint_info['indicators'][:5])}")
        return "\n".join(lines)
