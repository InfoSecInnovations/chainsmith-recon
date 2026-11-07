"""
app/checks/agent/agent_multi_agent_detection/check.py - Multi-Agent System Detection

Detect multi-agent architectures (supervisor + workers, debate patterns,
routing agents, crew-based systems) that single-endpoint discovery may miss.

Detection methods:
- Response analysis for delegation indicators
- Endpoint probing for multi-agent management paths
- Response style variation across repeated prompts
- Metadata inspection for agent identifiers

**Probe/grade.** The probe hits the management paths, sends
the delegation prompts, and reads response metadata, recording every exchange;
`grade()` re-reads them, rebuilds the `topology` dict, and emits the single
verdict its priority selects. `_reading()` is the one parser both halves call
(§0.12): which family an exchange belongs to is read back off its recorded
request (method + path + prompt), never a remembered list.

**Fixed**: the three discriminators are categorical —
`management-endpoint` (medium), `delegation-detected` (medium), `agent-ids`
(low) — so no grader above the rule tier is called. Confidence separates a
structured agent listing from a bare architecture keyword, and marks the
delegation-phrase match as the weakest signal: a model narrating "the research
agent will handle that" is describing a role, not proving a second agent exists.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://atlas.mitre.org/
"""

import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Endpoints that reveal multi-agent architectures
MULTI_AGENT_PATHS = [
    "/crew",
    "/kickoff",
    "/agents/list",
    "/agents",
    "/groupchat",
    "/workers",
    "/supervisor",
    "/orchestrator",
    "/v1/agents",
    "/api/agents",
    "/agent/list",
    "/graph",
    "/nodes",
    "/edges",
]

# Delegation indicators in agent responses
DELEGATION_PATTERNS = [
    "delegating to",
    "passing to",
    "forwarding to",
    "agent-1",
    "agent-2",
    "agent_1",
    "agent_2",
    "the research agent",
    "the analysis agent",
    "the review agent",
    "specialist agent",
    "worker agent",
    "supervisor",
    "handing off to",
    "routing to",
    "assigned to",
    "crew member",
    "task delegation",
]

# Test prompts to elicit multi-agent behavior
PROBE_PROMPTS = [
    "What agents or team members are involved in processing my request?",
    "Describe the steps and roles involved in answering this question.",
    "Who else is helping you with this task?",
]

METADATA_PROBE = "hello"


class AgentMultiAgentDetectionCheck(ServiceIteratingCheck):
    """
    Detect multi-agent system architectures.

    Identifies supervisor/worker, crew, debate, and routing patterns
    by probing management endpoints and analyzing response patterns
    for delegation indicators.
    """

    name = "agent_multi_agent_detection"
    description = "Detect multi-agent system architectures and topology"

    conditions = [CheckCondition("agent_endpoints", "truthy")]
    produces = ["multi_agent_topology"]
    service_types = ["ai", "api", "http"]

    reason = (
        "Multi-agent systems introduce trust chain vulnerabilities where "
        "one compromised agent can influence all downstream agents"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = [
        "multi-agent detection",
        "topology mapping",
        "delegation analysis",
    ]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        agent_endpoints = context.get("agent_endpoints", [])
        service_endpoints = [
            ep for ep in agent_endpoints if ep.get("service", {}).get("host") == service.host
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        candidate = self.create_candidate(host=service.host, target=service, target_url=service.url)

        try:
            async with AsyncHttpClient(cfg) as client:
                # 1. Probe multi-agent management endpoints
                for path in MULTI_AGENT_PATHS:
                    url = service.with_path(path)
                    resp = await client.get(url)
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                # 2. Probe execution endpoints for delegation indicators
                exec_endpoints = [
                    ep
                    for ep in service_endpoints
                    if any(
                        kw in ep.get("path", "").lower()
                        for kw in ["invoke", "run", "execute", "chat"]
                    )
                ]
                for ep in exec_endpoints[:2]:
                    url = ep.get("url", service.url)
                    for prompt in PROBE_PROMPTS:
                        body = self._build_request_body(prompt, ep)
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

                # 3. Check response metadata for agent identifiers
                for ep in service_endpoints[:3]:
                    url = ep.get("url", service.url)
                    body = {"input": METADATA_PROBE}
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

        if candidate.exchanges:
            result.candidates.append(candidate)
            topology = self._reading(candidate.exchanges)
            if topology["agent_count"] > 0:
                result.outputs["multi_agent_topology"] = topology

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        topology = self._reading(list(evidence))
        ids = evidence.ids()

        if topology["management_endpoints"]:
            structured = any(e.get("agent_names") for e in topology["management_endpoints"])
            confidence = 0.7 if structured else 0.5
            return [
                Verdict(
                    severity="medium",
                    confidence=confidence,
                    discriminator="management-endpoint",
                    title=(
                        f"Agent orchestrator endpoint: "
                        f"{topology['management_endpoints'][0]['path']}"
                    ),
                    description=(
                        "Multi-agent management endpoint discovered. "
                        f"Returns information about {topology['agent_count']} agents. "
                        f"Architecture: {topology['architecture']}."
                    ),
                    evidence=self._build_evidence(topology),
                    reasoning=(
                        "an agent listing parsed straight out of the endpoint's JSON is a "
                        "structural fact"
                        if structured
                        else "the endpoint answered and its path/body matched an architecture "
                        "keyword, but no agent listing was parsed — the route may exist without a "
                        "real multi-agent system behind it"
                    ),
                    signals=topology,
                    references=self.references,
                    raw_data=topology,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        if topology["delegation_patterns"]:
            return [
                Verdict(
                    severity="medium",
                    confidence=0.4,
                    discriminator="delegation-detected",
                    title="Multi-agent system detected via delegation patterns",
                    description=(
                        "Responses indicate delegation between agents. "
                        f"Detected patterns: {', '.join(topology['delegation_patterns'][:3])}. "
                        f"Architecture: {topology['architecture']}."
                    ),
                    evidence=self._build_evidence(topology),
                    reasoning=(
                        "delegation is inferred from phrase matches ('handing off to', 'the "
                        "research agent') in free text; a single agent narrating the roles it is "
                        "playing produces the same words, so this is a lead, not proof of a second "
                        "agent"
                    ),
                    signals=topology,
                    references=self.references,
                    raw_data=topology,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        if topology["agent_names"]:
            return [
                Verdict(
                    severity="low",
                    confidence=0.6,
                    discriminator="agent-ids",
                    title="Multiple agent identifiers detected",
                    description=(
                        f"Response metadata reveals {len(topology['agent_names'])} "
                        f"agent identifiers: {', '.join(topology['agent_names'][:5])}."
                    ),
                    evidence=self._build_evidence(topology),
                    reasoning=(
                        "the identifiers come from response headers or an `agent_name`/`agent_id` "
                        "field — a direct signal, though distinct ids need not mean distinct agents"
                    ),
                    signals=topology,
                    raw_data=topology,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        return []

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Rebuild the topology off the recorded exchanges."""
        topology = {
            "agent_count": 0,
            "agent_names": [],
            "architecture": "unknown",
            "delegation_patterns": [],
            "management_endpoints": [],
        }

        for exchange in exchanges:
            if exchange.request_method == "GET":
                path = self._management_path(exchange.request_url)
                if path is None or exchange.error:
                    continue
                if exchange.response_status in (404, 405, 502, 503):
                    continue
                endpoint_data = self._analyze_management_endpoint(exchange, path)
                if endpoint_data:
                    topology["management_endpoints"].append(endpoint_data)
                    if endpoint_data.get("agent_names"):
                        topology["agent_names"].extend(endpoint_data["agent_names"])
                    if endpoint_data.get("architecture"):
                        topology["architecture"] = endpoint_data["architecture"]
            elif exchange.request_method == "POST":
                prompt = self._prompt_of(exchange)
                if prompt in PROBE_PROMPTS:
                    if exchange.error or (exchange.response_status or 0) >= 400:
                        continue
                    topology["delegation_patterns"].extend(
                        self._detect_delegation(exchange.response_body or "")
                    )
                elif prompt == METADATA_PROBE:
                    if exchange.error:
                        continue
                    agent_id = self._extract_agent_id(exchange)
                    if agent_id and agent_id not in topology["agent_names"]:
                        topology["agent_names"].append(agent_id)

        topology["agent_names"] = list(set(topology["agent_names"]))
        topology["delegation_patterns"] = list(set(topology["delegation_patterns"]))
        topology["agent_count"] = max(
            len(topology["agent_names"]),
            2 if topology["delegation_patterns"] else 0,
        )
        if topology["architecture"] == "unknown" and topology["agent_count"] > 0:
            topology["architecture"] = self._infer_architecture(topology)
        return topology

    @staticmethod
    def _management_path(url: str | None) -> str | None:
        """The MULTI_AGENT_PATH a recorded GET targeted (longest suffix match)."""
        req_path = urlparse(url or "").path
        matches = [p for p in MULTI_AGENT_PATHS if req_path.endswith(p)]
        return max(matches, key=len) if matches else None

    def _analyze_management_endpoint(self, exchange: Exchange, path: str) -> dict | None:
        """Analyze a management endpoint response for agent information."""
        body = exchange.response_body or ""
        body_lower = body.lower()
        headers = exchange.response_headers or {}

        agent_names: list[str] = []
        architecture = None

        if exchange.response_status == 200 and "application/json" in headers.get(
            "content-type", ""
        ):
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    for item in data[:20]:
                        if isinstance(item, dict):
                            name = item.get("name") or item.get("agent_name") or item.get("id")
                            if name:
                                agent_names.append(str(name))
                        elif isinstance(item, str):
                            agent_names.append(item)
                elif isinstance(data, dict):
                    if "agents" in data:
                        agents = data["agents"]
                        if isinstance(agents, list):
                            for a in agents[:20]:
                                n = a.get("name") if isinstance(a, dict) else str(a)
                                if n:
                                    agent_names.append(n)
                    if "nodes" in data:
                        architecture = "graph"
                        nodes = data["nodes"]
                        if isinstance(nodes, list):
                            for n in nodes[:20]:
                                name = n.get("name") if isinstance(n, dict) else str(n)
                                if name:
                                    agent_names.append(name)
                    if "crew" in data or "tasks" in data:
                        architecture = "crew"
                    if "groupchat" in data or "participants" in data:
                        architecture = "debate"
            except (json.JSONDecodeError, TypeError):
                pass

        if "kickoff" in path or "crew" in body_lower:
            architecture = architecture or "crew"
        elif "groupchat" in path or "groupchat" in body_lower:
            architecture = architecture or "debate"
        elif "supervisor" in path or "orchestrator" in path:
            architecture = architecture or "supervisor"
        elif "graph" in path or "nodes" in path:
            architecture = architecture or "graph"

        if not agent_names and not architecture:
            return None

        return {
            "path": path,
            "status_code": exchange.response_status,
            "agent_names": agent_names,
            "architecture": architecture,
        }

    def _detect_delegation(self, body: str) -> list[str]:
        body_lower = body.lower()
        return [p for p in DELEGATION_PATTERNS if p in body_lower]

    def _extract_agent_id(self, exchange: Exchange) -> str | None:
        headers = exchange.response_headers or {}
        for header in ["x-agent-id", "x-agent-name", "x-worker-id"]:
            val = headers.get(header)
            if val:
                return val
        body = exchange.response_body or ""
        if "application/json" in headers.get("content-type", ""):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    return data.get("agent_name") or data.get("agent_id")
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def _prompt_of(self, exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        if "input" in body and isinstance(body["input"], str):
            return body["input"]
        messages = body.get("messages")
        if isinstance(messages, list) and messages:
            last = messages[-1]
            if isinstance(last, dict):
                return str(last.get("content", ""))
        return ""

    def _build_request_body(self, prompt: str, endpoint: dict) -> dict:
        framework = endpoint.get("framework", "").lower()
        if framework in ("langserve", "langchain", "langgraph"):
            return {"input": prompt}
        path = endpoint.get("path", "").lower()
        if "chat" in path:
            return {"messages": [{"role": "user", "content": prompt}]}
        return {"input": prompt}

    def _infer_architecture(self, topology: dict) -> str:
        patterns = " ".join(topology["delegation_patterns"]).lower()
        if "supervisor" in patterns or "orchestrator" in patterns:
            return "supervisor"
        if "crew" in patterns or "task delegation" in patterns:
            return "crew"
        if "debate" in patterns:
            return "debate"
        if "routing" in patterns:
            return "routing"
        return "unknown"

    def _build_evidence(self, topology: dict) -> str:
        lines = [f"Agent count: {topology['agent_count']}"]
        if topology["agent_names"]:
            lines.append(f"Agent names: {', '.join(topology['agent_names'][:5])}")
        lines.append(f"Architecture: {topology['architecture']}")
        if topology["delegation_patterns"]:
            lines.append(f"Delegation patterns: {', '.join(topology['delegation_patterns'][:3])}")
        if topology["management_endpoints"]:
            paths = [e["path"] for e in topology["management_endpoints"]]
            lines.append(f"Management endpoints: {', '.join(paths)}")
        return "\n".join(lines)
