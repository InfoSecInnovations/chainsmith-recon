"""
app/checks/agent/multi_agent_detection.py - Multi-Agent System Detection

Detect multi-agent architectures (supervisor + workers, debate patterns,
routing agents, crew-based systems) that single-endpoint discovery may miss.

Detection methods:
- Response analysis for delegation indicators
- Endpoint probing for multi-agent management paths
- Response style variation across repeated prompts
- Metadata inspection for agent identifiers

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://atlas.mitre.org/
"""

import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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

    timeout_seconds = 90.0
    delay_between_targets = 0.3

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

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        agent_endpoints = context.get("agent_endpoints", [])
        service_endpoints = [
            ep for ep in agent_endpoints if ep.get("service", {}).get("host") == service.host
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        topology = {
            "agent_count": 0,
            "agent_names": [],
            "architecture": "unknown",
            "delegation_patterns": [],
            "management_endpoints": [],
        }

        try:
            async with AsyncHttpClient(cfg) as client:
                # 1. Probe multi-agent management endpoints
                for path in MULTI_AGENT_PATHS:
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code in (404, 405, 502, 503):
                        continue

                    endpoint_data = self._analyze_management_endpoint(resp, path, service)
                    if endpoint_data:
                        topology["management_endpoints"].append(endpoint_data)
                        if endpoint_data.get("agent_names"):
                            topology["agent_names"].extend(endpoint_data["agent_names"])
                        if endpoint_data.get("architecture"):
                            topology["architecture"] = endpoint_data["architecture"]

                # 2. Probe execution endpoints for delegation indicators
                exec_endpoints = [
                    ep
                    for ep in service_endpoints
                    if any(
                        kw in ep.get("path", "").lower()
                        for kw in ["invoke", "run", "execute", "chat"]
                    )
                ]

                for ep in exec_endpoints[:2]:  # Limit probing
                    url = ep.get("url", service.url)
                    for prompt in PROBE_PROMPTS:
                        body = self._build_request_body(prompt, ep)
                        resp = await client.post(
                            url,
                            json=body,
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.error or resp.status_code >= 400:
                            continue

                        patterns = self._detect_delegation(resp.body or "")
                        topology["delegation_patterns"].extend(patterns)

                # 3. Check response metadata for agent identifiers
                for ep in service_endpoints[:3]:
                    url = ep.get("url", service.url)
                    resp = await client.post(
                        url,
                        json={"input": "hello"},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.error:
                        continue
                    agent_id = self._extract_agent_id(resp)
                    if agent_id and agent_id not in topology["agent_names"]:
                        topology["agent_names"].append(agent_id)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Deduplicate
        topology["agent_names"] = list(set(topology["agent_names"]))
        topology["delegation_patterns"] = list(set(topology["delegation_patterns"]))
        topology["agent_count"] = max(
            len(topology["agent_names"]),
            2 if topology["delegation_patterns"] else 0,
        )

        # Infer architecture if not already set
        if topology["architecture"] == "unknown" and topology["agent_count"] > 0:
            topology["architecture"] = self._infer_architecture(topology)

        # Generate observations
        if topology["management_endpoints"]:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Agent orchestrator endpoint: {topology['management_endpoints'][0]['path']}",
                    description=(
                        f"Multi-agent management endpoint discovered. "
                        f"Returns information about {topology['agent_count']} agents. "
                        f"Architecture: {topology['architecture']}."
                    ),
                    severity="medium",
                    evidence=self._build_evidence(topology),
                    host=service.host,
                    discriminator="management-endpoint",
                    target=service,
                    target_url=service.url,
                    raw_data=topology,
                    references=self.references,
                )
            )
        elif topology["delegation_patterns"]:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Multi-agent system detected via delegation patterns",
                    description=(
                        f"Responses indicate delegation between agents. "
                        f"Detected patterns: {', '.join(topology['delegation_patterns'][:3])}. "
                        f"Architecture: {topology['architecture']}."
                    ),
                    severity="medium",
                    evidence=self._build_evidence(topology),
                    host=service.host,
                    discriminator="delegation-detected",
                    target=service,
                    target_url=service.url,
                    raw_data=topology,
                    references=self.references,
                )
            )
        elif topology["agent_names"]:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Multiple agent identifiers detected",
                    description=(
                        f"Response metadata reveals {len(topology['agent_names'])} "
                        f"agent identifiers: {', '.join(topology['agent_names'][:5])}."
                    ),
                    severity="low",
                    evidence=self._build_evidence(topology),
                    host=service.host,
                    discriminator="agent-ids",
                    target=service,
                    target_url=service.url,
                    raw_data=topology,
                )
            )

        if topology["agent_count"] > 0:
            result.outputs["multi_agent_topology"] = topology

        return result

    def _analyze_management_endpoint(self, resp, path: str, service: Service) -> dict | None:
        """Analyze a management endpoint response for agent information."""
        body = resp.body or ""
        body_lower = body.lower()

        # Check for agent listings
        agent_names = []
        architecture = None

        if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    # List of agents
                    for item in data[:20]:
                        if isinstance(item, dict):
                            name = item.get("name") or item.get("agent_name") or item.get("id")
                            if name:
                                agent_names.append(str(name))
                        elif isinstance(item, str):
                            agent_names.append(item)
                elif isinstance(data, dict):
                    # Agent registry or graph structure
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

        # Keyword detection fallback
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
            "status_code": resp.status_code,
            "agent_names": agent_names,
            "architecture": architecture,
        }

    def _detect_delegation(self, body: str) -> list[str]:
        """Detect delegation patterns in response text."""
        body_lower = body.lower()
        return [p for p in DELEGATION_PATTERNS if p in body_lower]

    def _extract_agent_id(self, resp) -> str | None:
        """Extract agent identifier from response headers or body."""
        # Check headers
        for header in ["x-agent-id", "x-agent-name", "x-worker-id"]:
            val = resp.headers.get(header)
            if val:
                return val

        # Check JSON body for agent_name field
        body = resp.body or ""
        if "application/json" in resp.headers.get("content-type", ""):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    return data.get("agent_name") or data.get("agent_id")
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def _build_request_body(self, prompt: str, endpoint: dict) -> dict:
        """Build request body matching endpoint framework."""
        framework = endpoint.get("framework", "").lower()
        if framework in ("langserve", "langchain", "langgraph"):
            return {"input": prompt}
        path = endpoint.get("path", "").lower()
        if "chat" in path:
            return {"messages": [{"role": "user", "content": prompt}]}
        return {"input": prompt}

    def _infer_architecture(self, topology: dict) -> str:
        """Infer architecture from collected evidence."""
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
        """Build evidence string."""
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
