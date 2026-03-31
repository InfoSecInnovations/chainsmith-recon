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

References:
  https://python.langchain.com/docs/langserve
  https://langchain-ai.github.io/langgraph/
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Framework detection signatures
FRAMEWORK_SIGNATURES = {
    "langserve": {
        "headers": ["x-langserve-version", "x-langsmith-trace"],
        "paths": ["/invoke", "/stream", "/batch", "/input_schema", "/output_schema"],
        "body_patterns": ["langserve", "langchain", "input_schema", "output_schema", "configurable"],
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


class AgentDiscoveryCheck(ServiceIteratingCheck):
    """
    Discover AI agent orchestration endpoints and identify frameworks.
    
    Probes common agent paths and fingerprints responses to identify
    the underlying agent framework (LangChain, LangGraph, etc.).
    """

    name = "agent_discovery"
    description = "Detect AI agent orchestration endpoints and identify frameworks"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["agent_endpoints", "agent_frameworks"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    delay_between_targets = 0.2

    reason = "Agent endpoints expose autonomous AI systems that can execute multi-step tasks, access tools, and maintain state - high-value targets for goal injection and privilege escalation"
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = ["endpoint discovery", "framework fingerprinting", "API enumeration"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        agent_endpoints = []
        detected_frameworks = set()

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                for path in AGENT_PATHS:
                    url = service.with_path(path)

                    # Try GET first (schema endpoints, discovery)
                    get_resp = await client.get(url)
                    
                    endpoint_info = self._analyze_response(get_resp, path, "GET", service)
                    
                    if not endpoint_info:
                        # Try POST with minimal payload
                        post_resp = await client.post(
                            url,
                            json={"input": "test"},
                            headers={"Content-Type": "application/json"},
                        )
                        endpoint_info = self._analyze_response(post_resp, path, "POST", service)
                    
                    if endpoint_info:
                        agent_endpoints.append(endpoint_info)
                        
                        if endpoint_info.get("framework"):
                            detected_frameworks.add(endpoint_info["framework"])
                        
                        # Determine severity based on capabilities
                        severity = self._determine_severity(endpoint_info)
                        
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title=f"Agent endpoint: {path}",
                            description=self._build_description(endpoint_info),
                            severity=severity,
                            evidence=self._build_evidence(endpoint_info),
                            host=service.host,
                            discriminator=f"agent-{path.strip('/').replace('/', '-')}",
                            target=service,
                            target_url=url,
                            raw_data=endpoint_info,
                            references=self.references,
                        ))

                # Probe for additional capabilities if we found agent endpoints
                if agent_endpoints:
                    capabilities = await self._probe_capabilities(client, service, agent_endpoints)
                    if capabilities:
                        for endpoint in agent_endpoints:
                            endpoint["capabilities"] = capabilities

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if agent_endpoints:
            result.outputs["agent_endpoints"] = agent_endpoints
        if detected_frameworks:
            result.outputs["agent_frameworks"] = list(detected_frameworks)

        return result

    def _analyze_response(self, resp, path: str, method: str, service: Service) -> dict | None:
        """Analyze response for agent framework indicators."""
        if resp.error or resp.status_code in (404, 405, 502, 503):
            return None
        
        # Skip generic error pages
        if resp.status_code == 200 and len(resp.body) < 10:
            return None
        
        indicators = []
        framework = None
        framework_confidence = 0
        
        # Check headers for framework signatures
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        
        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            header_matches = sum(1 for h in sigs["headers"] if h in resp_headers_lower)
            if header_matches > 0:
                indicators.append(f"header:{fw_name}")
                if header_matches > framework_confidence:
                    framework = fw_name
                    framework_confidence = header_matches + 2  # Headers are strong signal
        
        # Check path patterns
        path_lower = path.lower()
        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            for sig_path in sigs["paths"]:
                if sig_path in path_lower:
                    indicators.append(f"path:{sig_path}")
                    if framework_confidence < 1:
                        framework = fw_name
                        framework_confidence = 1
        
        # Check body patterns
        body = resp.body or ""
        body_lower = body.lower()
        
        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            body_matches = sum(1 for p in sigs["body_patterns"] if p in body_lower)
            if body_matches > 0:
                indicators.append(f"body:{fw_name}({body_matches})")
                if body_matches > framework_confidence:
                    framework = fw_name
                    framework_confidence = body_matches
        
        # Check error patterns (often reveal framework)
        for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
            for pattern in sigs["error_patterns"]:
                if pattern in body:
                    indicators.append(f"error:{pattern}")
                    framework = fw_name
                    framework_confidence = max(framework_confidence, 3)
        
        # Check for JSON schema response (LangServe pattern)
        if resp.status_code == 200 and "application/json" in resp_headers_lower.get("content-type", ""):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # LangServe schema endpoints
                    if "properties" in data or "type" in data:
                        indicators.append("json-schema")
                    # State/thread endpoints
                    if "state" in data or "history" in data or "messages" in data:
                        indicators.append("stateful-agent")
                    # Tool listing
                    if "tools" in data:
                        indicators.append("tools-available")
            except json.JSONDecodeError:
                pass
        
        # Need at least one indicator to consider this an agent endpoint
        if not indicators:
            # Check for generic agent-like responses
            agent_keywords = ["agent", "assistant", "task", "execute", "invoke", "chain"]
            if any(kw in body_lower for kw in agent_keywords):
                indicators.append("agent-keywords")
            else:
                return None
        
        return {
            "url": service.with_path(path),
            "path": path,
            "method": method,
            "status_code": resp.status_code,
            "framework": framework,
            "framework_confidence": framework_confidence,
            "indicators": indicators,
            "auth_required": resp.status_code == 401,
            "service": service.to_dict(),
        }

    async def _probe_capabilities(
        self, client: AsyncHttpClient, service: Service, endpoints: list[dict]
    ) -> dict:
        """Probe for additional agent capabilities."""
        capabilities = {
            "memory": False,
            "tools": False,
            "streaming": False,
            "state": False,
            "threads": False,
        }
        
        # Check for memory endpoint
        for mem_path in ["/agent/memory", "/memory", "/history"]:
            url = service.with_path(mem_path)
            resp = await client.get(url)
            if resp.status_code not in (404, 405):
                capabilities["memory"] = True
                break
        
        # Check for tools endpoint
        for tools_path in ["/agent/tools", "/tools", "/input_schema"]:
            url = service.with_path(tools_path)
            resp = await client.get(url)
            if resp.status_code == 200:
                capabilities["tools"] = True
                break
        
        # Check for streaming support
        for endpoint in endpoints:
            if "stream" in endpoint.get("path", "").lower():
                capabilities["streaming"] = True
                break
        
        # Check for state/thread support (LangGraph)
        for state_path in ["/state", "/threads"]:
            url = service.with_path(state_path)
            resp = await client.get(url)
            if resp.status_code not in (404, 405):
                if "state" in state_path:
                    capabilities["state"] = True
                else:
                    capabilities["threads"] = True
        
        return capabilities

    def _determine_severity(self, endpoint_info: dict) -> str:
        """Determine finding severity based on endpoint characteristics."""
        # Unauthenticated access to agent is high severity
        if not endpoint_info.get("auth_required", True):
            # Execution endpoints are high
            exec_keywords = ["invoke", "run", "execute", "stream", "batch"]
            if any(kw in endpoint_info.get("path", "").lower() for kw in exec_keywords):
                return "high"
            # Schema/discovery endpoints are medium
            return "medium"
        
        # Authenticated endpoints are lower severity
        return "info"

    def _build_description(self, endpoint_info: dict) -> str:
        """Build human-readable description."""
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
        """Build evidence string."""
        lines = [
            f"Path: {endpoint_info['path']}",
            f"Method: {endpoint_info['method']}",
            f"Status: {endpoint_info['status_code']}",
        ]
        
        if endpoint_info.get("framework"):
            lines.append(f"Framework: {endpoint_info['framework']} (confidence: {endpoint_info.get('framework_confidence', 0)})")
        
        if endpoint_info.get("indicators"):
            lines.append(f"Indicators: {', '.join(endpoint_info['indicators'][:5])}")
        
        return "\n".join(lines)
