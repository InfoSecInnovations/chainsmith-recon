# Chainsmith Recon

**AI Reconnaissance Framework for Penetration Testers**

Chainsmith Recon is an open-source reconnaissance tool designed for security professionals to assess AI/ML systems, LLM-powered applications, and traditional web infrastructure. It provides automated discovery, fingerprinting, and vulnerability identification with a focus on emerging AI attack surfaces.

## How It Works: Stimulus-Response Checks

Every check in Chainsmith follows a **stimulus-response** pattern:

1. **Stimulus** — The check sends a probe to the target: an HTTP request, DNS query, TCP connection, crafted prompt, or API call.
2. **Response Analysis** — The check parses what comes back, comparing against signatures, indicators, and known patterns.
3. **Finding Generation** — If the response reveals something noteworthy, the check produces structured findings with severity, evidence, and references.

This pattern is enforced by the base framework. `BaseCheck` subclasses implement `run()` to probe and analyze. `ServiceIteratingCheck` subclasses implement `check_service()`, which is called once per discovered service matching the check's target types. Both base classes handle rate limiting, scope validation, timeouts, and error handling automatically.

For example, the jailbreak check sends crafted prompts (stimulus), looks for bypass indicators and block phrases in the response (analysis), then generates severity-rated findings. The banner grab check opens a TCP connection, optionally sends a protocol-specific probe, then matches the banner against known signatures.

## Features

- **102 Checks Across 7 Suites**: Network, Web, AI, MCP, Agent, RAG, and CAG reconnaissance
- **Stimulus-Response Architecture**: Every check probes, analyzes, and reports in a consistent pipeline
- **Swarm Mode**: Distribute scans across multiple agents for scale, coverage, and OPSEC
- **Scenario System**: Simulated target environments for training and testing without hitting real systems
- **Persistence**: Automatic scan history in SQLite (default) or PostgreSQL with trend analysis
- **Engagement Tracking**: Group related scans under named engagements for long-running assessments
- **Multiple Output Formats**: Text, JSON, YAML, Markdown, SARIF, HTML, and PDF
- **LLM Chain Analysis**: Automatic attack chain discovery using AI (optional, with graceful degradation)
- **Scan Profiles**: Built-in profiles (default, aggressive, stealth) and custom profile support
- **Proof of Scope**: Traffic logging and compliance reporting for engagements
- **Extensible Architecture**: Add custom checks by extending `BaseCheck` or `ServiceIteratingCheck`

## Setup

### From Source

```bash
git clone <repo-url>
cd chainsmith
pip install -e .
```

### Development Setup

```bash
pip install -e ".[dev]"
pytest tests/
```

## Quick Start

### Basic Scan

```bash
# Scan a target domain
chainsmith scan example.com

# Scan with specific suites
chainsmith scan example.com --suite network --suite web

# Scan with specific checks
chainsmith scan example.com -c dns_enumeration -c header_analysis

# Scan with exclusions
chainsmith scan example.com --exclude admin.example.com

# Show execution plan without running
chainsmith scan example.com --plan

# Dry run (validate config only)
chainsmith scan example.com --dry-run

# Output to file
chainsmith scan example.com -o report.json -f json

# Parallel execution
chainsmith scan example.com --parallel

# Link scan to an engagement
chainsmith scan example.com --engagement <engagement-id>
```

### Using Scenarios

Scenarios provide simulated target environments for training and testing.

```bash
# List available scenarios
chainsmith scenarios list

# View scenario details
chainsmith scenarios info fakobanko

# Scan with a scenario (simulated environment)
chainsmith scan fakobanko.local --scenario fakobanko
```

### List Checks and Suites

```bash
# List all checks
chainsmith list-checks

# List checks by suite
chainsmith list-checks --suite ai

# Show dependencies
chainsmith list-checks --deps

# List suites with check counts
chainsmith suites
```

### Export Findings

```bash
# Pipe JSON to export
chainsmith scan example.com -f json | chainsmith export -f md -o report.md

# Export from file
chainsmith export -i findings.json -f sarif -o findings.sarif
```

### Scan History

```bash
# List historical scans
chainsmith scans list

# Show scan details
chainsmith scans show <scan-id>

# Compare two scans
chainsmith scans compare <scan-a> <scan-b>

# View trend data
chainsmith scans trend --target example.com
```

### Engagements

```bash
# Create an engagement
chainsmith engagements create --name "Q1 Pentest" --target example.com

# List engagements
chainsmith engagements list

# Show engagement and its scans
chainsmith engagements show <engagement-id>

# View engagement trend
chainsmith engagements trend <engagement-id>
```

### Findings Management

```bash
# Accept a finding risk
chainsmith findings accept <fingerprint> --reason "Accepted risk"

# Mark as false positive
chainsmith findings false-positive <fingerprint> --reason "Not applicable"

# Reopen a finding
chainsmith findings reopen <fingerprint>

# List overrides
chainsmith findings overrides
```

### Reports

```bash
# Generate reports from historical scan data
chainsmith report technical <scan-id> -f md -o report.md
chainsmith report delta <scan-a> <scan-b> -f json
chainsmith report executive <scan-id> -f html -o exec.html
chainsmith report compliance <scan-id>
chainsmith report trend --target example.com
```

### Preferences and Profiles

```bash
# Show current preferences
chainsmith prefs show

# Set a preference
chainsmith prefs set network.timeout_seconds 60

# List profiles
chainsmith prefs profile list

# Activate a scan profile
chainsmith prefs profile activate aggressive

# Use a profile for a scan
chainsmith --profile stealth scan example.com
```

### Start Web UI / API Server

```bash
# Start the server
chainsmith serve

# Custom host/port
chainsmith serve --host 0.0.0.0 --port 8080

# Coordinator mode for swarm
chainsmith serve --coordinator
```

## Check Suites

### Network Suite (13 checks)

| Check | Description |
|-------|-------------|
| `dns_enumeration` | Enumerate subdomains via DNS resolution |
| `wildcard_dns` | Detect wildcard DNS records that cause false discoveries |
| `dns_records` | Extract MX, NS, TXT, CNAME, SOA, AAAA records |
| `geoip` | GeoIP and ASN lookups for infrastructure context |
| `reverse_dns` | PTR lookups to reveal services sharing IPs |
| `port_scan` | TCP port scanning to discover services |
| `tls_analysis` | Inspect TLS certificates and protocol support |
| `service_probe` | Probe services to determine type and gather fingerprints |
| `http_method_enum` | Probe with OPTIONS, TRACE, PUT, DELETE, PATCH |
| `banner_grab` | Raw TCP connect and version string parsing |
| `whois_lookup` | WHOIS and ASN lookups for infrastructure context |
| `traceroute` | TCP-based traceroute for CDN/WAF detection |
| `ipv6_discovery` | AAAA record resolution and firewall bypass detection |

### Web Suite (23 checks)

| Check | Description |
|-------|-------------|
| `header_analysis` | Analyze HTTP headers for security misconfigurations |
| `robots_txt` | Parse robots.txt for sensitive paths |
| `path_probe` | Check for admin panels, config files, sensitive endpoints |
| `cors_check` | Test for CORS misconfigurations |
| `openapi_discovery` | Find exposed API documentation |
| `webdav_check` | Probe for WebDAV file upload/listing |
| `vcs_exposure` | Detect exposed .git/.svn/.hg repositories |
| `config_exposure` | Parse accessible config files for secrets |
| `directory_listing` | Check for enabled autoindex |
| `default_creds` | Test admin panels for default credentials |
| `debug_endpoints` | Analyze exposed debug/actuator/status endpoints |
| `cookie_security` | Check for missing Secure, HttpOnly, SameSite |
| `auth_detection` | Detect authentication mechanisms |
| `waf_detection` | Identify WAF/CDN presence |
| `sitemap` | Parse sitemap.xml for undiscovered paths |
| `redirect_chain` | Follow redirect chains, detect open redirects |
| `error_page_fingerprinting` | Trigger errors to identify technology stack |
| `ssrf_indicator` | Identify endpoints accepting URL parameters |
| `favicon_fingerprinting` | Match favicon hash against known frameworks |
| `http2_detection` | Check HTTP/2 and HTTP/3 support |
| `hsts_preload` | Check HSTS preload list membership |
| `sri_check` | Check external resources for Subresource Integrity |
| `mass_assignment` | Test REST APIs for mass assignment vulnerabilities |

### AI Suite (28 checks)

| Check | Description |
|-------|-------------|
| `llm_endpoint_discovery` | Find chat and completion endpoints |
| `embedding_endpoint_discovery` | Find embedding and vector endpoints |
| `model_info_check` | Discover model information disclosure |
| `ai_framework_fingerprint` | Identify AI framework (vLLM, Ollama, etc.) |
| `ai_error_leakage` | Test for information leakage in errors |
| `content_filter_check` | Detect content filtering systems |
| `prompt_leakage` | Test for system prompt extraction |
| `rate_limit_check` | Probe rate limiting behavior |
| `tool_discovery` | Discover available tools/functions |
| `context_window_check` | Probe context window limits |
| `jailbreak_testing` | Test jailbreak techniques against content filters |
| `multi_turn_injection` | Multi-turn prompt extraction via trust-building |
| `input_format_injection` | Test formatting markers overriding instructions |
| `model_enumeration` | Enumerate available models |
| `token_cost_exhaustion` | Test for unbounded expensive completions |
| `system_prompt_injection` | Test client-supplied system message overrides |
| `output_format_manipulation` | Coerce crafted structured output |
| `api_parameter_injection` | Test acceptance of extra API parameters |
| `embedding_extraction` | Analyze embedding endpoints for metadata leakage |
| `streaming_analysis` | Test if streaming bypasses content filters |
| `auth_bypass` | Test AI endpoints with various auth states |
| `model_behavior_fingerprint` | Identify underlying model from response patterns |
| `conversation_history_leak` | Test for cross-user conversation leakage |
| `function_calling_abuse` | Test tools for parameter injection and escalation |
| `guardrail_consistency` | Test filter consistency across languages/encodings |
| `training_data_extraction` | Probe for memorized training data |
| `adversarial_input` | Test with unicode homoglyphs, zero-width chars |
| `response_caching` | Detect response caching via timing and content |

### MCP Suite (18 checks)

| Check | Description |
|-------|-------------|
| `mcp_discovery` | Discover Model Context Protocol server endpoints |
| `mcp_tool_enumeration` | Enumerate tools and assess risk levels |
| `mcp_auth_check` | Check authentication and authorization enforcement |
| `mcp_websocket_transport` | Discover MCP over WebSocket transport |
| `mcp_tool_chain_analysis` | Analyze tools for dangerous capability combinations |
| `mcp_shadow_tool_detection` | Detect shadow tool attack susceptibility |
| `mcp_schema_leakage` | Analyze tool schemas for information leakage |
| `mcp_server_fingerprint` | Identify MCP server implementation/version |
| `mcp_transport_security` | Analyze transport layer security |
| `mcp_notification_injection` | Test for unsolicited notification acceptance |
| `mcp_tool_invocation` | Probe tools with safe test payloads |
| `mcp_resource_traversal` | Test for path traversal and SSRF via resources |
| `mcp_template_injection` | Test resource templates for injection |
| `mcp_prompt_injection` | Test prompt injection via tool results |
| `mcp_sampling_abuse` | Test sampling endpoint for proxy/filter bypass |
| `mcp_protocol_version` | Test for protocol version downgrade |
| `mcp_tool_rate_limit` | Test tool invocation rate limiting |
| `mcp_undeclared_capabilities` | Probe for undeclared MCP capabilities |

### Agent Suite (17 checks)

| Check | Description |
|-------|-------------|
| `agent_discovery` | Detect agent orchestration endpoints and frameworks |
| `agent_goal_injection` | Test for goal hijacking attacks |
| `agent_multi_agent_detection` | Detect multi-agent architectures |
| `agent_framework_version` | Fingerprint framework versions for known CVEs |
| `agent_memory_extraction` | Probe memory endpoints for extractable content |
| `agent_tool_abuse` | Manipulate agents into unintended tool invocations |
| `agent_privilege_escalation` | Test for tool use with elevated permissions |
| `agent_loop_detection` | Detect runaway/infinite loop vulnerabilities |
| `agent_callback_injection` | Test callback URLs for SSRF/exfiltration |
| `agent_streaming_injection` | Prompt injection on streaming endpoints |
| `agent_framework_exploits` | Test framework-specific CVEs |
| `agent_memory_poisoning` | Test persistent memory poisoning across sessions |
| `agent_context_overflow` | Test guardrails after context window overflow |
| `agent_reflection_abuse` | Test injection bypass of self-reflection steps |
| `agent_state_manipulation` | Directly modify agent state via PUT/PATCH |
| `agent_trust_chain` | Exploit trust chain hierarchies in multi-agent systems |
| `agent_cross_injection` | Test cross-agent prompt injection |

### RAG Suite (2 checks)

| Check | Description |
|-------|-------------|
| `rag_discovery` | Detect RAG endpoints and vector store backends |
| `rag_indirect_injection` | Test for indirect prompt injection vulnerabilities |

### CAG Suite (2 checks)

| Check | Description |
|-------|-------------|
| `cag_discovery` | Detect CAG endpoints and cache infrastructure |
| `cag_cache_probe` | Probe for cache poisoning, cross-user leakage, stale context |

## Configuration

### Configuration File

Create `chainsmith.yaml` in your working directory:

```yaml
target_domain: example.com

scope:
  in_scope_domains:
    - example.com
    - "*.example.com"
  out_of_scope_domains:
    - vpn.example.com
  in_scope_ports: [80, 443, 8080, 8443]
  port_profile: lab  # web, ai, full, lab

litellm:
  base_url: http://localhost:4000/v1
  model_scout: nova-mini
  model_verifier: nova-mini
  model_chainsmith: nova-pro
  model_chainsmith_fallback: nova-mini

storage:
  backend: sqlite              # sqlite or postgresql
  db_path: ./data/chainsmith.db
  auto_persist: true
  retention_days: 365

swarm:
  enabled: false
  max_agents: 50
```

### Environment Variables

```bash
# LLM Provider (auto-detected from API keys if not set)
export CHAINSMITH_LLM_PROVIDER=openai  # openai, anthropic, litellm, none

# OpenAI
export OPENAI_API_KEY=sk-...

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# LiteLLM (role-based model names)
export LITELLM_BASE_URL=http://localhost:4000/v1
export LITELLM_MODEL_SCOUT=nova-mini
export LITELLM_MODEL_VERIFIER=nova-mini
export LITELLM_MODEL_CHAINSMITH=nova-pro

# LLM Settings
export CHAINSMITH_LLM_TEMPERATURE=0.3
export CHAINSMITH_LLM_MAX_TOKENS=2000

# Storage
export CHAINSMITH_STORAGE_BACKEND=sqlite
export CHAINSMITH_SQLITE_PATH=./data/chainsmith.db

# Config file path (default: ./chainsmith.yaml)
export CHAINSMITH_CONFIG=/path/to/config.yaml
```

Configuration is loaded in layers: hardcoded defaults, then YAML file overrides, then environment variable overrides.

## Scenario System

Scenarios provide simulated target environments for training and testing without affecting real systems.

### Included Scenarios

- **fakobanko** — AI-powered banking platform with LLM chatbot, credit scoring API, MCP tools, RAG knowledge base, and semantic caching. Covers all 7 check suites.

### Creating a Scenario

Create a directory under `scenarios/` with a `scenario.json`:

```json
{
  "name": "my-scenario",
  "version": "1.0.0",
  "description": "My custom training scenario",
  "target": {
    "pattern": "*.mycompany.local",
    "known_hosts": ["api", "chat", "mcp"]
  },
  "services": {
    "api": { "port": 8080, "type": "api", "description": "REST API" },
    "chat": { "port": 8081, "type": "ai", "description": "LLM chatbot" }
  },
  "findings": {
    "certain": ["header_vllm_version"],
    "random_pool": ["cors_misconfigured", "prompt_leaked"],
    "random_count": { "min": 2, "max": 5 }
  },
  "expected_findings": [
    "header_analysis-www.mycompany.local-missing-security-headers"
  ]
}
```

### Scenario Directory Structure

```
scenarios/
└── my-scenario/
    ├── scenario.json          # Scenario definition
    ├── simulations/           # Simulated check responses
    ├── services/              # Service implementations
    ├── data/                  # Session and runtime data
    └── docker-compose.yml     # Optional containerized services
```

## API Reference

Chainsmith provides a REST API when running in server mode (`chainsmith serve`).

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scope` | Set scan scope |
| `GET` | `/api/v1/scope` | Get current scope |
| `POST` | `/api/v1/scan` | Start a scan |
| `GET` | `/api/v1/scan` | Get current scan status |
| `GET` | `/api/v1/scan/checks` | Get check execution plan |
| `GET` | `/api/v1/scan/log` | Get scan execution log |
| `GET` | `/api/v1/findings` | Get findings |
| `GET` | `/api/v1/findings/by-host` | Get findings grouped by host |
| `POST` | `/api/v1/reset` | Reset state |
| `GET` | `/api/v1/checks` | List available checks |
| `GET` | `/api/v1/capabilities` | Get server capabilities |

### History and Comparison

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/scans` | List historical scans |
| `GET` | `/api/v1/scans/{id}` | Get scan details |
| `GET` | `/api/v1/scans/{id}/findings` | Get scan findings |
| `GET` | `/api/v1/scans/{id}/chains` | Get scan attack chains |
| `GET` | `/api/v1/scans/{a}/compare/{b}` | Compare two scans |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan |
| `GET` | `/api/v1/targets/{domain}/trend` | Trend data for a target |

### Engagements

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/engagements` | List engagements |
| `POST` | `/api/v1/engagements` | Create engagement |
| `GET` | `/api/v1/engagements/{id}` | Get engagement details |
| `PUT` | `/api/v1/engagements/{id}` | Update engagement |
| `DELETE` | `/api/v1/engagements/{id}` | Delete engagement |
| `GET` | `/api/v1/engagements/{id}/scans` | Get engagement scans |
| `GET` | `/api/v1/engagements/{id}/trend` | Engagement trend data |

### Chains, Compliance, Reports

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/chains/analyze` | Trigger chain analysis |
| `GET` | `/api/v1/chains` | Get detected chains |
| `GET` | `/api/v1/compliance/traffic` | Get traffic log |
| `GET` | `/api/v1/compliance/violations` | Get scope violations |
| `POST` | `/api/v1/compliance/report` | Generate compliance report |
| `POST` | `/api/v1/reports/technical` | Generate technical report |
| `POST` | `/api/v1/reports/delta` | Generate delta report |
| `POST` | `/api/v1/reports/executive` | Generate executive report |
| `POST` | `/api/v1/reports/trend` | Generate trend report |
| `POST` | `/api/v1/export` | Export findings |

### Preferences and Profiles

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/preferences` | Get preferences |
| `PUT` | `/api/v1/preferences` | Update preferences |
| `GET` | `/api/v1/profiles` | List profiles |
| `POST` | `/api/v1/profiles` | Create profile |
| `PUT` | `/api/v1/profiles/{name}/activate` | Activate profile |

### Scenarios

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/scenarios` | List scenarios |
| `POST` | `/api/v1/scenarios/load` | Load a scenario |
| `POST` | `/api/v1/scenarios/clear` | Clear loaded scenario |
| `GET` | `/api/v1/scenarios/current` | Get current scenario |

### Swarm

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/swarm/status` | Coordinator status |
| `GET` | `/api/swarm/agents` | List connected agents |
| `POST` | `/api/swarm/register` | Register an agent |
| `POST` | `/api/swarm/keys` | Generate API key |
| `GET` | `/api/swarm/keys` | List API keys |

### Example

```bash
# Set scope
curl -X POST http://localhost:8000/api/v1/scope \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "exclude": []}'

# Start scan
curl -X POST http://localhost:8000/api/v1/scan

# Get findings
curl http://localhost:8000/api/v1/findings
```

## Swarm Mode

Distribute scan execution across multiple machines for scale, network coverage, or OPSEC. The coordinator breaks scans into tasks and assigns them to remote agents.

```bash
# 1. Generate a key (on coordinator host)
chainsmith swarm generate-key --name "agent-01"

# 2. Start coordinator
chainsmith serve --coordinator --host 0.0.0.0

# 3. Start agent (on another host)
chainsmith swarm agent --coordinator http://coordinator:8000 --key <key>

# 4. Scan as usual -- the coordinator distributes work automatically
chainsmith scan example.com --server coordinator:8000
```

See [docs/swarm-usage.md](docs/swarm-usage.md) for the full guide and
[docs/swarm-architecture.md](docs/swarm-architecture.md) for design details.

## Adding a New Check

1. Create a new file in `app/checks/<suite>/`
2. Extend `BaseCheck` (general) or `ServiceIteratingCheck` (per-service)
3. Define `name`, `description`, `conditions`, `produces`
4. Implement `run()` or `check_service()` — following the stimulus-response pattern
5. Register in `app/checks/<suite>/__init__.py`
6. Add tests in `tests/checks/`

Example:

```python
from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service

class MyCustomCheck(ServiceIteratingCheck):
    name = "my_custom_check"
    description = "Check for something interesting"
    conditions = [CheckCondition("services", "truthy")]
    produces = ["my_output"]
    service_types = ["http", "api"]

    async def check_service(self, service: Service, context: dict) -> CheckResult:
        result = CheckResult(success=True)
        # 1. Stimulus: send a probe
        # 2. Response: analyze what comes back
        # 3. Findings: generate findings if warranted
        return result
```

## Development

### Running Tests

```bash
# All tests
pytest tests/

# With coverage
pytest tests/ --cov=app --cov-report=html

# Specific suite
pytest tests/checks/test_ai.py -v
```

### Code Quality

```bash
# Lint
ruff check app/ tests/

# Format
ruff format app/ tests/

# Type check
mypy app/
```

## Security Considerations

Chainsmith Recon is designed for authorized security testing. Always:

- Obtain written authorization before scanning
- Respect scope boundaries and exclusions
- Use proof-of-scope features for compliance documentation
- Never use against systems you don't have permission to test

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- OWASP for security testing methodologies
- MITRE ATT&CK and ATLAS frameworks
- The security research community
