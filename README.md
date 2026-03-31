# Chainsmith Recon

**AI Reconnaissance Framework for Penetration Testers**

Chainsmith Recon is an open-source reconnaissance tool designed for security professionals to assess AI/ML systems, LLM-powered applications, and traditional web infrastructure. It provides automated discovery, fingerprinting, and vulnerability identification with a focus on emerging AI attack surfaces.

## Features

- **Multi-Suite Scanning**: Network, Web, and AI-specific reconnaissance checks
- **Swarm Mode**: Distribute scans across multiple agents for scale, coverage, and OPSEC
- **Scenario System**: Simulated environments for training and testing
- **Multiple Output Formats**: Text, JSON, Markdown, and SARIF for CI/CD integration
- **LLM Chain Analysis**: Automatic attack chain discovery using AI (optional)
- **Proof of Scope**: Traffic logging and compliance reporting for engagements
- **Extensible Architecture**: Easy to add custom checks and scenarios

## Installation

### From PyPI (Recommended)

```bash
pip install chainsmith-recon
```

### From Source

```bash
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
pip install -e .
```

### Using Docker

```bash
docker pull infosecinnovations/chainsmith-recon:latest
docker run -it infosecinnovations/chainsmith-recon scan example.com
```

### Development Setup

```bash
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
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

# Scan with exclusions
chainsmith scan example.com --exclude admin.example.com --exclude vpn.example.com

# Output to file
chainsmith scan example.com -o report.json -f json
```

### List Available Checks

```bash
# List all checks
chainsmith list-checks

# List checks by suite
chainsmith list-checks --suite ai

# Detailed view
chainsmith list-checks --verbose
```

### Using Scenarios

```bash
# List available scenarios
chainsmith scenarios list

# View scenario details
chainsmith scenarios info fakobanko

# Scan with a scenario (simulated environment)
chainsmith scan fakobanko.local --scenario fakobanko
```

### Export Findings

```bash
# Convert JSON to Markdown report
chainsmith scan example.com -f json | chainsmith export -f md -o report.md

# Export to SARIF for CI/CD
chainsmith scan example.com -f json | chainsmith export -f sarif -o findings.sarif
```

### Start Web UI

```bash
# Start the web interface
chainsmith serve

# Custom host/port
chainsmith serve --host 0.0.0.0 --port 8080
```

## Check Suites

### Network Suite

| Check | Description |
|-------|-------------|
| `dns_enumeration` | Enumerate subdomains via DNS resolution |
| `service_probe` | Probe services to determine type and gather fingerprints |

### Web Suite

| Check | Description |
|-------|-------------|
| `header_analysis` | Analyze HTTP headers for security issues |
| `robots_txt` | Parse robots.txt for sensitive paths |
| `path_probe` | Check for common admin panels and sensitive endpoints |
| `openapi_discovery` | Find exposed API documentation |
| `cors_check` | Test for CORS misconfigurations |

### AI Suite

| Check | Description |
|-------|-------------|
| `llm_endpoint_discovery` | Find chat and completion endpoints |
| `embedding_endpoint_discovery` | Find embedding and vector endpoints |
| `model_info_check` | Discover model information disclosure |
| `ai_framework_fingerprint` | Identify AI framework (vLLM, Ollama, etc.) |
| `ai_error_leakage` | Test for information leakage in errors |
| `tool_discovery` | Discover available tools/functions |
| `prompt_leakage` | Test for system prompt extraction |
| `rate_limit_check` | Probe rate limiting behavior |
| `content_filter_check` | Detect content filtering systems |
| `context_window_check` | Probe context window limits |

## Configuration

### Environment Variables

```bash
# LLM Provider (auto-detected if not set)
export CHAINSMITH_LLM_PROVIDER=openai  # openai, anthropic, litellm, none

# OpenAI
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4o

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-sonnet-4-20250514

# LiteLLM (for SEC536 labs)
export LITELLM_BASE_URL=http://localhost:4000/v1
export LITELLM_MODEL_CHAINSMITH=nova-pro

# LLM Settings
export CHAINSMITH_LLM_TEMPERATURE=0.3
export CHAINSMITH_LLM_MAX_TOKENS=2000
```

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

litellm:
  base_url: http://localhost:4000/v1
  model_chainsmith: nova-pro
  model_chainsmith_fallback: nova-mini
```

## CLI Reference

### `chainsmith scan`

```
Usage: chainsmith scan [OPTIONS] TARGET

  Run reconnaissance scan against a target.

Options:
  -e, --exclude TEXT              Exclude domains from scope (repeatable)
  -c, --checks TEXT               Run specific checks by name (repeatable)
  -s, --suite TEXT                Run checks from suite (repeatable)
  --scenario TEXT                 Load a scenario for simulated scanning
  --parallel                      Run checks in parallel
  -o, --output PATH               Output file path
  -f, --format [json|md|sarif|text]
                                  Output format (default: text)
  -v, --verbose                   Verbose output
  -q, --quiet                     Quiet mode (only findings)
  --no-llm                        Disable LLM-based chain analysis
  --provider [openai|anthropic|litellm|none]
                                  LLM provider override
  --help                          Show this message and exit.
```

### `chainsmith list-checks`

```
Usage: chainsmith list-checks [OPTIONS]

  List available checks.

Options:
  -s, --suite TEXT  Filter by suite (network, web, ai)
  --json            Output as JSON
  -v, --verbose     Show detailed info
  --help            Show this message and exit.
```

### `chainsmith scenarios`

```
Usage: chainsmith scenarios [OPTIONS] COMMAND [ARGS]...

  Manage scenarios for simulated scans.

Commands:
  list  List available scenarios
  info  Show details about a scenario
```

### `chainsmith export`

```
Usage: chainsmith export [OPTIONS]

  Export findings to various formats.

Options:
  -f, --format [json|md|sarif]  Output format (default: json)
  -o, --output PATH             Output file path
  -i, --input PATH              Input JSON findings file
  --help                        Show this message and exit.
```

### `chainsmith serve`

```
Usage: chainsmith serve [OPTIONS]

  Start the web UI server.

Options:
  --host TEXT       Host to bind to (default: 127.0.0.1)
  -p, --port INT    Port to bind to (default: 8000)
  --coordinator     Enable swarm coordinator mode
  --reload          Enable auto-reload for development
  --help            Show this message and exit.
```

### `chainsmith swarm`

```
Usage: chainsmith swarm [OPTIONS] COMMAND [ARGS]...

  Swarm distributed scanning commands.

Commands:
  generate-key  Generate a new swarm API key
  list-keys     List all swarm API keys
  revoke-key    Revoke a swarm API key by ID
  agent         Start a swarm agent that connects to a coordinator
  status        Show coordinator swarm status
```

## Scenario System

Scenarios provide simulated target environments for training and testing without affecting real systems.

### Creating a Scenario

Create a directory with `scenario.json`:

```json
{
  "name": "my-scenario",
  "version": "1.0.0",
  "description": "My custom training scenario",
  "target": {
    "pattern": "*.mycompany.local",
    "known_hosts": ["api.mycompany.local", "chat.mycompany.local"],
    "ports": [80, 443, 8080]
  },
  "simulations": [
    "network/dns_success.yaml",
    "web/headers_missing_csp.yaml",
    "ai/llm_endpoint_found.yaml"
  ],
  "expected_findings": [
    {"check": "header_analysis", "severity": "low"},
    {"check": "llm_endpoint_discovery", "severity": "info"}
  ]
}
```

### Scenario Directory Structure

```
scenarios/
└── my-scenario/
    ├── scenario.json
    └── services/
        ├── api.py
        └── chat.py
```

## Output Formats

### Text (Default)

Human-readable terminal output with colored severity badges.

### JSON

```json
[
  {
    "id": "F-001",
    "title": "Missing security headers",
    "severity": "low",
    "check_name": "header_analysis",
    "target_url": "https://example.com",
    "evidence": "Headers not present: content-security-policy"
  }
]
```

### Markdown

Generates a formatted report with findings grouped by severity.

### SARIF

Standard format for static analysis tools, compatible with GitHub Code Scanning and other CI/CD platforms.

## API Reference

Chainsmith also provides a REST API when running in server mode.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scope` | Set scan scope |
| `POST` | `/api/v1/scan/start` | Start a scan |
| `GET` | `/api/v1/scan/status` | Get scan status |
| `GET` | `/api/v1/findings` | Get findings |
| `POST` | `/api/v1/reset` | Reset state |
| `GET` | `/api/swarm/status` | Swarm coordinator status |

### Example

```bash
# Set scope
curl -X POST http://localhost:8000/api/v1/scope \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "exclude": []}'

# Start scan
curl -X POST http://localhost:8000/api/v1/scan/start

# Get findings
curl http://localhost:8000/api/v1/findings
```

## Swarm Mode

Distribute scan execution across multiple machines for scale, network
coverage, or OPSEC. The coordinator breaks scans into tasks and assigns
them to remote agents.

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

### Adding a New Check

1. Create a new file in `app/checks/<suite>/`
2. Extend `BaseCheck` or `ServiceIteratingCheck`
3. Define `name`, `description`, `conditions`, `produces`
4. Implement `run()` or `check_service()` method
5. Register in `app/checks/<suite>/__init__.py`
6. Add tests in `tests/checks/`

Example:

```python
from app.checks.base import ServiceIteratingCheck, CheckResult, Service

class MyCustomCheck(ServiceIteratingCheck):
    name = "my_custom_check"
    description = "Check for something interesting"
    conditions = [CheckCondition("services", "truthy")]
    produces = ["my_output"]
    service_types = ["http", "api"]
    
    async def check_service(self, service: Service, context: dict) -> CheckResult:
        result = CheckResult(success=True)
        # Your check logic here
        return result
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
