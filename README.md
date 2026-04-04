# Chainsmith Recon

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/infosecinnovations/chainsmith-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/infosecinnovations/chainsmith-recon/actions/workflows/ci.yml)

**Recon for the AI era**

Chainsmith Recon is an open-source reconnaissance framework for security professionals assessing AI/ML systems, LLM-powered applications, and traditional web infrastructure. It provides automated discovery, fingerprinting, and vulnerability identification across emerging AI attack surfaces — with 133 checks spanning network, web, AI, MCP, agent, RAG, and CAG domains.

## How It Works

Every check follows a **stimulus-response** pattern:

1. **Stimulus** — Send a probe: HTTP request, DNS query, crafted prompt, API call, etc.
2. **Response Analysis** — Parse what comes back against signatures, indicators, and known patterns.
3. **Finding Generation** — Produce structured findings with severity, evidence, and references.

The base framework enforces this pattern. `BaseCheck` subclasses implement `run()` for general probes. `ServiceIteratingCheck` subclasses implement `check_service()`, called once per discovered service matching the check's target types. Both base classes handle rate limiting, scope validation, timeouts, and error handling automatically.

## Features

- **133 Checks Across 7 Suites** — Network, Web, AI, MCP, Agent, RAG, and CAG
- **Browser UI** — Web dashboard at `http://localhost:8100` for scan management and visualization
- **CLI** — Full-featured command-line interface for scripting and automation
- **REST API** — Programmatic access when running in server mode
- **Scenario System** — Simulated target environments for training and testing without hitting real systems
- **Swarm Mode** — Distribute scans across multiple agents for scale, coverage, and OPSEC
- **Persistence** — Automatic scan history in SQLite with trend analysis and engagement tracking
- **Multiple Output Formats** — Text, JSON, YAML, Markdown, SARIF, HTML, and PDF
- **LLM Chain Analysis** — Automatic attack chain discovery using AI (optional, with graceful degradation)
- **Scan Profiles** — Built-in profiles (default, aggressive, stealth) and custom profile support
- **Proof of Scope** — Traffic logging and compliance reporting for engagements

## Quick Start

### Prerequisites

- Docker + Docker Compose v2
- An API key for your chosen LLM provider (not needed for Ollama)

### 1. Configure

```bash
cp .env.example .env
```

Edit `.env` — set `LLM_PROFILE` and the matching API key:

| Profile      | Required variable      |
|-------------|------------------------|
| `openai`    | `OPENAI_API_KEY`       |
| `anthropic` | `ANTHROPIC_API_KEY`    |
| `ollama`    | *(none)*               |
| `litellm`   | `LITELLM_BASE_URL`    |

### 2. Launch

```bash
./chainsmith.sh start --profile openai
```

### 3. Use

**Browser UI** — http://localhost:8100

**CLI** (optional, for local command-line access):

> **Tip:** Use a virtual environment (`python -m venv .venv`, conda, etc.)
> to avoid polluting your system Python.

```bash
pip install -r requirements.txt
pip install -e .                 # installs the `chainsmith` CLI
chainsmith --server 127.0.0.1:8100 scan <target>
```

### Management Commands

```
./chainsmith.sh stop        # stop (keeps data)
./chainsmith.sh logs        # tail logs
./chainsmith.sh status      # container states
./chainsmith.sh teardown    # remove everything
```

## Check Suites

| Suite | Checks | Focus |
|-------|--------|-------|
| **Network** | 13 | DNS, port scanning, TLS, banner grabbing, traceroute, WHOIS |
| **Web** | 23 | Headers, CORS, auth, WAF, exposed configs, default creds, open redirects |
| **AI** | 27 | LLM endpoint discovery, prompt injection, jailbreaks, model enumeration, guardrail testing |
| **MCP** | 19 | MCP server discovery, tool enumeration, shadow tools, schema leakage, transport security |
| **Agent** | 17 | Agent discovery, goal injection, memory extraction, privilege escalation, cross-agent injection |
| **RAG** | 17 | RAG endpoint discovery, indirect injection, corpus poisoning, document exfiltration |
| **CAG** | 17 | Cache discovery, cache poisoning, cross-user leakage, side-channel, stale context |

Run `chainsmith list-checks` or `chainsmith list-checks --suite <name>` to see individual checks and descriptions.

## Scenarios

Scenarios provide simulated target environments for training and testing without affecting real systems.

### Included Scenarios

- **fakobanko** — AI-powered banking platform with LLM chatbot, credit scoring API, MCP tools, RAG knowledge base, and semantic caching. Covers all 7 check suites.
- **demo-domain** — Lightweight demo scenario for quick walkthroughs.

```bash
# List available scenarios
chainsmith scenarios list

# Scan with a scenario
chainsmith scan fakobanko.local --scenario fakobanko
```

See [docs/scenarios](docs/scenarios) for creating custom scenarios.

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

storage:
  backend: sqlite
  db_path: ./data/chainsmith.db
  auto_persist: true
  retention_days: 365

swarm:
  enabled: false
  max_agents: 50
```

Configuration is loaded in layers: hardcoded defaults, then YAML file overrides, then environment variable overrides.

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

## Documentation

- [QUICKSTART.md](QUICKSTART.md) — Fastest path to a running instance
- [docs/](docs/) — Full documentation: CLI reference, API endpoints, check details, scenarios, swarm, persistence
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup, adding checks, code quality, testing
- [CHANGELOG.md](CHANGELOG.md) — Release history
- [SECURITY.md](SECURITY.md) — Security policy

## Security Considerations

Chainsmith Recon is designed for authorized security testing. Always:

- Obtain written authorization before scanning
- Respect scope boundaries and exclusions
- Use proof-of-scope features for compliance documentation
- Never use against systems you don't have permission to test

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Acknowledgments

- OWASP for security testing methodologies
- MITRE ATT&CK and ATLAS frameworks
- The security research community
