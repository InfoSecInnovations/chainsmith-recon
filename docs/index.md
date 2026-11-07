# Chainsmith Recon

**AI Reconnaissance Framework for Penetration Testers**

Chainsmith Recon is an open-source reconnaissance tool designed to discover, enumerate, and assess AI/ML systems. Built for SEC536 and real-world penetration testing.

## Features

- **7 Check Suites**: Network, Web, AI, MCP, Agent, RAG, CAG
- **133 Automated Checks**: From DNS enumeration to prompt injection testing
- **Probe / Grade Split**: Every check records what it saw, then grades it — with optional evidence capture for later review and re-grading
- **Chain Orchestration**: Dependency-aware execution ordering
- **Scan Presets**: `quick`, `thorough`, `passive`, `ai-focused`
- **Workspaces**: One directory per body of work for its database, evidence, logs, and reports
- **Concurrent Scans**: Run several scans at once, with live progress streamed to the UI
- **Swarm Mode**: Distributed scanning across multiple agents
- **Scenario System**: Simulated environments for training
- **Payload Library**: 50 injection payloads across 9 categories
- **Multiple Output Formats**: JSON, YAML, Markdown, SARIF, CSV, plus HTML and PDF reports

## Quick Start

Chainsmith runs as a server (Docker recommended) that you drive from the browser
UI or the `chainsmith` CLI. See [QUICKSTART.md](../QUICKSTART.md) to get it
running, then:

```bash
# Install the CLI from your checkout
pip install -e .

# Scan a target (the Docker stack listens on 8100)
chainsmith --server 127.0.0.1:8100 scan example.com

# View execution plan
chainsmith --server 127.0.0.1:8100 scan example.com --plan

# Run specific suites
chainsmith --server 127.0.0.1:8100 scan example.com --suite ai --suite mcp

# Export observations
chainsmith --server 127.0.0.1:8100 scan example.com -o report.yaml -f yaml
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Chain Orchestrator                   │
│  network → web → ai → mcp → agent → rag → cag           │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                    Check Suites                         │
├────────┬────────┬────────┬────────┬────────┬──────┬─────┤
│network │  web   │   ai   │  mcp   │ agent  │ rag  │ cag │
│  (13)  │  (23)  │  (28)  │  (18)  │  (17)  │ (17) │(17) │
└────────┴────────┴────────┴────────┴────────┴──────┴─────┘
         │  probe → candidate → grade
         ▼
┌─────────────────────────────────────────────────────────┐
│                     Observations                        │
│  severity: critical | high | medium | low | info        │
└─────────────────────────────────────────────────────────┘
```

## Suites Overview

| Suite | Checks | Purpose |
|-------|--------|---------|
| **network** | 13 | DNS enumeration, service discovery, port scanning, TLS, WHOIS |
| **web** | 23 | Headers, robots.txt, CORS, OpenAPI, auth detection, exposed configs |
| **ai** | 28 | LLM endpoints, prompts, filters, jailbreaks, auth bypass, guardrails |
| **mcp** | 18 | MCP server/tool enumeration, permission testing, schema analysis |
| **agent** | 17 | Agent discovery, goal injection, memory extraction, privilege escalation |
| **rag** | 17 | RAG endpoints, indirect injection, corpus poisoning, document exfiltration |
| **cag** | 17 | Cache discovery, cross-user leakage, cache poisoning, side channels |

## Documentation

### Using Chainsmith

- [Installation Guide](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Configuration](getting-started/configuration.md)
- [CLI Reference](cli/overview.md)
- [Operating Modes](OPERATING_MODES.md) — Normal, scenario, and swarm modes
- [Check Reference](checks/overview.md)
- [Payload Library](payloads/overview.md)
- [Scenario System](scenarios/overview.md)
- [Working with Saved Scans](working-with-saved-scans.md) — Browse, compare, report on, and delete historical scans
- [Swarm Mode](swarm-usage.md) — Distributed scanning with remote agents
- [Vocabulary](vocabulary.md) — Core terms

### How It Works

- [How Chainsmith Works](how-chainsmith-works.md) — A scan, end to end
- [Pipeline & Component Reference](pipeline.md) — Agents, gates, advisors, event system, and configuration
- [Component Taxonomy](component-taxonomy.md) — Agents vs. gates vs. advisors
- [Swarm Architecture](swarm-architecture.md) — Design decisions and internals
- [Performance Tuning](performance-tuning.md)

### For Contributors

- [CONTRIBUTING.md](../CONTRIBUTING.md) — Development setup, adding checks, testing
- [Developer Vocabulary](vocabulary-dev.md)
- [Launching from VS Code](getting-started/launching-from-vscode.md)
- [Adjudicator Strategies Reference](adjudicator-strategies-reference.md) — Archived design notes
- [Roadmap and Design Notes](future-ideas/README.md) — Planned work, open issues, and completed design records

### Design Proposals (not yet implemented)

These documents describe planned work. Except where they say otherwise, nothing in them ships today.

- [Authentication & Authorization](authentication-authorization.md) — Only swarm agent API keys exist today; the server and UI are unauthenticated
- [Data Protection & Secrets](plan-data-protection-secrets.md)
- [Instance Auth & NIST CUI](plan-instance-auth-nist-cui.md)
- [Third-Party API Auth](plan-third-party-api-auth.md)
- [Data Persistence](data-persistence.md) — Historical design; persistence now ships, see Working with Saved Scans

## License

Apache 2.0 — See [LICENSE](https://github.com/infosecinnovations/chainsmith-recon/blob/main/LICENSE)
