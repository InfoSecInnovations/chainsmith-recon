# Chainsmith Recon

**AI Reconnaissance Framework for Penetration Testers**

Chainsmith Recon is an open-source reconnaissance tool designed to discover, enumerate, and assess AI/ML systems. Built for SEC536 and real-world penetration testing.

## Features

- **7 Check Suites**: Network, Web, AI, MCP, Agent, RAG, CAG
- **25 Automated Checks**: From DNS enumeration to prompt injection testing
- **Chain Orchestration**: Dependency-aware execution ordering
- **Swarm Mode**: Distributed scanning across multiple agents
- **Scenario System**: Simulated environments for training
- **Payload Library**: 50+ injection payloads across 9 categories
- **Multiple Output Formats**: JSON, YAML, Markdown, SARIF

## Quick Start

```bash
# Install
pip install chainsmith-recon

# Scan a target
chainsmith scan example.com

# View execution plan
chainsmith scan example.com --plan

# Run specific suites
chainsmith scan example.com --suite ai --suite mcp

# Export findings
chainsmith scan example.com -o report.yaml -f yaml
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Chain Orchestrator                    │
│  network → web → ai → mcp → agent → rag → cag          │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                    Check Suites                          │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ network  │   web    │    ai    │   mcp    │ agent/rag/  │
│ (2)      │   (5)    │   (10)   │   (2)    │ cag (6)     │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                     Findings                             │
│  severity: critical | high | medium | low | info        │
└─────────────────────────────────────────────────────────┘
```

## Suites Overview

| Suite | Checks | Purpose |
|-------|--------|---------|
| **network** | 2 | DNS enumeration, service discovery |
| **web** | 5 | Headers, robots.txt, CORS, OpenAPI |
| **ai** | 10 | LLM endpoints, prompts, filters, tools |
| **mcp** | 2 | MCP server and tool enumeration |
| **agent** | 2 | Agent discovery, goal injection |
| **rag** | 2 | RAG endpoints, indirect injection |
| **cag** | 2 | Cache discovery, cross-session probes |

## Documentation

- [Installation Guide](getting-started/installation.md)
- [CLI Reference](cli/overview.md)
- [Check Reference](checks/overview.md)
- [Scenario System](scenarios/overview.md)
- [Working with Saved Scans](working-with-saved-scans.md) — Browse, compare, report on, and delete historical scans
- [Swarm Mode](swarm-usage.md) — Distributed scanning with remote agents
- [Swarm Architecture](swarm-architecture.md) — Design decisions and internals
- [Lab Integration](labs/sec536.md)

## License

Apache 2.0 — See [LICENSE](https://github.com/infosecinnovations/chainsmith-recon/blob/main/LICENSE)
