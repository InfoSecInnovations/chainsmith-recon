# Quick Start

## Your First Scan

```bash
chainsmith scan example.com
```

This runs all 25 checks in dependency order:

1. **Network**: DNS enumeration → service probe
2. **Web**: Headers, robots.txt, CORS, OpenAPI, paths
3. **AI**: LLM endpoints, embeddings, prompts, tools, filters
4. **MCP/Agent/RAG/CAG**: Specialized AI infrastructure checks

## View the Execution Plan

Before running, see what will happen:

```bash
chainsmith scan example.com --plan
```

Output:
```
=== Execution Plan ===
Suite order: network → web → ai → mcp → agent → rag → cag

Phase 1 [network] → sequential
  • dns_enumeration → ['services', 'target_hosts']

Phase 2 [network] → sequential
  • service_probe ← ['dns_enumeration'] → ['services']

Phase 3 [web] → sequential
  • header_analysis ← ['dns_enumeration', 'service_probe']
  ...
```

## Run Specific Suites

```bash
# Just network and web
chainsmith scan example.com --suite network --suite web

# Just AI checks
chainsmith scan example.com --suite ai
```

## Run Specific Checks

```bash
chainsmith scan example.com -c dns_enumeration -c llm_endpoint_discovery
```

## Dry Run (Validate Without Running)

```bash
chainsmith scan example.com --dry-run
```

## Export Findings

```bash
# JSON
chainsmith scan example.com -o report.json -f json

# YAML
chainsmith scan example.com -o report.yaml -f yaml

# Markdown
chainsmith scan example.com -o report.md -f md

# SARIF (for CI/CD)
chainsmith scan example.com -o report.sarif -f sarif
```

## Use a Scenario (Simulated Target)

For training or testing without live targets:

```bash
chainsmith scan fakobanko.local --scenario fakobanko
```

## Verbose Output

```bash
chainsmith scan example.com -v
```

Shows per-check progress:
```
Phase 1 [network]
  Running: dns_enumeration
  ✓ dns_enumeration: 1 findings
  Running: service_probe
  ✓ service_probe
...
```

## List Available Checks

```bash
chainsmith list-checks

# With dependencies
chainsmith list-checks --deps

# Filter by suite
chainsmith list-checks --suite mcp --verbose
```

## List Suites

```bash
chainsmith suites
```

Output:
```
Check Suites
Execution order: network → web → ai → mcp → agent → rag → cag

network (2 checks)
  Checks: dns_enumeration, service_probe

mcp (2 checks)
  Runs after: network
  Checks: mcp_discovery, mcp_tool_enumeration
...
```
