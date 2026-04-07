# Scenarios

Scenarios provide simulated environments for training and testing without live targets.

## What is a Scenario?

A scenario is a collection of YAML simulation files that define how checks should behave. Instead of making real network requests, checks return predefined responses.

## Using Scenarios

```bash
# List available scenarios
chainsmith scenarios list

# Run with scenario
chainsmith scan fakobanko.local --scenario fakobanko
```

## Built-in Scenarios

### Fakobanko

A fictional regional bank with comprehensive AI infrastructure vulnerabilities.

```bash
chainsmith scan fakobanko.local --scenario fakobanko
```

**Hosts**: www, chat, api, docs, mcp, agent, rag, cache

**Simulations**: 21 checks across all suites

See [Fakobanko Details](fakobanko.md)

## Scenario Structure

```
scenarios/
└── fakobanko/
    ├── scenario.json        # Metadata and simulation list
    └── (references simulations in app/data/simulations/)
```

### scenario.json

```json
{
  "name": "fakobanko",
  "description": "AI-powered banking platform",
  "version": "2.0.0",
  "target": {
    "pattern": "*.fakobanko.local",
    "known_hosts": ["www", "chat", "api", "mcp", "agent", "rag", "cache"]
  },
  "simulations": [
    "network/dns_fakobanko.yaml",
    "mcp/mcp_discovery_fakobanko.yaml",
    ...
  ]
}
```

## Simulation Files

Simulations define check outputs:

```yaml
# app/data/simulations/mcp/mcp_discovery_fakobanko.yaml
suite: mcp
emulates: mcp_discovery
target: "mcp.fakobanko.local"
disposition: server_found

output:
  mcp_servers:
    - url: "http://mcp.fakobanko.local:8080/mcp"
      auth_required: false
      ...

observations:
  - title: "MCP server discovered"
    severity: "medium"
    ...
```

## Custom Scenarios

See [Creating Scenarios](creating.md)
