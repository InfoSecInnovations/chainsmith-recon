# Scenarios

Scenarios provide self-contained target environments for testing and training. Each scenario bundles Docker services, network configuration, and optional check overrides into a shareable directory.

## What is a Scenario?

A scenario defines a target environment — real services running in Docker that Chainsmith scans with real checks. Scenarios are **not** simulations by default. All checks run normally against the scenario's services.

Optionally, individual checks can be replaced with simulated (spoofed) responses via YAML files. This is only needed when a specific check must be skipped on the real target (e.g., the service can't withstand a particular test, or for development purposes). An empty `"simulations": []` is the normal and expected state.

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

See [Fakobanko Details](fakobanko.md)

## Scenario Structure

```
scenarios/
└── fakobanko/
    ├── scenario.json        # Metadata and configuration
    ├── docker-compose.yml   # Target services
    ├── services/            # FastAPI service implementations
    ├── simulations/         # Optional check overrides (usually empty)
    └── data/                # Persistent state (optional)
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
  "simulations": []
}
```

## Simulation Overrides

When a specific check needs to be spoofed, add its YAML path to the `simulations` array. Simulations replace the corresponding real check — all other checks still run normally.

```yaml
# scenarios/fakobanko/simulations/mcp/mcp_discovery_fakobanko.yaml
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
