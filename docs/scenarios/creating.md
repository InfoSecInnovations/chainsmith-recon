# Creating Scenarios

Create custom scenarios for training or testing.

A scenario is a self-contained directory under `scenarios/`: Docker services
that Chainsmith scans with its real checks, plus optional **simulations** that
replace individual checks with canned results.

## Directory Structure

Start from the template:

```bash
cp -r scenarios/_template scenarios/my-scenario
```

```
scenarios/
└── my-scenario/
    ├── scenario.json        # Metadata and configuration (required)
    ├── docker-compose.yml   # Target services
    ├── services/            # FastAPI service implementations
    ├── simulations/         # Optional check overrides, by suite
    │   └── mcp/
    │       └── mcp_discovery_my_scenario.yaml
    ├── data/                # Persistent state (optional)
    └── randomize.json       # Optional randomization config
```

Scenarios are found in `$CHAINSMITH_SCENARIOS_DIR`, `~/.chainsmith/scenarios/`,
and the repository's `scenarios/` directory, in that order.

See `scenarios/_template/README.md` for building the services themselves.

## scenario.json

```json
{
  "name": "my-scenario",
  "description": "Custom training scenario",
  "version": "1.0.0",
  "target": {
    "pattern": "*.my-scenario.local",
    "known_hosts": ["www", "api", "chat"],
    "ports": [9000, 9001, 9002]
  },
  "simulations": [
    "mcp/mcp_discovery_my_scenario.yaml"
  ]
}
```

`simulations` is normally empty — every check runs for real against the
scenario's services. List a simulation only when a specific check must be
spoofed (the target can't withstand the test, or for development).

### Simulation Path Resolution

Each entry is a path relative to a simulations directory, resolved in this order:

1. `scenarios/<name>/simulations/<path>` — scenario-specific (wins if both exist)
2. `app/checks/simulator/simulations/<path>` — global, shared by all scenarios

## Simulation YAML

Each simulation file stands in for one check: it supplies the check's outputs
for downstream checks and the observations to report.

```yaml
# scenarios/my-scenario/simulations/mcp/mcp_discovery_my_scenario.yaml

suite: mcp
emulates: mcp_discovery
target: "mcp.my-scenario.local"
disposition: server_found

behavior:
  latency_ms: 150

output:
  mcp_servers:
    - url: "http://mcp.my-scenario.local:8080/mcp"
      path: "/mcp"
      transport: "http"
      auth_required: false
      mcp_version: "1.0"
      service:
        url: "http://mcp.my-scenario.local:8080"
        host: "mcp.my-scenario.local"
        port: 8080
        scheme: "http"
        service_type: "ai"

findings:
  - title: "MCP server discovered"
    description: "MCP endpoint found without authentication."
    severity: "medium"
    evidence: "Path: /mcp, Auth: false"
    check_name: "mcp_discovery"
    target_url: "http://mcp.my-scenario.local:8080/mcp"
```

## Field Reference

### Top-Level

| Field | Required | Description |
|-------|----------|-------------|
| `suite` | Yes | Suite name (network, web, ai, mcp, agent, rag, cag) |
| `emulates` | Yes | Name of the check to replace. Must be the current, suite-prefixed name exactly (e.g. `network_dns_enumeration`, `web_header_analysis`) — run `chainsmith list-checks` to see them |
| `target` | Yes | Target host/pattern |
| `disposition` | Yes | Scenario variant identifier (also added to the outputs) |
| `behavior` | No | Simulated runtime behavior (below) |
| `output` | No | The check's outputs |
| `findings` | No | Observations to emit |

### behavior

| Field | Default | Description |
|-------|---------|-------------|
| `latency_ms` | 0 | Artificial delay before returning |
| `failure_mode` | `none` | `none`, `exception`, `timeout`, or `malformed` |
| `failure_message` | `Simulated failure` | Error text for `failure_mode: exception` |

### output

Becomes the check's `result.outputs`. It must match what the real check
produces (see the check's `produces` list in its `contract.yaml`), or
downstream checks won't find what they depend on. Two shapes get special
handling: `target_hosts` + `dns_records` (DNS-style, one observation per
host) and a `hosts` list (each entry becomes a discovered service).

### findings

List of observations to generate:

| Field | Required | Description |
|-------|----------|-------------|
| `title` | Yes | Observation title |
| `description` | No | Detailed description |
| `severity` | No (default `info`) | critical, high, medium, low, info |
| `evidence` | No | Raw evidence string |
| `check_name` | No | Originating check (defaults to `emulates`) |
| `target_url` | No | Specific URL |
| `references` | No | List of reference links |

Simulated observations are emitted directly; they do not pass through the
probe/grade stage that real checks use.

## Templates

Commented examples for each check live in the global simulations directory:

```bash
ls app/checks/simulator/simulations/*/TEMPLATE.yaml
```

Some templates still use older check names in `emulates`; use the current
suite-prefixed name from `chainsmith list-checks` when you copy one.

## Testing

```bash
# Verify scenario loads
chainsmith scenarios list
chainsmith scenarios info my-scenario

# Run scenario
chainsmith scan my-scenario.local --scenario my-scenario
```

## Tips

1. **Match real check outputs**: Read the check's `contract.yaml` (`produces`) and `check.py` to understand expected output shapes
2. **Use consistent naming**: `{check}_{scenario}.yaml`
3. **Include findings**: Simulations without findings are less useful for training
4. **Add references**: Link to OWASP, CWE, etc. for educational value
