# Creating Scenarios

Create custom scenarios for training or testing.

## Directory Structure

```
scenarios/
└── my-scenario/
    └── scenario.json
```

Simulation files go in `app/data/simulations/{suite}/`.

## scenario.json

```json
{
  "name": "my-scenario",
  "description": "Custom training scenario",
  "version": "1.0.0",
  "target": {
    "pattern": "*.example.local",
    "known_hosts": ["www", "api", "chat"]
  },
  "simulations": [
    "network/dns_my_scenario.yaml",
    "web/headers_my_scenario.yaml",
    "ai/llm_endpoint_my_scenario.yaml"
  ]
}
```

## Simulation YAML

Each simulation file defines outputs and findings for a check:

```yaml
# app/data/simulations/mcp/mcp_discovery_custom.yaml

suite: mcp
emulates: mcp_discovery
target: "mcp.example.local"
disposition: server_found

output:
  mcp_servers:
    - url: "http://mcp.example.local:8080/mcp"
      path: "/mcp"
      transport: "http"
      auth_required: false
      mcp_version: "1.0"
      service:
        url: "http://mcp.example.local:8080"
        host: "mcp.example.local"
        port: 8080
        scheme: "http"
        service_type: "ai"

findings:
  - title: "MCP server discovered"
    description: "MCP endpoint found without authentication."
    severity: "medium"
    evidence: "Path: /mcp, Auth: false"
    check_name: "mcp_discovery"
    target_url: "http://mcp.example.local:8080/mcp"
```

## Field Reference

### Top-Level

| Field | Required | Description |
|-------|----------|-------------|
| `suite` | Yes | Suite name (network, web, ai, mcp, agent, rag, cag) |
| `emulates` | Yes | Check name to simulate |
| `target` | Yes | Target host/pattern |
| `disposition` | Yes | Scenario variant identifier |

### output

Defines what the check's `result.outputs` should contain. Must match what the real check produces.

### findings

List of findings to generate:

| Field | Required | Description |
|-------|----------|-------------|
| `title` | Yes | Finding title |
| `description` | No | Detailed description |
| `severity` | Yes | critical, high, medium, low, info |
| `evidence` | No | Raw evidence string |
| `check_name` | Yes | Originating check |
| `target_url` | No | Specific URL |
| `references` | No | List of reference links |

## Templates

Use the TEMPLATE.yaml files in each simulation directory:

```bash
ls app/data/simulations/*/TEMPLATE.yaml
```

## Testing

```bash
# Verify scenario loads
chainsmith scenarios list

# Run scenario
chainsmith scan example.local --scenario my-scenario
```

## Tips

1. **Match real check outputs**: Study existing checks to understand expected output shapes
2. **Use consistent naming**: `{check}_{scenario}.yaml`
3. **Include findings**: Scenarios without findings are less useful for training
4. **Add references**: Link to OWASP, CWE, etc. for educational value
