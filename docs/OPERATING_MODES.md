# Chainsmith Operating Modes

Chainsmith supports three operating modes: **Normal Mode** for scanning real systems, **Scenario Mode** for training and testing with simulated targets, and **Swarm Mode** for distributed scanning across multiple agents.

## Normal Mode

Normal mode is for production use — scanning real systems to discover AI security vulnerabilities.

### Starting Chainsmith

```bash
# Start Chainsmith
./chainsmith.sh start

# With a specific LLM profile
./chainsmith.sh start --profile openai
./chainsmith.sh start --profile anthropic
./chainsmith.sh start --profile ollama
```

### Using the Web UI

1. Open http://localhost:8100
2. Set your target scope (e.g., `api.example.com`)
3. Configure exclusions if needed
4. Start the scan
5. Review observations

### Using the API

```bash
# Set scope
curl -X POST http://localhost:8100/api/v1/scope \
  -H "Content-Type: application/json" \
  -d '{"target": "api.example.com", "exclude": ["admin.example.com"]}'

# Start scan
curl -X POST http://localhost:8100/api/v1/scan/start

# Check status
curl http://localhost:8100/api/v1/scan

# Get observations
curl http://localhost:8100/api/v1/observations
```

### Using the CLI

```bash
# Scan a target
chainsmith scan --target api.example.com

# Run specific check suites
chainsmith scan --target api.example.com --suite ai --suite web

# Run specific checks
chainsmith scan --target api.example.com --check llm_endpoint_discovery --check prompt_leakage
```

---

## Scenario Mode

Scenario mode is for training and testing — running Chainsmith against simulated vulnerable targets in a controlled environment.

### Quick Start with Range Launcher

The easiest way to use scenario mode:

```bash
# Start a scenario (this also starts Chainsmith and loads the scenario)
./range/start-range.sh fakobanko

# Start with randomization (varies which attack chains are active)
./range/start-range.sh fakobanko --randomize

# Start with all optional services
./range/start-range.sh fakobanko --all

# Start with specific service profiles
./range/start-range.sh fakobanko --profile ml --profile agent
```

The range launcher will:
1. Start the scenario's Docker services
2. Start Chainsmith (if not already running)
3. Load the scenario in Chainsmith via API
4. Display status and access URLs

### Manual Scenario Loading

If Chainsmith is already running, you can load a scenario manually:

```bash
# List available scenarios
curl http://localhost:8100/api/v1/scenarios

# Load a scenario
curl -X POST http://localhost:8100/api/v1/scenarios/load \
  -H "Content-Type: application/json" \
  -d '{"name": "fakobanko"}'

# Check current scenario
curl http://localhost:8100/api/v1/scenarios/current

# Clear scenario (return to normal mode)
curl -X POST http://localhost:8100/api/v1/scenarios/clear
```

### CLI with Scenarios

```bash
# Run with a scenario
chainsmith scan --scenario fakobanko --target "*.fakobanko.local"

# List available scenarios
chainsmith scenarios list

# Show scenario details
chainsmith scenarios info fakobanko
```

### How Scenario Mode Works

When a scenario is loaded:

1. **Simulated checks are activated** — The checks listed in the scenario's `scenario.json` under `simulations` are loaded from `app/checks/simulator/simulations/`

2. **Real checks are bypassed** — Instead of making actual network requests, checks return pre-configured responses from YAML simulation files

3. **Observations are generated** — The simulated responses trigger the same observation logic as real checks, producing realistic observations

4. **Attack chains are detected** — Chainsmith's chain detection works the same way, identifying attack patterns from the simulated observations

### Available Scenarios

| Scenario | Description | Services |
|----------|-------------|----------|
| `fakobanko` | AI-powered banking platform with LLM chatbot, MCP tools, RAG, and semantic caching | www, chat, api, docs, ml*, internal*, admin*, vector*, agent*, mcp* |
| `demo-domain` | Generic IT helpdesk portal with AI assistant and MCP agent | www, chat, api, agent |

\* = Optional services (activated via `--profile` or `--all`)

### Creating Custom Scenarios

See `scenarios/_template/README.md` for instructions on creating your own scenarios.

---

## Swarm Mode

Swarm mode distributes check execution across multiple agents running on
different hosts. A coordinator (the Chainsmith server) breaks scans into
tasks, resolves dependencies, and assigns work to agents that poll, execute,
and report back. The scan API and web UI work exactly the same -- swarm mode
is transparent.

For full setup instructions, see [swarm-usage.md](swarm-usage.md).
For architecture and design decisions, see [swarm-architecture.md](swarm-architecture.md).

### Quick Start

```bash
# 1. Generate an API key (on coordinator host)
chainsmith swarm generate-key --name "agent-01"

# 2. Start coordinator
chainsmith serve --coordinator --host 0.0.0.0

# 3. Start agent (on another host)
chainsmith swarm agent --coordinator http://coordinator:8000 --key <key>

# 4. Run a scan (same as normal mode)
chainsmith scan example.com --server coordinator:8000
```

### When to Use Swarm Mode

- Large check suites that benefit from parallel execution across hosts
- Targets spanning multiple network segments or cloud regions
- Engagements requiring distributed scan traffic for OPSEC

---

## Switching Between Modes

### From Normal to Scenario Mode

```bash
# Via API
curl -X POST http://localhost:8100/api/v1/scenarios/load \
  -H "Content-Type: application/json" \
  -d '{"name": "fakobanko"}'

# Or restart with range launcher
./range/start-range.sh fakobanko
```

### From Scenario to Normal Mode

```bash
# Via API
curl -X POST http://localhost:8100/api/v1/scenarios/clear

# The next scan will use real checks against real targets
```

---

## Stopping and Resetting

### Stop Range (keeps session state)

```bash
# Stop specific scenario
./range/stop-range.sh fakobanko

# Stop all running scenarios
./range/stop-range.sh
```

### Reset Range (clears session state)

```bash
# Reset specific scenario
./range/reset-range.sh fakobanko

# Reset all scenarios
./range/reset-range.sh --all
```

### Stop Chainsmith

```bash
./chainsmith.sh stop
```

---

## API Reference

### Scenarios

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scenarios` | GET | List available scenarios and current active scenario |
| `/api/v1/scenarios/load` | POST | Load a scenario by name |
| `/api/v1/scenarios/clear` | POST | Clear active scenario (return to normal mode) |
| `/api/v1/scenarios/current` | GET | Get details of currently active scenario |

### Scan

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scope` | POST | Set target scope |
| `/api/v1/scope` | GET | Get current scope |
| `/api/v1/scan/start` | POST | Start scan |
| `/api/v1/scan` | GET | Get scan status |
| `/api/v1/scan/stop` | POST | Stop running scan |
| `/api/v1/observations` | GET | Get all observations |
| `/api/v1/observations/by-host` | GET | Get observations grouped by host |
| `/api/v1/chains` | GET | Get detected attack chains |

---

## Troubleshooting

### Scenario not loading

```bash
# Check if scenario exists
ls scenarios/

# Check scenario.json is valid
cat scenarios/fakobanko/scenario.json | jq .

# Check Chainsmith logs
docker logs chainsmith-recon
```

### Simulations not working

```bash
# Verify simulations exist
ls app/checks/simulator/simulations/

# Check scenario lists correct simulation paths
cat scenarios/fakobanko/scenario.json | jq '.simulations'
```

### Port conflicts

```bash
# Check what's using a port
ss -tuln | grep 8080

# Stop conflicting services before starting range
./range/stop-range.sh
```
