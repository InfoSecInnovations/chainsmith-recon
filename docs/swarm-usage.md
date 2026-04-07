# Swarm Mode: Usage Guide

Swarm mode distributes scan execution across multiple machines. A
**coordinator** (the Chainsmith server) breaks scans into tasks and assigns
them to **agents** that poll for work, execute checks locally, and report
observations back. The existing scan API and web UI work unchanged -- swarm
mode is transparent to the user.

For architecture details and design rationale, see
[swarm-architecture.md](swarm-architecture.md).

## When to Use Swarm Mode

- **Scale**: 60+ checks across 7 suites take time on a single node.
  Distributing work across agents parallelizes execution.
- **Network topology**: Targets may span network segments, zones, or
  cloud regions. Agents can scan from different vantage points.
- **OPSEC**: Distributing scan traffic across multiple source IPs
  reduces the detection signature on any single origin.

If you're running a quick scan from your laptop, you don't need swarm
mode. It's designed for engagements where throughput, coverage, or
stealth matter.

## Quick Start

### 1. Generate an API key

On the coordinator host:

```bash
chainsmith swarm generate-key --name "agent-dmz-01"
```

This prints the raw API key once. Save it -- it cannot be retrieved
later.

### 2. Start the coordinator

```bash
chainsmith serve --coordinator --host 0.0.0.0
```

The `--coordinator` flag enables swarm mode. The server still serves the
web UI and API as usual.

### 3. Start an agent

On a different machine (or the same machine for testing):

```bash
chainsmith swarm agent \
  --coordinator http://coordinator-host:8000 \
  --key <api-key> \
  --name "dmz-scanner-01"
```

The agent registers with the coordinator, then polls for tasks.

### 4. Run a scan

Scans are triggered exactly as before -- via CLI, API, or the web UI:

```bash
# CLI
chainsmith scan example.com --server coordinator-host:8000

# API
curl -X POST http://coordinator-host:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"suites": ["network", "web", "ai"]}'
```

The coordinator decomposes the scan into tasks, resolves dependencies
using the check execution plan (network before web, web before ai, etc.),
and assigns ready tasks to connected agents. Observations stream back and
appear in the web UI and API in real time.

### 5. Check status

```bash
# CLI
chainsmith swarm status

# API (no auth required)
curl http://coordinator-host:8000/api/swarm/status
```

## CLI Reference

### Key Management

Keys are stored in the coordinator's database. These commands operate
directly on the database, so run them on the coordinator host.

```bash
# Generate a new key
chainsmith swarm generate-key --name "agent-dmz-01"

# List all keys
chainsmith swarm list-keys

# Revoke a key by ID
chainsmith swarm revoke-key <key-id>
```

### Starting an Agent

```bash
chainsmith swarm agent [OPTIONS]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--coordinator URL` | Yes | -- | Coordinator address (e.g., `http://10.0.0.1:8000`) |
| `--key KEY` | Yes | -- | API key from `generate-key` |
| `--name NAME` | No | hostname | Human-readable agent name |
| `--suites SUITE` | No | all | Restrict to specific suites (repeatable) |
| `--max-concurrent N` | No | 3 | Max parallel checks on this agent |

Examples:

```bash
# Basic agent
chainsmith swarm agent --coordinator http://10.0.0.1:8000 --key abc123

# Agent restricted to network and web suites
chainsmith swarm agent \
  --coordinator http://10.0.0.1:8000 \
  --key abc123 \
  --name "external-scanner" \
  --suites network --suites web

# High-concurrency agent on a powerful host
chainsmith swarm agent \
  --coordinator http://10.0.0.1:8000 \
  --key abc123 \
  --max-concurrent 10
```

### Coordinator Mode

```bash
chainsmith serve --coordinator [--host HOST] [--port PORT]
```

The `--coordinator` flag sets the `CHAINSMITH_SWARM_ENABLED` environment
variable. You can also enable it via config (see below).

### Status

```bash
chainsmith swarm status [--server HOST:PORT]
```

Shows: running state, connected agents, task progress by status
(queued/assigned/in-progress/complete/failed), and total observations.

## API Endpoints

All agent-facing endpoints require `Authorization: Bearer <key>`.
Status is public.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/swarm/register` | Yes | Agent registration |
| `DELETE` | `/api/swarm/agents/{id}` | Yes | Agent deregistration |
| `POST` | `/api/swarm/heartbeat` | Yes | Agent heartbeat |
| `GET` | `/api/swarm/tasks/next?agent_id=X` | Yes | Poll for next task |
| `POST` | `/api/swarm/tasks/{id}/start` | Yes | Acknowledge task start |
| `POST` | `/api/swarm/tasks/{id}/result` | Yes | Submit check results |
| `POST` | `/api/swarm/tasks/{id}/fail` | Yes | Report check failure |
| `GET` | `/api/swarm/status` | No | Coordinator status |
| `GET` | `/api/swarm/agents` | Yes | List connected agents |
| `POST` | `/api/swarm/keys` | No | Create API key |
| `GET` | `/api/swarm/keys` | No | List API keys |
| `DELETE` | `/api/swarm/keys/{id}` | No | Revoke API key |

## Configuration

### Coordinator

Add to `chainsmith.yaml`:

```yaml
swarm:
  enabled: true
  default_rate_limit: 10.0    # requests/sec per agent per host
  task_timeout_seconds: 300   # max time for a single check
  heartbeat_interval: 30      # expected agent heartbeat interval (seconds)
  max_agents: 50              # max connected agents
```

Or via environment variables:

```bash
export CHAINSMITH_SWARM_ENABLED=true
export CHAINSMITH_SWARM_DEFAULT_RATE_LIMIT=10.0
export CHAINSMITH_SWARM_TASK_TIMEOUT=300
```

### Agent

Agents are configured entirely via CLI flags (see above). They don't
read the coordinator's config file.

## How It Works

### Task Lifecycle

```
[queued] --> [assigned] --> [in_progress] --> [complete]
                |                               |
                |          (agent failure)       |
                |<------------------------------+
                |               |
                v          [failed]
```

1. **Scan starts**: The coordinator resolves check dependencies using
   `ChainOrchestrator` and creates one task per check, grouped into
   phases (network phase 1, web phase 2, etc.).

2. **Agent polls**: An agent calls `GET /api/swarm/tasks/next`. The
   coordinator finds the first queued task whose phase dependencies
   are satisfied and assigns it.

3. **Agent executes**: The agent instantiates the check locally, sets
   the scope validator from the task payload, applies the coordinator-
   assigned rate limit, and runs the check.

4. **Agent reports**: Results (observations, outputs, discovered services)
   are sent back via `POST /api/swarm/tasks/{id}/result`. The
   coordinator merges outputs into the shared context so downstream
   checks have the data they need.

5. **Scan completes**: When all tasks are terminal (complete or failed),
   the coordinator marks the scan as done and persists results to the
   database.

### Dependency Resolution

Checks are grouped into phases by suite order:

```
Phase 1: network (DNS, port scan, service probes)
Phase 2: web (headers, robots, path probes, ...)
Phase 3: ai (LLM endpoints, prompt leakage, ...)
Phase 4: mcp, agent, rag
Phase 5: cag
```

A task in phase N is not assignable until all tasks in phases 1 through
N-1 are complete. This ensures that downstream checks receive upstream
outputs (e.g., web checks receive the services discovered by network
checks).

### Rate Limiting

Rate limits are coordinator-assigned and agent-enforced. The coordinator
sets `rate_limit` in each task payload based on the global budget. The
agent configures the check's built-in rate limiter before execution.

### Scope Validation

Each task payload includes only the domains and ports relevant to that
check. The agent validates all outbound requests against these before
sending. This is a defense-in-depth measure -- agents never receive the
full scope, only what they need.

## Security Considerations

- **API keys** are SHA-256 hashed before storage. The raw key is shown
  once at creation time and never stored.
- **Agents receive minimum data**: scoped domains/ports and upstream
  context, not the full scope, other agents' observations, or LLM config.
- **mTLS** is planned for Phase 3 (production deployments on untrusted
  networks). For now, deploy the coordinator behind a VPN or firewall.
- **Key management**: Revoke keys immediately if an agent is compromised.
  Use `chainsmith swarm revoke-key <id>`.

## Troubleshooting

### Agent can't connect

```bash
# Verify coordinator is reachable
curl http://coordinator-host:8000/api/swarm/status

# Check that the API key is valid
curl -H "Authorization: Bearer <key>" http://coordinator-host:8000/api/swarm/agents
```

### Agent connects but gets no tasks

- A scan must be running. Start one via the CLI, API, or web UI.
- If the agent declared `--suites`, check that the running scan includes
  those suites.
- Phase dependencies may not be satisfied yet. Tasks in later phases
  wait for earlier phases to complete.

### Observations not appearing

- Check `chainsmith swarm status` to see if tasks are completing.
- Check the agent's terminal output for errors.
- Verify the coordinator is running with `--coordinator` or
  `swarm.enabled: true`.

### Agent disconnects mid-scan

In Phase 1, assigned tasks for a disconnected agent are re-queued only
if the agent explicitly deregisters (e.g., Ctrl+C shutdown). If the
agent crashes without deregistering, its tasks remain in `assigned`
state. Heartbeat-based timeout and automatic reassignment are planned
for Phase 2.
