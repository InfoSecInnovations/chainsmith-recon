# Swarm Testing Architecture

Design guidance for distributed scan execution in Chainsmith.

For setup instructions and CLI reference, see [swarm-usage.md](swarm-usage.md).

## Overview

Swarm mode enables multiple lightweight agents to execute checks in parallel
from different network vantage points, reporting results back to a central
coordinator. This scales both throughput (more checks running simultaneously)
and coverage (scanning from internal, external, and segmented network positions).

## Architecture

### Option C: Coordinator as a mode of the same binary

The coordinator is not a separate service. It is the existing Chainsmith server
running in coordinator mode. Agents are the same binary running in agent mode.

```
# Coordinator (accepts agents, also runs checks locally by default)
chainsmith serve --coordinator --host 0.0.0.0

# Agents (lightweight workers that poll for tasks)
chainsmith agent --server coordinator.internal:8000 --key <api-key>
```

When no agents are connected, the server behaves exactly as it does today
(solo mode). When agents connect, the coordinator distributes checks across
them while optionally continuing to run checks locally.

### Target Architecture (future)

The long-term target is a stub installer model (Option D): a minimal install
that pulls only the files needed for its role (coordinator or agent). This
reduces footprint on agent hosts and enables the coordinator to push check
code alongside task assignments.

The path to get there:

1. **Now (Option A):** Full binary, agent subcommand. Zero packaging overhead.
2. **Later (Option B):** Separate `chainsmith-agent` package built from the
   same repo, containing only the check runner and agent client.
3. **Eventually (Option D):** Stub installer that pulls role-specific modules
   from a registry or the coordinator itself.

The critical design constraint: keep a clean module boundary between agent
code and server code from day one, so the extraction at each step is
straightforward.

## Components

### Coordinator

The coordinator is the existing Chainsmith server with additional
responsibilities:

- **Agent registry:** Track connected agents, health, capabilities
- **Task scheduler:** Resolve check dependencies, assign ready checks to agents
- **Result collector:** Receive findings streamed from agents, store in AppState
- **Heartbeat monitor:** Detect failed agents, reassign their tasks
- **Local runner toggle:** Optionally run checks locally (default: on)

The coordinator lives in `app/swarm/coordinator.py` with API endpoints in
`app/routes/swarm.py`. It calls into the existing `ChainOrchestrator` and
`CheckRunner` interfaces — it does not duplicate their logic.

### Agent

A lightweight worker that:

1. Connects to the coordinator and registers
2. Polls for assigned checks
3. Executes checks using the local check runner
4. Streams findings back to the coordinator
5. Sends periodic heartbeats

The agent lives in `app/swarm/agent.py`. Its dependencies are minimal:

- `app/checks/` — The check framework and individual checks
- `app/swarm/agent.py` — Registration, polling, result submission
- HTTP client — For talking to the coordinator

The agent does NOT depend on:

- `app/routes/` — No server/API layer
- `app/engine/chains.py` — No chain analysis
- `app/agents/` — No LLM agents (verifier, chainsmith, scout)
- `app/preferences.py` — Preferences are coordinator-side
- `static/` — No UI

### API Endpoints

New endpoints under `/api/swarm/`:

```
POST   /api/swarm/register          Agent registration
DELETE /api/swarm/agents/{id}       Agent deregistration
POST   /api/swarm/heartbeat         Agent heartbeat
GET    /api/swarm/tasks/next        Poll for next assigned check
POST   /api/swarm/tasks/{id}/start  Mark task as in_progress
POST   /api/swarm/tasks/{id}/result Submit check results (findings)
POST   /api/swarm/tasks/{id}/fail   Report check failure
GET    /api/swarm/status            Coordinator status (for UI/CLI)
GET    /api/swarm/agents            List connected agents (for UI/CLI)
```

## Task Lifecycle

```
                    ┌─────────────────────────────┐
                    │                             │
                    v                             │
  [queued] ──▶ [assigned] ──▶ [in_progress] ──▶ [complete]
                    │                             │
                    │         (heartbeat timeout)  │
                    │◀────────────────────────────┘
                    │                 │
                    │                 v
                    │            [failed]
                    │                │
                    └────────────────┘
                      (reassignment)
```

1. **queued** — Check is ready to run (all dependencies resolved). Not yet
   assigned to any agent.
2. **assigned** — Coordinator has handed the check to a specific agent.
   Clock starts for heartbeat monitoring.
3. **in_progress** — Agent has acknowledged and started execution.
4. **complete** — Agent submitted findings. Findings are merged into the
   coordinator's AppState.
5. **failed** — Agent reported an error, or agent went silent (heartbeat
   timeout). Task returns to `queued` for reassignment.

### Dependency Resolution

The coordinator resolves all check dependencies before queueing. An agent
never receives a check whose dependencies have not been satisfied. The
existing `ChainOrchestrator` suite ordering (network -> web -> ai -> mcp ->
agent -> rag -> cag) is respected.

When a check completes, the coordinator evaluates whether any blocked checks
are now ready, and moves them to `queued`.

### Heartbeat & Reassignment

- Default heartbeat interval: **30 seconds** (configurable)
- Default timeout: **3 missed heartbeats** (90 seconds)
- On timeout: task returns to `queued`, agent marked as `stale`
- A stale agent that reconnects can re-register and receive new tasks

## Agent Identity & Authentication

### Registration

On connect, an agent provides:

- **API key** — Pre-shared key configured on the coordinator
- **Agent name** (optional) — Human-readable identifier; server assigns a
  UUID if not provided
- **TLS client certificate** — For mTLS in production deployments

The coordinator validates the key and certificate, then returns:

- Agent UUID
- Coordinator-assigned configuration (rate limits, etc.)

### Authentication Layers

| Layer | Purpose | Required |
|-------|---------|----------|
| API key | Identity verification, prevents unauthorized agents | Always |
| mTLS | Mutual authentication, prevents MITM and data injection | Production |

**Concern: false data injection.** An attacker who can impersonate an agent
could inject false findings into the coordinator. mTLS mitigates this by
ensuring both sides verify identity. API keys alone are insufficient if the
network is untrusted.

### Key Management

API keys are configured on the coordinator:

```bash
# Generate and register an agent key
chainsmith swarm add-key --name "agent-dmz-01"

# List registered keys
chainsmith swarm list-keys

# Revoke a key
chainsmith swarm revoke-key --name "agent-dmz-01"
```

## Scope & Data Visibility

Agents receive only what is needed to execute their assigned check:

| Data | Passed to Agent | Rationale |
|------|-----------------|-----------|
| Target URL(s) for the check | Yes | Required to execute |
| In-scope domains relevant to this check | Yes | Needed for scope validation |
| In-scope ports relevant to this check | Yes | Needed for scope validation |
| Full scope (all domains/ports) | No | Minimize exposure |
| Other agents' findings | No | Not needed for check execution |
| Chain analysis results | No | Coordinator-side only |
| LLM configuration/keys | No | Coordinator-side only |

The task payload sent to an agent looks like:

```json
{
  "task_id": "uuid",
  "check_name": "dns_enumeration",
  "check_config": { },
  "target": {
    "url": "https://example.com",
    "domains": ["example.com", "*.example.com"],
    "ports": [80, 443, 8080]
  },
  "rate_limit": {
    "requests_per_second": 10
  },
  "timeout_seconds": 120
}
```

## Rate Limiting

Rate limits are **coordinator-assigned, per-agent**. When an agent registers,
the coordinator assigns it a rate limit based on:

- The coordinator's global rate limit budget
- The number of connected agents
- The target host the agent is scanning

This ensures that N agents scanning the same host don't collectively exceed
a safe request rate, even though each agent enforces its own limit locally.

```
Global budget: 30 req/s for host X
3 agents scanning host X → each gets 10 req/s
1 agent disconnects → remaining 2 get 15 req/s each (rebalanced)
```

Future enhancement: coordinator-side global rate limiting with a token bucket
that agents draw from.

## Local Execution

The coordinator can optionally run checks locally, acting as an agent to
itself. This is controlled by a toggle:

```bash
# Default: coordinator also runs checks locally
chainsmith serve --coordinator

# Coordinator delegates only, does not run checks itself
chainsmith serve --coordinator --no-local
```

Default is `--local` (on) so that a single-server setup with one external
agent doubles throughput rather than just shifting work.

## Result Streaming

Agents stream findings back as each check completes (not batched):

```
POST /api/swarm/tasks/{id}/result
{
  "task_id": "uuid",
  "status": "complete",
  "findings": [ ... ],
  "duration_ms": 1234,
  "checks_metadata": { }
}
```

Findings use the same format as locally-run checks (`Finding` objects with
severity, title, description, evidence, check_name, target_url). No
transformation is needed — the coordinator inserts them directly into AppState.

Future enhancement: batched result submission for high-latency links.

## Duplicate Work

The coordinator does not assign the same check to multiple agents. Each check
is assigned to exactly one agent at a time. If that agent fails (heartbeat
timeout), the check is reassigned to a different agent.

This means duplicate findings from concurrent scans of the same endpoint
should not occur under normal operation. The only edge case is a network
partition where an agent completes work after being timed out and replaced.
The coordinator should deduplicate by `(check_name, target_url)` when
receiving late results.

## CLI Commands

### Coordinator Commands

```bash
# Start coordinator mode
chainsmith serve --coordinator [--host HOST] [--port PORT] [--no-local]

# Agent key management
chainsmith swarm add-key --name NAME
chainsmith swarm list-keys
chainsmith swarm revoke-key --name NAME

# Status
chainsmith swarm status
chainsmith swarm agents
```

### Agent Commands

```bash
# Start an agent
chainsmith agent --server HOST:PORT --key KEY [--name NAME] [--tls-cert CERT] [--tls-key KEY]

# Agent with custom name
chainsmith agent --server coordinator.internal:8000 --key abc123 --name "dmz-scanner-01"
```

## Module Structure

```
app/
  swarm/
    __init__.py
    coordinator.py      # Task scheduler, agent registry, heartbeat monitor
    agent.py            # Agent client: register, poll, execute, report
    models.py           # SwarmTask, AgentInfo, TaskStatus dataclasses
    auth.py             # API key validation, mTLS helpers
  routes/
    swarm.py            # /api/swarm/* endpoints
```

The swarm module depends on the existing check framework (`app/checks/`) but
not on the LLM agents, chain analysis, or UI.

## Configuration

### Coordinator Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `swarm.enabled` | false | Enable coordinator mode |
| `swarm.local_execution` | true | Run checks locally in addition to delegating |
| `swarm.heartbeat_interval` | 30 | Expected heartbeat interval (seconds) |
| `swarm.heartbeat_timeout` | 3 | Missed heartbeats before reassignment |
| `swarm.max_agents` | 50 | Maximum connected agents |
| `swarm.task_timeout` | 300 | Max time for a single check (seconds) |

### Agent Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `agent.server` | — | Coordinator address (required) |
| `agent.key` | — | API key (required) |
| `agent.name` | auto | Agent name (auto-generated UUID if omitted) |
| `agent.poll_interval` | 5 | Seconds between task polls |
| `agent.max_concurrent` | 3 | Max concurrent checks on this agent |

## Design Decisions (settled 2026-03-31)

The following questions were resolved during design review:

| # | Question | Decision |
|---|----------|----------|
| 1 | Which orchestrator for dependency resolution? | `ChainOrchestrator` — already understands suite ordering and phases |
| 2 | What data ships with a task? | Minimum needed: target info, scoped domains/ports, upstream outputs the check depends on |
| 3 | Agent concurrency model? | Async parallel via asyncio semaphore (size = `max_concurrent`). Checks are already async. |
| 4 | Where do API keys live? | New `swarm_api_keys` DB table (SQLite/Postgres). CLI commands map to DB CRUD. |
| 5 | How is the agent identified after registration? | API key at registration only. Agent UUID on all subsequent requests. |
| 6 | Concurrent findings merge — locking? | No. Single uvicorn worker + async event loop. Append between awaits is atomic. Multi-worker fix is DB-backed state (persistence track), not locks. |
| 7 | Scan lifecycle integration? | `SwarmRunner` replaces `CheckLauncher` when `swarm.enabled`. Same scan API surface, different backend. Coordinator *is* the runner. |
| 8 | Rate limiting? | Built from scratch. Coordinator-assigned, agent-enforced. |
| 9 | Agent-side scope validation? | **MVP:** Agent validates outbound requests against task payload domains/ports. **Future:** Defense-in-depth — agent independently fetches/validates full scope. |
| 10 | Phase 1 MVP definition? | One coordinator + one remote agent. Agent executes a single suite's checks. Findings appear in coordinator UI. |

## Implementation Phases

### Phase 1: Foundation

- Agent registration and heartbeat endpoints
- Task queueing from existing check dependency graph
- Agent CLI subcommand (register, poll, execute, report)
- API key authentication
- Basic coordinator status endpoint

### Phase 2: Robustness

- Heartbeat timeout and task reassignment
- Coordinator-assigned rate limiting with rebalancing
- Late result deduplication
- `--no-local` toggle
- `chainsmith swarm status` CLI command

### Phase 3: Security & Observability

- mTLS support
- Agent key management CLI commands
- Web UI: agent status panel, task distribution view
- Logging and audit trail for agent actions

### Phase 4: Distribution (target architecture)

- Separate `chainsmith-agent` package (Option B)
- Stub installer with role-based module pull (Option D)
- Coordinator pushes check code to agents
- Version pinning between coordinator and agent check sets
