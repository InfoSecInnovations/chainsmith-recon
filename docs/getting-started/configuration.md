# Configuration

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROFILE` | Docker stack LLM profile (openai, anthropic, ollama, litellm) — set in `.env` | openai |
| `CHAINSMITH_LLM_PROVIDER` | LLM provider for the server process (anthropic, openai, litellm, none) | auto-detect |
| `CHAINSMITH_WORKSPACE` | Workspace directory (database, evidence, reports, logs) | `~/chainsmith/default` |
| `CHAINSMITH_STORAGE_EVIDENCE_RETENTION_DAYS` | Prune captured evidence older than this many days, at server start and daily (`storage.evidence_retention_days`; also `chainsmith evidence prune`). Scans and observations stay | 0 (keep for the workspace's lifetime) |
| `CHAINSMITH_SCENARIOS_DIR` | Custom scenarios directory | ./scenarios |
| `CHAINSMITH_PORT` | Host port the Docker stack publishes | 8100 |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `LITELLM_BASE_URL` | LiteLLM proxy URL | - |

## Workspace

Everything one body of work produces — database, captured evidence, reports,
scratch files, logs, and customizations — lives in a single workspace
directory. Choose it at launch (most specific wins):

1. `chainsmith --workspace DIR ...`
2. `CHAINSMITH_WORKSPACE`
3. `workspace:` in `chainsmith.yaml`
4. `~/chainsmith/default`

A workspace may contain its own `workspace.yaml` with settings for that
workspace. The Docker stack uses `./workspace` in the repository directory.

## Scope Control

### Include Domains

The target argument defines the primary scope:

```bash
chainsmith scan example.com
chainsmith scan "*.example.com"  # Wildcard
```

### Exclude Domains

```bash
chainsmith scan example.com --exclude admin.example.com --exclude internal.example.com
```

### Scope File

Exclusions, a scan window and proof-of-scope settings can come from a YAML or JSON file. The scope is
sent with the scan request itself, so another client changing scope cannot affect this scan.

```yaml
# scope.yaml
target: example.com              # optional; must match TARGET if given
exclude: [admin.example.com]
scan_window: {start: "2026-11-07T09:00:00Z", end: "2026-11-07T17:00:00Z"}
proof_of_scope: {traffic_logging: true, block_exclusions: true, log_violations: true}
```

```bash
chainsmith scan example.com --scope scope.yaml
```

An unknown key is an error, not ignored.

## Check Selection

### By Suite

```bash
chainsmith scan example.com --suite network --suite ai
```

Available suites: `network`, `web`, `ai`, `mcp`, `agent`, `rag`, `cag`

### By Check Name

```bash
chainsmith scan example.com -c network_dns_enumeration -c mcp_discovery
```

### By Preset

Presets bundle a check selection with default tunables:

| Preset | What it runs |
|--------|--------------|
| `quick` | Network and web suites, narrow web port profile, one attempt per check |
| `thorough` | Every suite, `lab` port profile (the widest), one extra retry |
| `passive` | Every suite minus intrusive (active-probing) checks, at a lower request rate |
| `ai-focused` | AI, MCP, agent, RAG, and CAG suites |

```bash
chainsmith scan example.com --preset passive
```

Explicit `--suite`, `--checks`, and `--port-profile` override a preset's
selection. Presets are defined in `app/data/presets.yaml`.

### Port Profile

```bash
chainsmith scan example.com --port-profile ai   # web, ai, full, lab
```

## Execution

Checks always run in dependency order: a check waits until the context keys it
depends on exist, and is skipped if they never appear.

### Parallel Execution

Run independent checks in parallel within phases:

```bash
chainsmith scan example.com --parallel
```

## Output Configuration

### Format

```bash
chainsmith scan example.com -f json   # JSON array
chainsmith scan example.com -f yaml   # YAML with summary
chainsmith scan example.com -f md     # Markdown report
chainsmith scan example.com -f sarif  # SARIF for CI/CD
chainsmith scan example.com -f csv    # CSV
chainsmith scan example.com -f text   # Terminal (default)
```

### File Output

```bash
chainsmith scan example.com -o observations.json -f json
```

### Quiet Mode

Only output observations, no progress:

```bash
chainsmith scan example.com -q
```

### No Color

For piping or CI environments:

```bash
chainsmith scan example.com --no-color
```

## LLM Configuration

LLM features power attack chain discovery and observation verification. Scanning
checks are fully deterministic and do not require an LLM.

### Setting Up a Provider

**Docker stack:** set `LLM_PROFILE` and the matching key in `.env`, or pass
`./chainsmith.sh start --profile <name>` for one launch. This is the usual route.

**One-time (CLI flags):**

```bash
chainsmith scan example.com --provider anthropic
chainsmith scan example.com --provider openai
chainsmith scan example.com --no-llm
```

> `--provider` and `--no-llm` set `CHAINSMITH_LLM_PROVIDER` in the CLI's own
> process. A server the CLI starts inherits it. When the CLI talks to a
> separately running server (including the Docker stack) the flags cannot
> apply, and the CLI says so; configure the server instead, via `.env`, its
> environment, or `chainsmith prefs set llm.provider <name|none>`.

**Per-session (environment variables, for a native `chainsmith serve`):**

```bash
export CHAINSMITH_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
chainsmith serve
```

**Persistent (preferences):**

```bash
# Set provider permanently — no env vars or flags needed on future scans
chainsmith prefs set llm.provider anthropic

# Or disable LLM permanently
chainsmith prefs set llm.enabled false
```

### Priority Order

LLM configuration is resolved in this order (highest priority first):

1. **CLI flags** (`--no-llm`, `--provider`) — one-shot override for this scan
2. **Persistent preferences** (`chainsmith prefs set llm.*`) — saved to disk
3. **Auto-detection** — checks for `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `LITELLM_BASE_URL`
4. **Default** — no LLM (graceful degradation)

### LLM Preference Keys

| Key | Type | Description |
|-----|------|-------------|
| `llm.enabled` | bool | Enable/disable all LLM features (default: true) |
| `llm.provider` | string | Provider: openai, anthropic, litellm, none (default: auto-detect) |
| `llm.chain_analysis` | bool | Enable LLM-based chain discovery (default: true) |
| `llm.verification` | bool | Enable LLM-based observation verification (default: true) |

### What LLM Affects

**Disabled without LLM:**
- LLM-based attack chain discovery (rule-based chains still work)
- LLM-based observation verification
- Conversational scoping dialogue

**NOT affected:**
- All scanning checks (100% deterministic)
- Rule-based chain analysis (pattern matching against known attack chains)
- All UI visualizations and reporting

### When to Disable LLM

- No API keys available
- Air-gapped or restricted environments
- Fully deterministic, reproducible results needed
- CI/CD pipelines where LLM costs or latency are undesirable

## Profiles

Profiles are named sets of scan behavior preferences (timeouts, rate limits,
concurrency). Built-in profiles: `default`, `aggressive`, `stealth`.

Profiles control *how* the scanner behaves, not *what features* are enabled.
LLM configuration is managed separately via `llm.*` preferences or CLI flags.

### Activating a Profile

```bash
# One-shot via CLI flag
chainsmith --profile aggressive scan example.com
chainsmith --profile stealth scan example.com

# Persistent activation
chainsmith prefs profile activate stealth
```

### Built-in Profiles

| Profile | Description |
|---------|-------------|
| `default` | Balanced settings for general reconnaissance |
| `aggressive` | High timeouts, parallel execution, WAF evasion enabled |
| `stealth` | Low rate limits, respects robots.txt, longer delays |

### Managing Profiles

```bash
# List available profiles
chainsmith prefs profile list

# Show profile details
chainsmith prefs profile show aggressive

# Show fully resolved preferences
chainsmith prefs profile show stealth --resolved

# Create a custom profile
chainsmith prefs profile create my-profile --base aggressive

# Activate a profile persistently
chainsmith prefs profile activate stealth
```

## Scenarios Directory

Custom scenario location:

```bash
export CHAINSMITH_SCENARIOS_DIR=/path/to/scenarios
chainsmith scenarios list
```

Default search paths:
1. `$CHAINSMITH_SCENARIOS_DIR`
2. `~/.chainsmith/scenarios/`
3. `./scenarios/`
