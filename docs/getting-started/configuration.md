# Configuration

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CHAINSMITH_LLM_PROVIDER` | LLM provider (anthropic, openai, litellm, none) | none |
| `CHAINSMITH_SCENARIOS_DIR` | Custom scenarios directory | ./scenarios |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `LITELLM_API_BASE` | LiteLLM proxy URL | - |

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

## Check Selection

### By Suite

```bash
chainsmith scan example.com --suite network --suite ai
```

Available suites: `network`, `web`, `ai`, `mcp`, `agent`, `rag`, `cag`

### By Check Name

```bash
chainsmith scan example.com -c dns_enumeration -c mcp_discovery
```

## Execution Modes

### Chain Mode (Default)

Respects dependencies between checks:

```bash
chainsmith scan example.com  # Chain mode on by default
```

### Legacy Mode

Runs checks without dependency ordering:

```bash
chainsmith scan example.com --no-chain
```

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
chainsmith scan example.com -f text   # Terminal (default)
```

### File Output

```bash
chainsmith scan example.com -o findings.json -f json
```

### Quiet Mode

Only output findings, no progress:

```bash
chainsmith scan example.com -q
```

### No Color

For piping or CI environments:

```bash
chainsmith scan example.com --no-color
```

## LLM Configuration

LLM features power attack chain discovery and finding verification. Scanning
checks are fully deterministic and do not require an LLM.

### Setting Up a Provider

**One-time (CLI flags):**

```bash
chainsmith scan example.com --provider anthropic
chainsmith scan example.com --provider openai
chainsmith scan example.com --no-llm
```

**Per-session (environment variables):**

```bash
export CHAINSMITH_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
chainsmith scan example.com
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
| `llm.verification` | bool | Enable LLM-based finding verification (default: true) |

### What LLM Affects

**Disabled without LLM:**
- LLM-based attack chain discovery (rule-based chains still work)
- LLM-based finding verification
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
