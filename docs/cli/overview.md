# CLI Overview

Chainsmith provides a command-line interface for AI reconnaissance.

The CLI is a client of the Chainsmith API server: commands such as `scan`,
`list-checks`, and `scans` send requests to a running server and display the
results. Start a server first — either the Docker stack from
[QUICKSTART.md](../../QUICKSTART.md) or `chainsmith serve` — then point the CLI at it.

## Server Address

| How the server runs | Address | CLI usage |
|---------------------|---------|-----------|
| Docker, via `./chainsmith.sh start` | `127.0.0.1:8100` (host port; override with `CHAINSMITH_PORT`) | `chainsmith --server 127.0.0.1:8100 scan example.com` |
| Native, via `chainsmith serve` | `127.0.0.1:8000` (change with `--host` / `--port`) | `chainsmith scan example.com` (8000 is the default) |

Inside the container the server always listens on 8000; `docker-compose.chainsmith.yml`
maps it to 8100 on the host. The examples in these docs omit `--server` for brevity.

## Global Options

```bash
chainsmith --version             # Show version
chainsmith --help                # Show help
chainsmith --profile PROFILE     # Activate a profile for this session
chainsmith --workspace DIR       # Use a specific workspace
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help and exit |
| `--server` | API server address (default: 127.0.0.1:8000) |
| `--profile` | Activate a scan behavior profile (e.g., aggressive, stealth) |
| `--workspace` | Workspace directory owning the database, evidence, logs, and reports (default: `~/chainsmith/default`, or `$CHAINSMITH_WORKSPACE`) |

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Run reconnaissance scan |
| `list-checks` | List available checks |
| `suites` | List check suites |
| `scenarios list` | List available scenarios |
| `scenarios info` | Show scenario details |
| `export` | Export observations |
| `scans` | Browse, compare, and delete saved scans |
| `observations` | Accept, mark false-positive, or reopen observations |
| `report` | Generate reports from saved scans |
| `prefs` | Preferences and scan behavior profiles |
| `swarm` | Distributed scanning (keys, agents, status) |
| `serve` | Start the API server and web UI natively |

See [CLI Commands](commands.md) for every option.

## Common Workflows

### Basic Scan

```bash
chainsmith scan example.com
```

### Targeted Scan

```bash
chainsmith scan example.com --suite ai --suite mcp
```

### Training Mode

```bash
chainsmith scan fakobanko.local --scenario fakobanko
```

### Scan Without LLM

```bash
chainsmith scan example.com --no-llm
```

### CI/CD Integration

```bash
chainsmith scan example.com -f sarif -o results.sarif --quiet --no-color
```

### Exploration

```bash
# What checks are available?
chainsmith list-checks

# What suites exist?
chainsmith suites

# What would run?
chainsmith scan example.com --plan

# Validate config
chainsmith scan example.com --dry-run
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid config, scan failure) |
