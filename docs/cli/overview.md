# CLI Overview

Chainsmith provides a command-line interface for AI reconnaissance.

## Global Options

```bash
chainsmith --version             # Show version
chainsmith --help                # Show help
chainsmith --profile PROFILE     # Activate a profile for this session
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help and exit |
| `--server` | API server address (default: 127.0.0.1:8000) |
| `--profile` | Activate a scan behavior profile (e.g., aggressive, stealth) |

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Run reconnaissance scan |
| `list-checks` | List available checks |
| `suites` | List check suites |
| `scenarios list` | List available scenarios |
| `scenarios info` | Show scenario details |
| `export` | Export observations |
| `serve` | Start web UI |

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
