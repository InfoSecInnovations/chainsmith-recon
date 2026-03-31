# CLI Commands

## Global Options

These options apply to all commands and must appear before the command name.

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help and exit |
| `--server` | API server address (default: 127.0.0.1:8000) |
| `--profile` | Activate a scan behavior profile (e.g., aggressive, stealth) |

```bash
# Example: scan with aggressive profile
chainsmith --profile aggressive scan example.com

# Example: scan with stealth profile
chainsmith --profile stealth scan example.com
```

---

## scan

Run reconnaissance scan against a target.

```bash
chainsmith scan TARGET [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `TARGET` | Base domain to scan (e.g., example.com, *.example.com) |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--exclude` | `-e` | Exclude domains from scope (repeatable) |
| `--checks` | `-c` | Run specific checks by name (repeatable) |
| `--suite` | `-s` | Run checks from suite (repeatable) |
| `--scenario` | | Load scenario for simulated scanning |
| `--parallel` | | Run checks in parallel within phases |
| `--chain/--no-chain` | | Enable/disable dependency ordering (default: on) |
| `--plan` | | Show execution plan and exit |
| `--dry-run` | | Validate config without running |
| `--output` | `-o` | Output file path |
| `--format` | `-f` | Output format: json, yaml, md, sarif, text |
| `--verbose` | `-v` | Verbose output |
| `--quiet` | `-q` | Quiet mode (findings only) |
| `--no-color` | | Disable colored output |
| `--no-llm` | | Disable LLM analysis |
| `--provider` | | LLM provider override |

### Examples

```bash
# Basic scan
chainsmith scan example.com

# With exclusions
chainsmith scan example.com -e admin.example.com

# Specific suites
chainsmith scan example.com -s network -s ai

# Specific checks
chainsmith scan example.com -c mcp_discovery -c mcp_tool_enumeration

# Scenario mode
chainsmith scan fakobanko.local --scenario fakobanko

# Export to YAML
chainsmith scan example.com -o report.yaml -f yaml

# CI mode
chainsmith scan example.com -f sarif -o results.sarif -q --no-color

# Scan without LLM features
chainsmith scan example.com --no-llm
```

---

## list-checks

List available checks.

```bash
chainsmith list-checks [OPTIONS]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--suite` | `-s` | Filter by suite |
| `--verbose` | `-v` | Show detailed info |
| `--deps` | | Show dependencies |
| `--json` | | Output as JSON |

### Examples

```bash
# All checks
chainsmith list-checks

# MCP suite only
chainsmith list-checks -s mcp

# With details
chainsmith list-checks -s agent --verbose

# JSON output
chainsmith list-checks --json
```

---

## suites

List available check suites.

```bash
chainsmith suites [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

### Example Output

```
Check Suites
Execution order: network → web → ai → mcp → agent → rag → cag

network (2 checks)
  Checks: dns_enumeration, service_probe

mcp (2 checks)
  Runs after: network
  Checks: mcp_discovery, mcp_tool_enumeration
```

---

## scenarios list

List available scenarios.

```bash
chainsmith scenarios list [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

---

## scenarios info

Show scenario details.

```bash
chainsmith scenarios info NAME
```

---

## export

Export findings to various formats.

```bash
chainsmith export [OPTIONS]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--format` | `-f` | Output format |
| `--output` | `-o` | Output file |

---

## serve

Start the web UI server.

```bash
chainsmith serve [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--host` | Bind address (default: 127.0.0.1) |
| `--port` | Port number (default: 8000) |
