# CLI Commands

## Global Options

These options apply to all commands and must appear before the command name.

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help and exit |
| `--server` | API server address (default: 127.0.0.1:8000). Use `127.0.0.1:8100` for the Docker stack — see [Server Address](overview.md#server-address) |
| `--profile` | Activate a scan behavior profile (e.g., aggressive, stealth) |
| `--workspace` | Workspace directory that owns the database, evidence, logs, and reports (default: `~/chainsmith/default`, or `$CHAINSMITH_WORKSPACE`) |

```bash
# Example: scan the Docker stack
chainsmith --server 127.0.0.1:8100 scan example.com

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
| `--scope` | | YAML/JSON scope file (exclude, techniques, scan_window, proof_of_scope), sent with the scan |
| `--checks` | `-c` | Run specific checks by name (repeatable) |
| `--suite` | `-s` | Run checks from suite (repeatable) |
| `--scenario` | | Load scenario for simulated scanning |
| `--parallel` | | Run checks in parallel within phases |
| `--plan` | | Show execution plan and exit |
| `--dry-run` | | Validate config without running |
| `--output` | `-o` | Output file path |
| `--format` | `-f` | Output format: json, yaml, md, sarif, csv, text (default: text) |
| `--verbose` | `-v` | Verbose output |
| `--quiet` | `-q` | Quiet mode (observations only) |
| `--no-color` | | Disable colored output |
| `--no-llm` | | Disable LLM analysis |
| `--provider` | | LLM provider override: openai, anthropic, litellm, none |
| `--port-profile` | | Port scan profile: web, ai, full, lab |
| `--preset` | | Named scan preset: quick, thorough, passive, ai-focused. Explicit `--suite`/`--checks`/`--port-profile` override it |
| `--capture` | | Record evidence (raw request/response pairs) into the workspace. Off by default |
| `--capture-protocol` | | Protocols to record (repeatable): http, dns, tcp, tls, whois, icmp, llm, local. Default: http and llm |
| `--capture-full` | | Record every exchange, overriding each check's own capture policy |
| `--capture-failures` | | Also record probes that never completed, with the transport error |

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

# Passive preset (drops intrusive checks)
chainsmith scan example.com --preset passive

# Record evidence for later review or re-grading
chainsmith scan example.com --capture

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

network (13 checks)
  Checks: network_banner_grab, network_dns_enumeration, network_dns_records, network_geoip, ... (+9 more)

web (23 checks)
  Checks: web_auth_detection, web_config_exposure, web_cookie_security, web_cors, ... (+19 more)
...
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

Export observations from a saved JSON observations file to another format.

```bash
chainsmith export [OPTIONS]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--format` | `-f` | Output format: json, md, sarif, csv (default: json) |
| `--output` | `-o` | Output file |
| `--input` | `-i` | Input JSON observations file |

---

## serve

Start the API server and web UI natively (without Docker).

```bash
chainsmith serve [OPTIONS]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--host` | | Bind address (default: 127.0.0.1) |
| `--port` | `-p` | Port number (default: 8000) |
| `--reload` | | Enable auto-reload for development |
| `--coordinator` | | Enable swarm coordinator mode |

A natively served instance listens on port 8000, which matches the CLI's default
`--server`. The Docker stack started by `./chainsmith.sh start` publishes the same
server on host port 8100 instead.

---

## scans

Browse and manage saved scans. See [Working with Saved Scans](../working-with-saved-scans.md).

| Command | Description |
|---------|-------------|
| `scans list [-t TARGET] [-n LIMIT] [--json]` | List saved scans |
| `scans show SCAN_ID [--json]` | Show one scan |
| `scans compare SCAN_A SCAN_B [--json]` | Compare two scans |
| `scans delete SCAN_ID [-y]` | Delete a scan |
| `scans trend -t TARGET [--json]` | Observation trend for a target |

---

## observations

Track the status of individual observations across scans, by fingerprint.

| Command | Description |
|---------|-------------|
| `observations accept FINGERPRINT [-r REASON]` | Mark as accepted risk |
| `observations false-positive FINGERPRINT [-r REASON]` | Mark as false positive |
| `observations reopen FINGERPRINT` | Remove an override |
| `observations overrides [-s STATUS] [--json]` | List overrides (STATUS: accepted, false_positive) |

---

## report

Generate reports from saved scans. Every generator accepts `--format/-f`
(md, json, html, pdf, sarif, csv; default md) and `--output/-o`.
PDF output requires the optional `pdf` extra (`pip install -e ".[pdf]"`).

| Command | Description |
|---------|-------------|
| `report technical --scan SCAN_ID` | Full technical report |
| `report executive --scan SCAN_ID` | Executive summary |
| `report compliance --scan SCAN_ID` | Compliance-oriented report |
| `report delta --scan-a A --scan-b B` | Changes between two scans |
| `report trend --target TARGET` | Trend across scans of one target |
| `report list [-t TYPE] [-n LIMIT]` | List saved reports in the reports directory |

---

## prefs

View and change persistent preferences and scan behavior profiles.

| Command | Description |
|---------|-------------|
| `prefs show [KEY] [--advanced] [--json]` | Show preferences |
| `prefs set KEY VALUE` | Set a preference |
| `prefs reset [KEY] [--all] [-y]` | Reset preferences |
| `prefs path` | Show where preferences are stored |
| `prefs profile <list, show, create, activate, delete, reset, copy>` | Manage profiles |

---

## swarm

Distributed scanning. See [Swarm Mode](../swarm-usage.md).

| Command | Description |
|---------|-------------|
| `swarm generate-key --name NAME` | Create an agent API key |
| `swarm list-keys` | List API keys |
| `swarm revoke-key KEY_ID` | Revoke an API key |
| `swarm agent --coordinator URL --key KEY [--name NAME] [-s SUITE] [--max-concurrent N]` | Run a swarm agent |
| `swarm status` | Show coordinator swarm status |

---

## scratch-list / scratch-to-db

Recover scans that were written to scratch directories but not imported into the database.

| Command | Description |
|---------|-------------|
| `scratch-list` | List scratch directories |
| `scratch-to-db [SCAN_ID] [--all] [--dry-run] [--keep]` | Import scratch data into the database |
