# Quick Start

To get a running instance (Docker, `.env`, `./chainsmith.sh start`), follow the
canonical [QUICKSTART.md](../../QUICKSTART.md) at the repository root. This page
picks up from there and walks through your first scans from the CLI.

The `chainsmith` CLI is a client: it talks to a running Chainsmith server. With
the Docker stack from QUICKSTART.md, the server is published on port **8100**, so
pass `--server 127.0.0.1:8100` (the examples below omit it for brevity). If you
run the server natively with `chainsmith serve`, it listens on `127.0.0.1:8000`,
which is the CLI's default. See [CLI Overview](../cli/overview.md#server-address).

## Your First Scan

```bash
chainsmith --server 127.0.0.1:8100 scan example.com
```

This runs all 133 checks in dependency order across the seven suites:

1. **Network**: DNS enumeration → port scan → service probe, plus TLS, banners, WHOIS
2. **Web**: Headers, robots.txt, CORS, OpenAPI, paths, exposed configs
3. **AI**: LLM endpoints, embeddings, prompt leakage, jailbreaks, filters
4. **MCP / Agent / RAG / CAG**: Specialized AI infrastructure checks

Checks whose prerequisites never appear (for example, no chat endpoint was found)
are skipped automatically.

## View the Execution Plan

```bash
chainsmith scan example.com --plan
```

Shows which checks would run, in what order, without sending any traffic.

## Narrow the Scan

```bash
# Just network and web
chainsmith scan example.com --suite network --suite web

# Specific checks
chainsmith scan example.com -c network_dns_enumeration -c ai_llm_endpoint_discovery

# A named preset (quick, thorough, passive, ai-focused)
chainsmith scan example.com --preset passive
```

## Export Observations

```bash
chainsmith scan example.com -o report.json -f json     # also: yaml, md, sarif, csv, text
```

## Use a Scenario (Simulated Target)

For training or testing without live targets:

```bash
chainsmith scan fakobanko.local --scenario fakobanko
```

## Explore Checks

```bash
chainsmith suites                         # suites and execution order
chainsmith list-checks --suite mcp -v     # checks in one suite, with detail
chainsmith list-checks --deps             # with dependencies
```

## Next Steps

- [CLI Reference](../cli/commands.md) — every command and option
- [Configuration](configuration.md) — scope, profiles, presets
- [Check Reference](../checks/overview.md) — what each check does
- [Working with Saved Scans](../working-with-saved-scans.md) — history, comparison, reports
