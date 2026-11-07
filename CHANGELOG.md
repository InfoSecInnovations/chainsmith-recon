# Changelog

All notable changes to Chainsmith Recon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Probe/grade check model** — every one of the 133 built-in checks is now split into a probe (sends traffic, records the exchange, judges nothing) and a grader (re-reads the recorded response and returns verdicts with severity, confidence, reasoning, and evidence references)
- **Evidence capture** — optional recording of raw request/response pairs into the workspace (`scan --capture`, with `--capture-protocol`, `--capture-full`, and `--capture-failures`); off by default
- **Offline re-grading** — `chainsmith dev regrade <scan_id>` replays graders over a captured scan and shows the diff; `--apply` writes the new verdicts back, keeping replaced observations as *superseded* (excluded from counts, listed in the technical report)
- **Workspaces** — one directory per body of work holding its database, evidence, reports, scratch files, logs, and customizations; selected with `--workspace`, `CHAINSMITH_WORKSPACE`, or `workspace:` in `chainsmith.yaml` (default `~/chainsmith/default`)
- **Folder-per-component layout** — each check, agent, advisor, and gate lives in its own folder with a `contract.yaml` (identity, dependencies, outputs, and severity model), a `config.yaml` (tunables), and co-located tests; discovered automatically with no manual registry
- **Scan presets** — `quick`, `thorough`, `passive`, and `ai-focused` (`scan --preset`), defined in `app/data/presets.yaml`
- **Custom checks** — organization-specific check folders in `app/checks/custom/`, discovered like built-in checks
- **Developer tooling** — `chainsmith dev new-check`, `verify-contracts`, `show-config`, `diff-registry`, and `migrate-check`
- **Concurrent scans** — several scans can run at once (`concurrency.max_concurrent_scans`, default 1 until scope moves inline onto the scan request), with per-scan pause/resume/stop endpoints and a scan selector in the web UI
- **Live scan streaming** — Server-Sent Events at `GET /api/v1/scans/{scan_id}/stream`
- Adjudicator agent for evidence-based severity review
- Triage agent for prioritized remediation planning
- Researcher and Coach agents, and the CheckProof advisor for reproduction steps
- Operator chat with a prompt router that dispatches questions to the right agent
- Guided mode for operators who want more explanation and proactive suggestions
- Scan history with comparison, trends, and per-observation overrides (accepted risk, false positive)
- Technical, executive, compliance, delta, and trend reports (Markdown, JSON, HTML, PDF, SARIF, CSV), saved to a reports directory
- CSV export, compliance framework tags on observations, timeline timestamps, benchmark bar chart, and "why skipped" coverage view
- Guardian enforcement of the scope's scan time window
- Per-check severity and scan customizations
- Expanded `fakobanko` and `demo-domain` scenarios

### Changed
- Check names now carry their suite prefix (e.g. `dns_enumeration` → `network_dns_enumeration`, `cors_check` → `web_cors`); MCP, agent, RAG, and CAG checks keep their existing `mcp_`/`agent_`/`rag_`/`cag_` names. Update any `-c`/`--checks` arguments, saved presets, and simulation `emulates:` fields
- Each check's severity is declared in its `contract.yaml` (`fixed` or `contextual` model)
- `on_critical` (`annotate`, `skip_downstream`, `stop`) is enforced per check
- "Findings" renamed to "observations" throughout the API, database, and UI
- The database is the source of truth for scan data; API routes read from it rather than in-memory state
- All API routes versioned under `/api/v1/`
- Observations carry an explicit `target_host`
- Timestamps handled as UTC throughout
- Agent and advisor configuration moved into each component's own `config.yaml`
- Scout agent replaced by the scan advisor; steward agent folded into the Chainsmith agent
- Observations whose ids would collide within one check (for example, one per chat endpoint on the same host) are now kept and renamed with a stable suffix, with a warning. Previously the database dropped all but the first
- A custom check that fails its contract or fails to import is logged and skipped. It no longer stops all check discovery
- `web_mass_assignment` no longer records a request header it never sent, so it can be re-graded from captured evidence
- A scan rejected at the concurrent-scan cap (429) now carries a `Retry-After` header (`concurrency.retry_after_seconds`, default 30)
- `chainsmith dev new-check` scaffolds a probe/grade check with a `severity:` block, so it passes `verify-contracts` and the coverage tests

### Fixed
- Checks that iterate over services kept only the last service's list outputs (`chat_endpoints`, `rag_endpoints`, `cag_endpoints`, `mcp_servers`); downstream checks now see every service
- `web_favicon` no longer fails grading on pages with non-latin-1 characters
- `chainsmith.sh start` no longer exits 1 before the health wait on non-ollama profiles

### Removed
- Engagements, replaced by workspaces and scan history
- Python 3.11 support (Python 3.12+ required)

## [1.2.0] - 2026-04-03

### Added
- CAG (Cache-Augmented Generation) check suite
- RAG (Retrieval-Augmented Generation) check suite
- Agent discovery and testing checks
- MCP (Model Context Protocol) server discovery checks
- Adversarial input, guardrail consistency, jailbreak, streaming, and output format AI checks
- Chain orchestrator for dependency-aware check execution
- Swarm mode for distributed check execution
- Scenario system with session-based finding randomization
- Persistence layer (SQLite) for scan history, findings, and trend data
- Scout agent for automated reconnaissance workflows
- Engagement management UI

### Changed
- Enhanced chain creation logic with LLM-assisted rule generation
- Expanded built-in chain execution rules
- Streamlined findings and trend views

### Fixed
- Replaced debug print statements with proper logging
- Removed dev-only `--reload` flag from production Dockerfile

## [1.0.0] - 2026-03-01

### Added
- Initial release
- Network, web, and AI check suites
- FastAPI-based scan engine with WebSocket progress
- Docker Compose deployment
- HTML dashboard (scan, findings, reports, trend views)
