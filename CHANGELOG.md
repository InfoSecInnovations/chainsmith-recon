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
- Evidence retention: `storage.evidence_retention_days` (off by default) prunes old captured evidence at server start and daily; `chainsmith evidence prune [--older-than N] [--dry-run]`
- `dev regrade` reports `CONFIG DRIFT` when a check's config, especially its severity block, changed since the scan
- Check references render as links in the check detail view, and skipped checks show why
- A semantic cache on fakobanko's ML service (`/semantic-cache`, `/cache/stats`) for the CAG suite, with planted cross-session leakage and timing observations

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
- The fakobanko range now activates its planted observations: range sessions derive them, seeded by the session id, so every container agrees; `start-range.sh` resumes an existing session and creates it before containers start; the internal portal no longer crashes when wildcard CORS is active; range scripts ignore inherited `COMPOSE_FILE`/`COMPOSE_PROJECT_NAME`
- Request bodies sent as bytes are captured as text, not their Python repr, and multipart probes record the headers they send, so `rag_corpus_poisoning`, `rag_multimodal_injection` and `cag_serialization` can be re-graded from captured evidence
- Errors a check reports for individual targets are now logged
- Rule-based attack chains are saved before the LLM chain pass, which now times out (`chains.llm_timeout_seconds`, default 300), so a slow model no longer hides every chain
- `POST /api/v1/scan` takes the scope inline and requires `target`; a scan never reads the global scope, so concurrent clients cannot mis-scope each other (`POST /api/v1/scope` remains, as planning input for the advisor and chat). `chainsmith scan --scope FILE` sends a YAML/JSON scope with the scan
- The proof-of-scope traffic log is written (it never was): every request a check sends, with its scope status, and every attempt Guardian blocks, per scan
- Deleting a scan deletes its captured evidence documents; `scratch-to-db` no longer fails on rows diverted for an id collision
- The web UI's "block exclusions" and "log violations" settings take effect; one-sided scan windows are accepted
- MCP tool enumeration posts `tools/list` as a JSON-RPC method to `/mcp` (and similar) first, and classifies raw-SQL and money-movement tools as critical; 12 web checks now also run on `ai` hosts; `cag_discovery` no longer lists an endpoint twice
- `--provider`/`--no-llm` warn when a running server will ignore them; a 429 at the scan cap prints when to retry
- Scenario simulations use current check names, so they apply again; fakobanko and demo-domain observation lists match what their services actually plant, and demo-domain containers share one session
- Scenario `expected_findings` are loaded (the loader only read `expected_observations`), fakobanko's host list matches its containers, and simulations that match no check are logged

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
