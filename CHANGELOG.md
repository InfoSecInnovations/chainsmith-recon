# Changelog

All notable changes to Chainsmith Recon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
