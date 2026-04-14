# Phase 49 — Observability Expansion

## Goal

Make Chainsmith's runtime behavior legible while it's running and after it's
done. Operators and developers should be able to answer "what is the system
doing right now?" and "what did it do during scan X?" without reading code or
tailing raw logs.

Phase 48 (oversight) describes what the code *is*. This phase instruments what
the code *does*.

## Motivation

Current runtime visibility is partial:

- `check_log` records per-check outcomes (expanded in Phase 47 with raw I/O).
- Scan history stores observations and wave state.
- Application logs are unstructured prints/loguru in mixed formats.
- No metrics surface. No single place to watch a live scan at a system level.
- Swarm agent health is inferred from whether work completes.

Symptoms: debugging slow scans means reconstructing timelines by hand;
diagnosing a stuck wave means reading source to know which state to inspect;
swarm problems surface only when a check silently fails to run.

## Scope

### Workstream A — Structured logging

1. Standardize on a single structured logger (JSON lines) with fixed fields:
   `ts`, `level`, `scan_id`, `check`, `agent`, `component`, `event`, `msg`.
2. Log levels with documented meaning (DEBUG/INFO/WARN/ERROR + what each
   means in Chainsmith specifically).
3. Correlation IDs: every scan, wave, and check run gets an ID that threads
   through all related log lines.
4. Log sinks: stdout (container-friendly), rotating file, optional forward to
   an external collector (config-gated).

### Workstream B — Metrics

1. Prometheus-compatible `/metrics` endpoint.
2. Core metrics:
   - `chainsmith_scan_active` (gauge), `chainsmith_scan_duration_seconds`
     (histogram), `chainsmith_scan_total{status}` (counter).
   - `chainsmith_check_duration_seconds{check}` (histogram),
     `chainsmith_check_errors_total{check,reason}`.
   - `chainsmith_wave_duration_seconds{wave}`.
   - `chainsmith_observations_total{severity}`.
   - `chainsmith_swarm_agents{status}`, `chainsmith_swarm_jobs_inflight`.
3. Example Grafana dashboards committed under `docs/observability/dashboards/`.

### Workstream C — Scan telemetry (in-product)

1. Live scan view: active wave, in-flight checks, queue depth, agent
   assignments, elapsed/projected time.
2. Timeline view per scan: Gantt-style chart of waves and checks, mapping
   observations to the check run that produced them.
3. Leverages Phase 47 raw I/O — drill from a timeline bar into the raw
   request/response.

### Workstream D — Runtime introspection

1. `GET /api/v1/debug/state` (auth-gated): current ScanContext snapshot, swarm
   roster, queue state. Meant for operators, not UI.
2. Health endpoint split: `/healthz` (liveness, cheap) vs `/readyz`
   (readiness: DB reachable, migrations current, swarm coordinator responsive).
3. Agent heartbeat surface: last-seen, current job, version, capability tags.
   Feeds the swarm metrics and a swarm-status panel in the UI.

### Workstream E — Error + panic capture

1. Unhandled exceptions route through the structured logger with full context
   (scan/check/agent IDs) and increment a metric.
2. Optional Sentry/equivalent integration, env-gated.
3. Redaction applied before anything leaves the process (reuse Phase 47
   redaction rules).

## Deliverables

- `chainsmith/logging.py` — structured logger module + migration of existing
  call sites.
- `/metrics` endpoint + metrics registry module.
- Live scan view + timeline view in the scan detail UI.
- `/api/v1/debug/state`, `/healthz`, `/readyz`.
- `docs/observability/` — logging field reference, metrics catalog, dashboard
  JSON, operator runbook for common alerts.

## Sequencing

1. Structured logging (cross-cutting prerequisite; everything else emits logs).
2. Health endpoint split (cheap, unblocks container orchestration).
3. Metrics endpoint + core metrics.
4. Runtime introspection endpoints.
5. Live scan + timeline UI.
6. Dashboards, runbook, error-capture integration.

## Open questions

- Metrics backend assumption: Prometheus pull, or push to OTLP? Prometheus is
  simpler; OTLP is more portable. Probably Prometheus + an OTLP adapter later.
- Do swarm agents export their own `/metrics` (scraped individually) or
  push metrics through the coordinator? Individual scraping is more standard
  but requires network reachability back to agents.
- Timeline UI: build on the existing D3 modules (Phase 10) or a lighter
  charting lib? D3 has the skills; it's heavier than needed for Gantt.
- Retention for structured logs — tie to scan retention, or separate?

## Non-goals

- Distributed tracing (OpenTelemetry spans). Worth a later phase if
  cross-agent latency becomes a problem; not needed now.
- Log analytics UI inside Chainsmith. Export to a real tool for that.
- APM / profiling integration.

## Dependencies

- Phase 47 (raw check I/O) — timeline drill-down relies on it.
- Phase 48 (oversight) — module contracts should name the events each module
  emits, so the logging field reference isn't invented in isolation.
