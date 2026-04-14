# Phase 47 — Raw Check I/O Capture

## Goal

Persist the raw request/response payloads emitted by checks so the scan-history
**Log** tab can show exactly what went over the wire, not just curated evidence
strings derived from observations.

## Motivation

Today `check_log` stores only metadata (check name, event, observations count,
duration, error). Observations carry an `evidence` text field and a `raw_data`
JSON blob, but both are *curated* — the check decides what to surface. For
debugging a check, triaging a false positive, or reproducing a finding outside
Chainsmith, operators want the unfiltered HTTP exchange.

The Log tab was reworked in Phase 46 to group observations under their parent
check. This phase adds the missing raw-I/O layer.

## Scope

1. **Schema**
   - New table `check_io` (one-to-many with `check_log`), columns:
     - `id`, `scan_id`, `check_name`, `sequence` (int, within the check run)
     - `request_method`, `request_url`, `request_headers` (JSON), `request_body` (text/blob)
     - `response_status`, `response_headers` (JSON), `response_body` (text/blob)
     - `duration_ms`, `timestamp`, `error` (text, nullable)
   - Alembic migration.
   - Size cap per row (e.g. 256 KB body; truncate + flag).

2. **Check runner plumbing**
   - Provide a shared HTTP client wrapper that emits I/O records.
   - Opt-in flag per check so non-HTTP checks (dns, traceroute) can skip or emit
     their own structured equivalents.
   - Decision needed: capture **every** request (port_scan, dns_enumeration can
     be huge) or **only requests linked to observations**. Recommended default:
     only observation-linked requests, with a scan setting to enable full capture.

3. **API**
   - `GET /api/v1/scans/{scan_id}/check-io?check={name}` → list of I/O records for one check.
   - Optional inline-include on `GET .../log` when a `?include=io` flag is set.

4. **UI**
   - Extend the Log tab's per-check `<details>` section with a "Raw I/O" block
     listing request/response pairs, each collapsible, with syntax-highlighted
     bodies (JSON pretty-print, HTML escaping).
   - "Copy as curl" button per request.

5. **Retention / redaction**
   - Redaction pass on capture (strip `Authorization`, `Cookie`, known token
     patterns) with a setting to disable for local engagements.
   - Retention policy aligned with scan retention; consider a separate
     `io_retention_days` setting since bodies are the bulky part.

## Open questions

- Binary response bodies — store base64 with a content-type hint, or skip?
- Streaming responses (SSE, long polls) — capture first N bytes + a marker?
- Do we want to capture I/O from swarm agents' remote checks too? Requires
  propagating the capture flag and piping records back through the agent API.

## Non-goals

- Not a full packet capture. TLS-terminated HTTP only.
- Not a replay tool (that's a later phase on top of this).
