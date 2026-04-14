# Phase 45: Observation `target_host` Field

## Overview

Add a `target_host` field to the `Observation` model so observations
carry the hostname of whatever they describe, independent of whether
a full URL or `Service` was passed as the target. Today observations
created from `Service` objects without a scheme/url (e.g. raw TCP
port-scan hits) end up with a `null` host in exports and the UI.

## Motivation

Surfaced during the fakobanko scan debug (April 2026): port-scan
observations displayed `host: null` even though the scan clearly
knew which host the port belonged to. Root cause — `Observation` only
stores `target_url` and `target_service`, and `create_observation()`
derives the host from the URL. Services without a URL lose the host.

This is a real data-quality gap:

1. **Reports are harder to read.** Triage and the WebUI group by
   host; `null` rows float to the top and look broken.
2. **Downstream correlation breaks.** Attack-chain building and
   dedup logic that wants "all observations on host X" has to
   reparse `target_url` and fall back to `target_service`.
3. **Network-layer checks have the host but no URL.** Port scans,
   service probes on closed ports, and DNS enumeration all know the
   host before any URL exists. The model should let them say so.

## Target Changes

### `app/models.py`
- Add `target_host: str | None = None` to `Observation` alongside
  `target_url` / `target_service`.
- Document in the field comment that `target_host` is the canonical
  host identifier and should be set whenever known, even if
  `target_url` is also set.

### `app/checks/base.py` — `create_observation()`
- Accept an explicit `host` argument.
- When `target` is a `Service`, populate `target_host` from
  `service.host` directly (not parsed from URL).
- When `target` is a URL string, extract host via `urlparse` and set
  `target_host` in addition to `target_url`.
- When neither is provided but `host=` is passed, use it.

### Call sites
- Audit checks that pass raw hostnames (port_scan, dns_enumeration,
  service_probe fallbacks) and ensure `host=` or a `Service` with
  `.host` set is threaded through.

### Exports / UI
- `app/api/routes/observations.py` response already serializes model
  fields — no route change needed.
- WebUI observation list: display `target_host` as the primary host
  column, falling back to the URL-parsed value for old records.

## Migration

No DB migration needed — `Observation` is serialized as JSON blobs in
the scan artifacts. Older scans will have `target_host = None`; the
UI fallback handles that.

## Test Plan

- Unit: `create_observation(target=Service(host="x", port=8080))`
  yields `target_host="x"` with no URL.
- Unit: `create_observation(target="https://x:8080/path")` yields
  `target_host="x"` and `target_url` populated.
- Integration: re-run fakobanko scenario and confirm port_scan
  observations no longer show `null` host.

## Out of Scope

- Renaming `target_url` / `target_service` — keep for backward
  compatibility.
- Changing export schemas beyond adding the new optional field.
