# Phase 46: Fakobanko Semantic Cache Service

## Overview

Add a real semantic-cache (CAG) service to the fakobanko scenario so
the CAG check suite has something to fingerprint. Today
`cache.fakobanko.local` is an alias that points at the ml_serving
container, which causes every CAG check beyond discovery to skip
with "CAG not found on target".

## Motivation

Surfaced during the fakobanko end-to-end validation (April 2026):
after fixing the Guardian scope bug and service-probe race, every
suite fired cleanly *except* CAG — 1 completed, 16 skipped. Root
cause isn't in the scanner; it's that the scenario has no cache
service to find. Adding one closes the coverage gap and gives us a
realistic target for cache-poisoning / prompt-leak checks.

## Target Changes

### New container: `cache-server`
- Lightweight FastAPI service exposing a minimal semantic-cache API:
  - `GET /health` → basic liveness
  - `POST /cache/query` → {query, embedding} → {hit, response,
    similarity_score}
  - `POST /cache/store` → {query, response, embedding}
  - `GET /cache/stats` → entry count, hit rate
  - `GET /.well-known/cag.json` or similar advertisement so
    `cag_discovery` can fingerprint it deterministically.
- In-memory dict backing store seeded with a few plausible
  banking-FAQ entries so later checks (cache probing, prompt leak)
  have material to work with.
- Listens on a new port (suggest `8090`) under a new
  `cache`/`cag` compose profile.

### `scenarios/fakobanko/docker-compose.yml`
- New service block for `cache-server` with profile `cag`.
- Remove the current `cache.fakobanko.local` alias from the
  `ml_serving` service — the alias is what causes false-positive
  discovery today.
- Add `cache.fakobanko.local` alias to the new `cache-server`
  container on the `chainsmith-shared` network.

### `scenarios/fakobanko/randomize.json`
- Add `cag` to at least one `chain_packages` bundle so
  `--randomize` can roll it in. Keep it off the default bundle if we
  want CAG coverage to remain opt-in.

### Check fingerprint signals
- Ensure the service advertises headers and body content that
  `app/checks/cag/discovery.py` already looks for (review that
  file's classifier before picking response shapes).

## Test Plan

- Start fakobanko with the `cag` profile and confirm
  `cache.fakobanko.local:8090/health` responds.
- Run a full scan; `cag_discovery` should complete, and the 16
  previously-skipped CAG checks should run (pass/fail is fine —
  we just want them to execute).
- Confirm `ml_serving` still answers on `ml.fakobanko.local` with
  the alias removed.

## Out of Scope

- Building a production-grade semantic cache — this is a scenario
  prop, not a reusable service.
- Adding caches to other scenarios (warhawk, nanomed, etc.) — those
  can copy this pattern later if needed.
