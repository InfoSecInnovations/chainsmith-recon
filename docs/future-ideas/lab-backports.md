# Lab Edition Backports

**Status:** Nearly done. §1, §2, 3a–3d, §4 and the §5 tests marked below are done (2026-11-07). Left: 3e (needs the live range), and VM validation of all of it
**Track:** Range / checks correctness
**Depends on:** nothing
**Related:** [`lab-edition.md`](lab-edition.md), which is the longer-term fix: generating the lab from main so this drift cannot recur
**Last reviewed:** 2026-10-11 (each item verified against code in main)

In August 2026 the SEC536 lab 1.2 snapshot received a round of bug fixes and polish. That snapshot is an
older trim of main. Most of the fixes target code that main still has, so main carries the same bugs.
This doc lists what still needs porting. Lab notes: `post-beta/RESUME-HERE-1.2.md` and
`post-beta/work/plans/1.2-*.md` in the course workspace.

Main renamed *findings* to *observations* in the range services (`active_observations`,
`is_observation_active`), so the lab's names have been mapped across.

---

## 1. Range: planted observations never activate (port together)

**Done 2026-11-07.** The lab's fixed code was not available (only the March pre-fix snapshot
under `536/pre-alpha/Labs/Labs/1.2`), so each item was built from this table. 1a/1b:
`resolve_active_observations` and `session_from_file_data` in
`app/scenario_services/common/config.py`. A session file with no `active_observations` key
derives one, and a legacy `extra_findings` list is folded in, so the old committed
`scenarios/fakobanko/data/session.json` plants observations too. 1c: start-range creates the session
before any container starts, resumes an existing one, and loads profiles on resume. 1d: done at
import time. 1e: all three scripts. Tests: `tests/scanning/test_range_backports.py`.

This is the headline lab bug. Without it, the fakobanko range runs with almost every planted
vulnerability switched off, and the guided walkthrough hides that because it mostly exercises surface
that is always on.

| Item | Problem in main | Fix |
|---|---|---|
| 1a | `range/start-range.sh` writes `extra_findings`, but `scenario_services/common/config.py` reads `active_observations` (default `[]`). `get_or_create_session()` accepts an existing file as-is, so after `--randomize` no gated observation is active. | Remove the `extra_findings` lines. Derive `active_observations` in Python (1b). Add a test that round-trips the file start-range writes through `from_dict` and asserts the list is non-empty. |
| 1b | The selection uses the unseeded global `random` and ignores `selected_chains[].required_findings`. | Add `resolve_active_observations(config, session_id, selected_chains)`: `rng = random.Random(session_id)`; take the certain observations, then `rng.sample` from the pool, then each selected package's required observations, then an order-stable dedupe. Seeding by session id means every container agrees on the result without a lock, and a session id reproduces its range. |
| 1c | start-range re-rolls the session on every start, and the profile loop only runs inside the randomize branch. | Resume the session if the file already exists. Move the profile loop after the `fi` so it also runs on resume, and use `.active_services[]?`. |
| 1d | `scenario_services/corporate/internal.py` calls `add_middleware` inside a startup handler, which Starlette forbids. This is latent today, but fixing 1a will make the container crash-loop whenever `cors_wildcard` is active. | Call `add_middleware` at module level, guarded by `is_observation_active("cors_wildcard")`. |
| 1e | `range/*.sh` inherit `COMPOSE_FILE` / `COMPOSE_PROJECT_NAME` from the caller's shell. | `unset` them at the top of start, stop and reset. |

## 2. Scenario data

**Done 2026-11-07.** 2a: `rag`→`vector` and `cache`→`ml` (going by the compose ports; both stay as network
aliases), `internal` and `admin` added to `services`. 2d was built from the spec, not ported: a
token-overlap cache on `ml` at `/semantic-cache` and `/cache/stats`. Phase 46 asked for a separate
container instead, see that doc.

| Item | Problem in main | Fix |
|---|---|---|
| 2a | `scenarios/fakobanko/scenario.json` `known_hosts` lists `rag` and `cache`, which do not exist, and leaves out `ml`, `internal`, `admin` and `vector`, which do. `expected_findings` uses the wrong hosts. | Set `known_hosts` to `www, chat, api, docs, ml, internal, admin, vector, agent, mcp`, and rewrite the expected hosts. Add a test that compares `known_hosts` with the compose `hostname:` lines. |
| 2b | `app/scenarios.py` reads `expected_observations`, but every scenario.json uses `expected_findings`, so the expected list is never loaded. | Accept either key. |
| 2c | `apply_scenario` silently drops simulations that match no check. Main has about 130 fakobanko simulation YAMLs and suite-prefixed names, so a typo stays invisible. | Warn on `set(sims) - set(checks)`. |
| 2d | The CAG suite has nothing real to probe (also [`phase46-fakobanko-semantic-cache.md`](phase46-fakobanko-semantic-cache.md)). | Port the lab's semantic cache routes in `ai/ml_serving.py` (token-overlap cache, gated on `no_session_isolation` / `cache_timing_leak`, ungated discovery). This may let phase 46 shrink to just that. |

## 3. Checks

| Item | Problem in main | Fix |
|---|---|---|
| 3a | **Done 2026-11-07.** `mcp_tool_enumeration` POSTs to `/tools/list`-style URL paths. `tools/list` is a JSON-RPC *method*; the range serves only POST `/mcp`. | POST the JSON-RPC `tools/list` payload to `/mcp`, `/rpc`, `/jsonrpc`, `/messages` and `/` first, then fall back to the path probes. |
| 3b | **Done 2026-11-07.** `mcp_tool_enumeration` risk patterns have nothing for SQL or money movement, which are the range's `run_sql` and `execute_transfer`. | Add critical patterns `(run\|exec(ute)?\|eval)_?(sql\|query)`, `(^\|_)sql(_\|$)`, and `(transfer\|wire\|payment\|payout\|remit\|refund\|withdraw\|disburse)`. |
| 3c | **Done 2026-11-07** (12 checks; `web_favicon`/`web_sri` stay HTML-only). `web_robots_txt`, plus about nine other web checks, leave `ai` out of `service_types`, so they never run on a vLLM host. | Add `ai` to `check.py` and `contract.yaml`. Add a test that a vLLM header classifies as `ai` and robots still runs. |
| 3d | **Done 2026-11-07.** `cag_discovery` lists five paths in both `_PATH_TO_TYPE` and `CAG_PATHS`, so `cag_endpoints` gets duplicates. | Skip the second entry for a path already added. |
| 3e | `agent_discovery` paths leave out the agent's GET routes (`/config`, `/sessions`, `/memory`, `/tools`). | Verify against the live range, and add them if needed. |

## 4. Engine and operator UX

| Item | Problem in main | Fix |
|---|---|---|
| 4a | **Done 2026-11-07.** `check_launcher._run_check` never logged `result.errors`. Only the swarm path forwarded them. | Logs a warning with the count and the first error. |
| 4b | **Done 2026-11-07.** Rule-based chains were saved only after the LLM chain pass, which had no timeout. A slow model hid every chain. | Rule chains are saved first, and the DB status is `rules_done` (the in-memory session stays `analyzing`, the routes' guard). The LLM pass is bounded by `chains.llm_timeout_seconds` (default 300). A timeout is a retryable failure, so the scan ends `partial`. The UI shows `rules_done` as "Rules only". |
| 4c | `observations.html` and `trend.html` load D3 from a CDN, so they break offline (classrooms, air-gapped engagements). | Vendor `d3.v7.min.js` and `d3-sankey.min.js` under `static/js/vendor/`. |
| 4d | **Done 2026-11-07.** Observation references render as plain text (`static/js/api.js`). | Render them as links. |
| 4e | **Done 2026-11-07.** `scan.html` never shows `skip_reason` (the API sends it), and `determineCurrentPhase` does not count `skipped` as reached. | Show the reason in the check row, and treat skipped as reached. |
| 4f | **Done 2026-11-07 (D-6).** A custom check that fails to import, or fails its contract, used to stop **all** discovery. | `discover_components` now logs and skips the bad `custom` check. A custom check that reuses a built-in name or UUID is the one skipped. Built-in failures still raise. |

## 5. Tests the lab has and main lacks

- Session file round-trip (the active observations are non-empty). **Done:** `tests/scanning/test_range_backports.py`.
- Service-type coverage (every web check runs on `ai` hosts). **Done:** `tests/checks/test_web_service_types.py`.
- Expected observations are reachable. Needs a recorded scan; not done.
- `known_hosts` matches the compose hostnames. **Done.**
- (Added) every listed observation id is a gate: `tests/scanning/test_range_observation_ids.py`, `test_demo_domain_range.py`.
- Chain rules fire against a recorded real scan.

## Found while doing §1–2 (not in the lab)

- **Observation-id vocabulary drift.** `scenario.json`'s `certain`/`random_pool` and the ids the
  services gate on (`is_observation_active(...)`) have diverged. Many pool ids gate nothing, and
  dozens of gated ids are in no list, so nothing can switch them on. `randomize.json`'s
  `random_findings_pool` is no longer read. Some of its gated ids (`cookie_security_missing`,
  `customer_lookup_tool`, `namespace_leak`, …) should move into `scenario.json`'s `random_pool`. Needs
  a reconciliation pass and a test that every pool id gates something.
- Simulation YAMLs still name `rag.`/`cache.` hosts (part of B-9).

Also: `mcp_sampling_abuse`'s "missing" corpus exchange is its `local` capabilities record. `local` is not captured by default, so this is expected (like `mcp_server_fingerprint`).

## Not fixed in either edition

- `agent_goal_injection` POSTs to endpoints that only accept GET.
- `network_port_scan` observation ids are awkward.
- `scenarios/fakobanko/*.py` holds dead files.
