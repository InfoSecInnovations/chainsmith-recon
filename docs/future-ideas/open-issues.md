# Open Issues and Pending Decisions

**Status:** Live list. These are bugs and decisions, not proposals, so fix them before starting new feature work.
**Last reviewed:** 2026-10-11
**Source:** carried forward from `audits/next-steps-2026-09-15.txt`

---

## Bugs

| # | Issue | Where | Size |
|---|---|---|---|
| B-1 | **Fixed 2026-11-07** (concurrent-scans §2.1): `POST /api/v1/scan` requires `target` and takes the whole scope inline; a scan never reads scope prep. CLI and web UI send scope with the scan; `chainsmith scan --scope FILE`. `POST /api/v1/scope` was **kept** as planning input for the scan planner advisor and chat (D-7). **Scope can still be set globally between "set scope" and "start scan".** The CLI's two-step flow can create a mis-scoped session at request time. `run_scan()` itself is fixed (2026-09-10). | `app/routes/scope.py`, `app/cli_client.py`; fix in [`concurrent-scans.md`](concurrent-scans.md) §2.1 | M |
| B-2 | **Fixed 2026-11-07.** The violation half was already scan-scoped; the traffic log was never written at all (no caller), so every report claimed 0 requests. The HTTP client now logs each request a check sends (scope status from the scan's Guardian), and Guardian logs blocked attempts as `excluded` plus a violation. Swarm traffic is not logged (O-4 gap). **Compliance statistics aggregate across concurrent scans.** `violation_logger` / `traffic_logger` are process singletons writing one JSONL file with no `scan_id` per record. The scope half of the report is correct; the counts are not. | `app/proof_of_scope.py` | S–M |
| B-3 | **Fixed 2026-11-07:** list outputs now accumulate across services (`merge_service_outputs`, deduplicated; non-list outputs still last-wins). **`ServiceIteratingCheck.run` kept only the last service's list outputs.** `result.outputs.update(...)` overwrites `chat_endpoints`, `rag_endpoints`, `cag_endpoints`, `mcp_servers`. Found by reading the code; not yet reproduced in a scan. | `app/checks/base.py` | S |
| B-4 | **Fixed 2026-11-07:** falls back to UTF-8, so the body grades as an unidentified favicon. **`web_favicon` grader crashed on non-latin-1 bodies.** `_md5_of` does `body.encode("latin-1")`, and fakobanko pages carry emoji, so 4 observations per full scan end up `grading_failed`. | `app/checks/web/web_favicon/check.py` | XS |
| B-5 | **Fixed 2026-11-07:** the ollama guards are `if` blocks. **`chainsmith.sh start` exited 1 after `up` for every non-ollama profile.** The trailing `[ ... = "ollama" ] && pull_ollama_model` is false under `set -e`, so the health wait never runs. | `chainsmith.sh` | XS |
| B-6 | **Mitigated 2026-11-07 by the D-2 guard.** ~36 checks can mint duplicate observation ids when a host has two or more matching endpoints, or the same hostname is on two ports. The grading stage now renames colliders (D-2). Per-check discriminator fixes are still the cleaner long-term answer. The writer remains the backstop for collisions across separate check results, such as swarm tasks. | `ai_*` per-endpoint checks, several `cag_*` / `agent_*` / `web_*` / `network_*` | M |
| B-7 | **Further fixed 2026-11-07:** fakobanko and demo-domain observation-id lists reconciled with the services' gates (tests enforce it); demo-domain containers now share one session (they read a different env var than compose set). Remaining: ~100 ids removed from the lists are range features never built, and 4 chain packages can never complete (lab-backports.md). **Partly fixed 2026-11-07** (lab-backports §1–2; not yet validated on the VM). Remaining: the observation-id vocabulary drift that lab-backports.md now lists. **Fakobanko range planted almost nothing.** Session-key mismatch and related range bugs were fixed in the SEC536 lab edition but never ported back. | see [`lab-backports.md`](lab-backports.md) | M |
| B-8 | **Fixed 2026-11-07.** One shared body rule (`app.lib.http.request_body_text`) for the interceptor and `exchange_from_response(request_data=)`, and the probes now record the headers they send. Covers `rag_corpus_poisoning`, `rag_multimodal_injection` and, as a latent case, `cag_serialization`. Old corpora keep the `b'...'` text. Not yet re-measured on the VM. (`web_mass_assignment` fixed by D-3.) | see [`phase57-evidence-and-capture.md`](phase57-evidence-and-capture.md) §0 | S |
| B-9 | **Fixed 2026-11-07:** 83 stale `emulates:` names renamed across 139 YAMLs, `rag.`/`cache.` hosts renamed, `tests/scanning/test_simulation_names.py` enforces it. One known unresolved (`invocation_safety`, a helper not a check). **Most scenario simulations silently do nothing.** `apply_scenario` swaps in a simulation only when its `emulates:` equals a current check name. Simulation YAMLs still use pre-rename names (`dns_enumeration`, `header_analysis`, `llm_endpoint_discovery`, …). 84 of the 133 distinct emulated names match no check (counted 2026-10-11), so the real check runs instead and nothing is logged. Some names predate the rename map (e.g. `agent_callback`). | `scenarios/*/simulations/*.yaml`, `app/checks/simulator/simulations/`, `app/check_resolver.py`. Rename with `.phase56/rename-map.yaml` plus a hand pass, add a test that every `emulates:` resolves, and add the warning in [`lab-backports.md`](lab-backports.md) 2c | M |
| B-10 | **Fixed 2026-11-07:** the flags do work when the CLI starts the server (it inherits the env); when a server was already running the CLI now warns and points at `prefs set llm.provider`. **`--provider` / `--no-llm` probably have no effect.** They set an environment variable in the CLI process, but LLM work runs in the server. `docs/getting-started/configuration.md` documents the caveat. | `app/cli.py` | S |
| B-11 | **Fixed 2026-11-07:** `pyproject.toml` is now 1.3.0. Cutting CHANGELOG `[Unreleased]` → `[1.3.0]` is still open. **Version mismatch.** The CLI reports 1.3.0 (`click.version_option`), while `pyproject.toml` says 1.2.0. CHANGELOG has an `[Unreleased]` section ready to become the release. | `app/cli.py`, `pyproject.toml` | XS |
| B-12 | **Fixed 2026-11-07:** the template declares `severity: {model: fixed, default: info}`, and the check template is now probe/grade (has `grade()`). Tested in `tests/checks/test_scaffold_gates.py`. **`dev new-check` scaffolded a contract that failed `verify-contracts`** (`severity-undeclared`), because the template has no `severity:` block. | `app/dev/` scaffold template | XS |

## Unverified

- **2026-11-07 UI changes, JS syntax-checked only:** starting a scan from the index page now sends scope inline (B-1); reference links in the check modal (4d); skip reasons on scan.html (4e); "Rules only" chain status badge (4b).
- **The fakobanko range after the observation-id reconciliation and semantic cache** has not been scanned. Expect many more observations, CAG checks running, MCP tools found as critical.
- **56.17 WebUI param editing** has never had a live smoke test by the operator. The JS was only syntax-checked. To exercise: the detail modal, the preset selector, the `include_disabled` toggle, and save-as-default.
- **Superseded rows in the WebUI** have not been smoke-tested live. The fix is the API default.
- `test_run_with_latency` timing flake: 0.0892 s against a 0.09 s floor.

## Doc drift

- None known. (`docs/vocabulary.md` now mentions engagements only as the history of workspaces.)

## Fixed 2026-11-07, found while working (no prior issue number)

- **Deleting a scan left its evidence documents on disk** (raw client traffic). `DELETE /api/v1/scans/{id}` now removes them.
- **`scratch-to-db` crashed on rows the writer diverted for an id collision** (UNIQUE constraint), and its dedupe fingerprint used a different host field than stored rows. Now one fingerprint helper, and colliding ids get a stable suffix.
- **The web UI's "block exclusions" / "log violations" toggles never took effect** (dropped by validation, then read with `hasattr`).
- **A one-sided scan window** (start only / end only) failed validation; via the old scope route it was silently lost.
- **`mcp_tool_enumeration`** could raise on a JSON scalar response body.

---

## Decisions pending

| # | Question | Options | Recommendation |
|---|---|---|---|
| D-1 | Residual B-1 exposure until inline scope lands | **Decided 2026-11-07: (a).** `max_concurrent_scans` defaults to 1 (`app/config.py`) |
| D-2 | Duplicate observation ids (B-6) | **Decided 2026-11-07: (1), built.** `claim_observation_id` in `app/grading/stage.py`. The first observation keeps its bare id. Later ones get a short hash of their target URL, or an ordinal when the URL also collides. A warning is logged. `dev regrade` reproduces the same ids |
| D-3 | `web_mass_assignment` reproducibility | **Decided 2026-11-07: (A), built.** No fake header. The injected field is read back as the recorded body's last key |
| D-4 | Phase 57 criterion 6 | **Decided 2026-11-07: closed** on the `--capture-failures` pair |
| D-5 | Concurrent scans at the cap | **Decided 2026-11-07: keep 429, built.** It now sends `Retry-After` (`concurrency.retry_after_seconds`, default 30). Queuing can be revisited after inline scope |
| D-7 | `POST /api/v1/scope` after inline scope (B-1) | (a) keep it as planning input for the scan planner advisor and chat (built); (b) remove it, as concurrent-scans §2.1 decided, and give the advisor its own scope input | (a) for now: removing it breaks pre-scan planning |
| D-8 | `storage.retention_days` (365) claims to auto-delete scans, but nothing enforces it | enforce it (deletes scan data automatically), set it to 0 and document, or remove the setting | — your call; evidence retention is separate and off by default |
| D-9 | Six gates activate only when a chain needing them is selected (`cors_wildcard`, `framework_fingerprint`, `model_config_exposed`, `no_auth_internal`, `no_rate_limit`, `rag_endpoint_exposed`) | add them to fakobanko's `random_pool`, or keep them chain-only | — |
| D-10 | `max_concurrent_scans` is 1 (D-1) until inline scope landed, which it now has | raise the default back (it was 4), or keep 1 | — |
| D-6 | Custom (student) checks that fail to import | **Decided 2026-11-07: log and skip, built.** Covers both contract violations and import/construction errors, for the `custom` suite only (`app/component_loader.py`) |
