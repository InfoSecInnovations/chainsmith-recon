# Open Issues and Pending Decisions

**Status:** Live list. These are bugs and decisions, not proposals, so fix them before starting new feature work.
**Last reviewed:** 2026-10-11
**Source:** carried forward from `audits/next-steps-2026-09-15.txt`

---

## Bugs

| # | Issue | Where | Size |
|---|---|---|---|
| B-1 | **Scope can still be set globally between "set scope" and "start scan".** The CLI's two-step flow can create a mis-scoped session at request time. `run_scan()` itself is fixed (2026-09-10). | `app/routes/scope.py`, `app/cli_client.py`; fix in [`concurrent-scans.md`](concurrent-scans.md) §2.1 | M |
| B-2 | **Compliance statistics aggregate across concurrent scans.** `violation_logger` / `traffic_logger` are process singletons writing one JSONL file with no `scan_id` per record. The scope half of the report is correct; the counts are not. | `app/proof_of_scope.py` | S–M |
| B-3 | **Fixed 2026-11-07:** list outputs now accumulate across services (`merge_service_outputs`, deduplicated; non-list outputs still last-wins). **`ServiceIteratingCheck.run` kept only the last service's list outputs.** `result.outputs.update(...)` overwrites `chat_endpoints`, `rag_endpoints`, `cag_endpoints`, `mcp_servers`. Found by reading the code; not yet reproduced in a scan. | `app/checks/base.py` | S |
| B-4 | **Fixed 2026-11-07:** falls back to UTF-8, so the body grades as an unidentified favicon. **`web_favicon` grader crashed on non-latin-1 bodies.** `_md5_of` does `body.encode("latin-1")`, and fakobanko pages carry emoji, so 4 observations per full scan end up `grading_failed`. | `app/checks/web/web_favicon/check.py` | XS |
| B-5 | **Fixed 2026-11-07:** the ollama guards are `if` blocks. **`chainsmith.sh start` exited 1 after `up` for every non-ollama profile.** The trailing `[ ... = "ollama" ] && pull_ollama_model` is false under `set -e`, so the health wait never runs. | `chainsmith.sh` | XS |
| B-6 | **Mitigated 2026-11-07 by the D-2 guard.** ~36 checks can mint duplicate observation ids when a host has two or more matching endpoints, or the same hostname is on two ports. The grading stage now renames colliders (D-2). Per-check discriminator fixes are still the cleaner long-term answer. The writer remains the backstop for collisions across separate check results, such as swarm tasks. | `ai_*` per-endpoint checks, several `cag_*` / `agent_*` / `web_*` / `network_*` | M |
| B-7 | **Fakobanko range plants almost nothing.** Session-key mismatch and related range bugs were fixed in the SEC536 lab edition but never ported back. | see [`lab-backports.md`](lab-backports.md) | M |
| B-8 | Two phase 57 hash mismatches make `rag_corpus_poisoning` and `rag_multimodal_injection` unreproducible from the corpus. (`web_mass_assignment` fixed by D-3.) | see [`phase57-evidence-and-capture.md`](phase57-evidence-and-capture.md) §0 | S |
| B-9 | **Most scenario simulations silently do nothing.** `apply_scenario` swaps in a simulation only when its `emulates:` equals a current check name. Simulation YAMLs still use pre-rename names (`dns_enumeration`, `header_analysis`, `llm_endpoint_discovery`, …). 84 of the 133 distinct emulated names match no check (counted 2026-10-11), so the real check runs instead and nothing is logged. Some names predate the rename map (e.g. `agent_callback`). | `scenarios/*/simulations/*.yaml`, `app/checks/simulator/simulations/`, `app/check_resolver.py`. Rename with `.phase56/rename-map.yaml` plus a hand pass, add a test that every `emulates:` resolves, and add the warning in [`lab-backports.md`](lab-backports.md) 2c | M |
| B-10 | **`--provider` / `--no-llm` probably have no effect.** They set an environment variable in the CLI process, but LLM work runs in the server. `docs/getting-started/configuration.md` documents the caveat. | `app/cli.py` | S |
| B-11 | **Fixed 2026-11-07:** `pyproject.toml` is now 1.3.0. Cutting CHANGELOG `[Unreleased]` → `[1.3.0]` is still open. **Version mismatch.** The CLI reports 1.3.0 (`click.version_option`), while `pyproject.toml` says 1.2.0. CHANGELOG has an `[Unreleased]` section ready to become the release. | `app/cli.py`, `pyproject.toml` | XS |
| B-12 | **Fixed 2026-11-07:** the template declares `severity: {model: fixed, default: info}`, and the check template is now probe/grade (has `grade()`). Tested in `tests/checks/test_scaffold_gates.py`. **`dev new-check` scaffolded a contract that failed `verify-contracts`** (`severity-undeclared`), because the template has no `severity:` block. | `app/dev/` scaffold template | XS |

## Unverified

- **56.17 WebUI param editing** has never had a live smoke test by the operator. The JS was only syntax-checked. To exercise: the detail modal, the preset selector, the `include_disabled` toggle, and save-as-default.
- **Superseded rows in the WebUI** have not been smoke-tested live. The fix is the API default.
- `test_run_with_latency` timing flake: 0.0892 s against a 0.09 s floor.

## Doc drift

- `docs/vocabulary.md` still documents **Engagement**, which was removed in phase 52.

---

## Decisions pending

| # | Question | Options | Recommendation |
|---|---|---|---|
| D-1 | Residual B-1 exposure until inline scope lands | **Decided 2026-11-07: (a).** `max_concurrent_scans` defaults to 1 (`app/config.py`) |
| D-2 | Duplicate observation ids (B-6) | **Decided 2026-11-07: (1), built.** `claim_observation_id` in `app/grading/stage.py`. The first observation keeps its bare id. Later ones get a short hash of their target URL, or an ordinal when the URL also collides. A warning is logged. `dev regrade` reproduces the same ids |
| D-3 | `web_mass_assignment` reproducibility | **Decided 2026-11-07: (A), built.** No fake header. The injected field is read back as the recorded body's last key |
| D-4 | Phase 57 criterion 6 | **Decided 2026-11-07: closed** on the `--capture-failures` pair |
| D-5 | Concurrent scans at the cap | **Decided 2026-11-07: keep 429, built.** It now sends `Retry-After` (`concurrency.retry_after_seconds`, default 30). Queuing can be revisited after inline scope |
| D-6 | Custom (student) checks that fail to import | **Decided 2026-11-07: log and skip, built.** Covers both contract violations and import/construction errors, for the `custom` suite only (`app/component_loader.py`) |
