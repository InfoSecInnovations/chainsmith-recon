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
| B-3 | **`ServiceIteratingCheck.run` keeps only the last service's list outputs.** `result.outputs.update(...)` overwrites `chat_endpoints`, `rag_endpoints`, `cag_endpoints`, `mcp_servers`. Found by reading the code; not yet reproduced in a scan. | `app/checks/base.py` | S |
| B-4 | **`web_favicon` grader crashes on non-latin-1 bodies.** `_md5_of` does `body.encode("latin-1")`, and fakobanko pages carry emoji, so 4 observations per full scan end up `grading_failed`. | `app/checks/web/web_favicon/check.py` | XS |
| B-5 | **`chainsmith.sh start` exits 1 after `up` for every non-ollama profile.** The trailing `[ ... = "ollama" ] && pull_ollama_model` is false under `set -e`, so the health wait never runs. | `chainsmith.sh` | XS |
| B-6 | **~36 checks can mint duplicate observation ids** when a host has two or more matching endpoints, or the same hostname is on two ports. `ObservationWriter` now drops only the colliding row and warns. See decision D-2. | `ai_*` per-endpoint checks, several `cag_*` / `agent_*` / `web_*` / `network_*` | M |
| B-7 | **Fakobanko range plants almost nothing.** Session-key mismatch and related range bugs were fixed in the SEC536 lab edition but never ported back. | see [`lab-backports.md`](lab-backports.md) | M |
| B-8 | Three phase 57 hash mismatches make `rag_corpus_poisoning`, `rag_multimodal_injection` and `web_mass_assignment` unreproducible from the corpus. | see [`phase57-evidence-and-capture.md`](phase57-evidence-and-capture.md) §0 | S |
| B-9 | **Most scenario simulations silently do nothing.** `apply_scenario` swaps in a simulation only when its `emulates:` equals a current check name. Simulation YAMLs still use pre-rename names (`dns_enumeration`, `header_analysis`, `llm_endpoint_discovery`, …). 84 of the 133 distinct emulated names match no check (counted 2026-10-11), so the real check runs instead and nothing is logged. Some names predate the rename map (e.g. `agent_callback`). | `scenarios/*/simulations/*.yaml`, `app/checks/simulator/simulations/`, `app/check_resolver.py`. Rename with `.phase56/rename-map.yaml` plus a hand pass, add a test that every `emulates:` resolves, and add the warning in [`lab-backports.md`](lab-backports.md) 2c | M |
| B-10 | **`--provider` / `--no-llm` probably have no effect.** They set an environment variable in the CLI process, but LLM work runs in the server. `docs/getting-started/configuration.md` documents the caveat. | `app/cli.py` | S |
| B-11 | **Version mismatch.** The CLI reports 1.3.0 (`click.version_option`), while `pyproject.toml` says 1.2.0. CHANGELOG has an `[Unreleased]` section ready to become the release. | `app/cli.py`, `pyproject.toml` | XS |
| B-12 | **`dev new-check` scaffolds a contract that fails `verify-contracts`** (`severity-undeclared`), because the template has no `severity:` block. | `app/dev/` scaffold template | XS |

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
| D-1 | What to do about residual B-1 exposure until inline scope lands | (a) set `max_concurrent_scans: 1`; (b) accept the residual | (a) if more than one person or script shares an instance |
| D-2 | Duplicate observation ids (B-6) | (1) a guard in the grading stage that gives colliding ids a stable suffix and warns; (2) per-check fixes; (3) rely on the writer | (1) |
| D-3 | `web_mass_assignment` reproducibility | (A) drop the fake header and read the injected field back from the recorded body; (B) actually send the header | (A) |
| D-4 | Phase 57 criterion 6 | close it on the `--capture-failures` pair, or wait for a pair that includes a transient failure | close it |
| D-5 | Concurrent scans at the cap | queue, or reject with 429 (current behavior) | — |
| D-6 | Custom (student) checks that fail to import | stop all discovery (current behavior), or log and skip the one bad check, as the lab edition does | log and skip |
