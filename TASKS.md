# Tasks

Things only you can do: commits, decisions, live smoke tests. After those comes the next enhancement round.
Written 2026-10-11 after the cleanup pass. The detail behind each item is in
[`docs/future-ideas/open-issues.md`](docs/future-ideas/open-issues.md) and
[`docs/future-ideas/README.md`](docs/future-ideas/README.md).

---

## 1. Housekeeping (do first)

- [ ] **Move `ssh-info.txt` out of the repo.** It holds a plaintext password. It is now gitignored, but it is still in the working tree.
- [ ] **Commit the uncommitted work in reviewable chunks.** There are about 600 entries in `git status`. Suggested order:
  1. `ruff format` only (169 files, no logic changes). Doing this first keeps the later diffs readable.
  2. Phase 57 core: `app/workspace.py`, `app/capture/`, `app/grading/`, `app/lib/evidence.py` → `evidence_fmt.py` (use `git add -A app/lib` so git records the rename), and their tests.
  3. Phase 57 check migration: `app/checks/**`.
  4. Hygiene pass: phase-reference cleanup, the un-skipped simulator tests, and vendored d3 (`static/js/vendor/`).
  5. Docs: README, CONTRIBUTING, CHANGELOG, `docs/**`, and the `docs/future-ideas/` reorganization.
- [ ] **Decide what to do with `.phase56/`.** `registry-baseline.json` and `fakobanko-netweb-baseline.json` are still used by `dev diff-registry`. `rename-map.yaml` will be needed for B-9 (below). `_find_oversweep.py` is scratch and is now gitignored.
- [ ] **Decide whether `.vscode/` should be committed.** `docs/getting-started/launching-from-vscode.md` relies on it, but it is gitignored.
- [ ] **Consider adding a `.gitattributes`** (`* text=auto eol=lf`) to stop the CRLF/LF warnings. Do it in its own commit, because it may renormalize files.
- [ ] **Pin ruff in CI** (`.github/`). CI installs it unpinned, so a new ruff release can fail the format check with no code change.

## 2. Decisions waiting on you

| # | Decision | Recommendation |
|---|---|---|
| D-1 | Set `max_concurrent_scans: 1` until inline scope lands, or accept the residual mis-scope risk? | Set it to 1 if more than one person or script shares an instance |
| D-2 | Duplicate observation ids (~36 checks): a grading-stage guard, per-check fixes, or rely on the writer? | Grading-stage guard |
| D-3 | `web_mass_assignment` reproducibility: read the injected field from the body (A), or actually send the header (B)? | A |
| D-4 | Phase 57 criterion 6: close it on the `--capture-failures` pair, or wait for a transient failure? | Close it |
| D-5 | Concurrent scans at the cap: queue, or reject with 429 (current behavior)? | — |
| D-6 | A custom check that fails to import: stop all discovery (current), or log and skip it like the lab? | Log and skip |
| — | Version: release as 1.3.0? The CLI already says 1.3.0; `pyproject.toml` says 1.2.0. | Bump `pyproject.toml` and cut `[Unreleased]` → `[1.3.0]` |
| — | Is `docs.chainsmith.io` real? Three UI pages link to it. | If not, point the links at the repo docs |
| — | Web UI has 6 nav pages; the lab's 3 feel tighter. Merge trend and scan-history into reports? | — |

## 3. Live smoke tests (never run by a human)

- [ ] WebUI check-parameter editing: detail modal, preset selector, `include_disabled` toggle, save-as-default.
- [ ] Superseded observation rows in the WebUI.
- [ ] Observations and trend pages load **offline** now that d3 is vendored.
- [ ] Full fakobanko scan after the lab backports land. Expect many more observations than today.

## 4. Next enhancement round

Work in this order. Each item links to its doc.

### Correctness first
- [ ] **Lab backports §1–2:** range session activation, the `internal.py` crash, scenario hosts, and the `expected_findings` key. See [`lab-backports.md`](docs/future-ideas/lab-backports.md). Until this lands, fakobanko scans undercount.
- [ ] **B-9:** rename simulation `emulates:` names to the current check names (84 of 133 match nothing). Add a test that every name resolves, and a warning in `apply_scenario`.
- [ ] **B-3:** `ServiceIteratingCheck` keeps only the last service's list outputs (`app/checks/base.py`).
- [ ] **B-4:** `web_favicon` crashes on non-latin-1 bodies.
- [ ] **B-5:** `chainsmith.sh start` exits 1 for non-ollama profiles.
- [ ] **B-10:** `--provider` / `--no-llm` only affect the CLI process, not the server.
- [ ] **B-12:** `dev new-check` scaffold has no `severity:` block, so it fails `verify-contracts`.
- [ ] Implement the D-2 choice.
- [ ] **Lab backports §3–4:**
  - MCP JSON-RPC `tools/list`, plus SQL and money-movement risk patterns.
  - `ai` service type on the web checks.
  - Log `result.errors`.
  - Save rule chains before the LLM pass, with a timeout.
  - Linkify references.
  - Show `skip_reason`.

### Then
- [ ] **Finish phase 57:** hash-mismatch fixes, then retention (this unlocks turning capture on by default). See [`phase57-evidence-and-capture.md`](docs/future-ideas/phase57-evidence-and-capture.md) §0.
- [ ] **Concurrency:** inline scope on `POST /api/v1/scan` and remove `POST /api/v1/scope`. Then finish the scan-selector UI and add per-scan swarm coordinators. See [`concurrent-scans.md`](docs/future-ideas/concurrent-scans.md).
- [ ] **Small features:** [compliance framework selector](docs/future-ideas/compliance-framework-selector.md), then the [lab edition build target](docs/future-ideas/lab-edition.md).
- [ ] **Module track:** module system, then the phase 55 SSE client, then the terminal dashboard, then the reporter and scope wizard.
- [ ] **Phase 58 AI grading**, then the [adversarial-AI checks](docs/future-ideas/checks-adversarial-ai.md).

### Leftover polish (low priority)
- [ ] 26 remaining "Phase NN" references in `app/capture`, `app/grading`, `app/db` and nearby. Each needs its sentence rewritten.
- [ ] The `plan-*.md` docs still use "Phase N" headings for their rollout steps.
- [ ] Verify the `docs/scenarios/fakobanko.md` "~23 observations" breakdown against a real scan, after the backports.
