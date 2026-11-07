# Phase 57 — Implementation Log (57.1–57.4)

**Status:** Archive. Split out of [`../phase57-evidence-and-capture.md`](../phase57-evidence-and-capture.md) on 2026-10-11, where it was §0.
**Use:** the as-built record of 57.1–57.4. Section numbers (§0.1–§0.22) are unchanged, so "§0.x"
references in the design doc and elsewhere resolve here.

---

## 0. Implementation status

*Last updated 2026-09-12 (57.4 complete — probe/grade migration across all suites, the §8 exit condition enforced, §0.19, the offline re-grade pass, §0.20, and superseded rows handled in reports, reads and history, §0.21). This section is the handoff: it says what exists in the
tree, what is wired, what is not, and what has to be decided next. Sections 1-13
are the design and are written in the future tense; this one is written in the
past tense and wins where they disagree.*

### 0.1 Where the rollout stands

| Sub-phase | State |
|---|---|
| **57.1a** Workspace root + path rooting | **Done** |
| **57.1b** `workspace.yaml` as config layer 5 | **Done** |
| **57.2** Evidence capture | **Done, off by default** (§0.4). All six §0.5 items landed; D-20 settled; **D-21 measured** (§0.22): ~9.7 MB per full fakobanko scan |
| **57.3** Probe/grade framework | **Done** (§0.9). `Candidate` / `Evidence` / `Verdict` / `GradeContext`, the grading stage, grading state on the observation, the candidate binding, the §2 suppression corollary, and `web_header_analysis` migrated as the pilot |
| **57.4** `contract.yaml` severity + fixed migration | **Wave 1 done** (§0.10). **Probe/grade migration done** (§0.12–§0.18): all seven suites — `network` (13), `web` (23), `ai` (28), `agent` (17), `rag` (17), `cag` (17), `mcp` (18), 133 checks — migrated, plus the capture plumbing the migration needed. **§8's exit condition enforced** (§0.19): `severity-undeclared` for built-in checks, a suite-wide probe/grade guard, criteria 1 and 4 asserted in a scan. **Offline re-grade pass built** (§0.20): `chainsmith dev regrade <scan_id>`, criterion 4's second half. **Superseded rows handled** (§0.21): excluded from counts, stated in reports, status history rebuilt on `--apply`. Open gaps in §0.11 |
| **57.5** Evidence encryption | Not started (floats; does not block 57.3/57.4) |

**Gates at last run (after §0.22):** `pytest` 2846 passed / 5 skipped / 1 timing
flake (`test_run_with_latency`: 0.0892 s against a 0.09 s floor; passed 5/5 when
re-run alone) (the 5 skips are
pre-existing missing-simulation skips), `ruff check` clean,
`dev verify-contracts` OK.

*`ruff format --check` reports 18 files it would reformat. All 18 predate 57.4
and none is a file this phase touched; the project's gate is `ruff check`.*

`dev diff-registry --compare .phase56/registry-baseline.json` reports DRIFT, but
it is **entirely the 56.7 suite-prefix rename** — 52 names in, the same 52
prefixed out. Nothing from phase 57. The baseline is stale, and re-baselining is
an operator decision rather than a phase-57 task.

### 0.2 What 57.1 built

**`app/workspace.py`** (new) — `Workspace` dataclass, four-level precedence
(`--workspace` then `CHAINSMITH_WORKSPACE` then `workspace:` in chainsmith.yaml
then `~/chainsmith/default`), `legacy_conflicts()`, `legacy_db_notice()`,
`load_workspace_config()`, and the process-wide `set_workspace()` /
`get_workspace()` / `active()`.

Rooted off the workspace: the database (`config.py` `_apply_workspace`),
proof-of-scope logs into `logs/` (`proof_of_scope.py`), reports (`cli.py`
`_get_reports_dir`), scratch (`db/writers.py` `scratch_dir()`), and
customizations / severity overrides (`customizations.py`). `PathsConfig.db_path`
deleted. `--workspace` added to the CLI group; `app/main.py` logs the active
workspace at startup.

Three implementation notes that are not obvious from the design sections:

- **The three proof-of-scope logger singletons and `SCRATCH_DIR` became lazy.**
  They are constructed at import, long before an entry point selects a
  workspace, so a module-level constant would have frozen the pre-workspace path.
- **An installed workspace beats re-resolution.** `_apply_workspace` defers to
  `workspace.active()`. Without that, the first `get_config()` after
  `chainsmith --workspace X` re-resolved from env/default and silently discarded
  the flag — the operator was shown one workspace and scanned into another.
  Regression test: `test_an_installed_workspace_survives_load_config`.
- **The CLI workspace banner is TTY-gated.** An unconditional stderr banner
  landed in the output of `list-checks --json`, `export`, and friends. The server
  path logs the same lines unconditionally, and a pipeline set the workspace
  explicitly anyway.

**Layer 5** — `WorkspaceConfig` in `components/config_models.py`,
`ConfigResolver(workspace_config=...)` applying it after env and tagging
provenance `workspace`, `component_loader.py` passing it in. `dev show-config`
prints the workspace and its defaults. `/api/v1/checks` needed **no change** —
provenance already flows through `ResolvedConfig`.

### 0.3 What 57.2 built

**`app/capture/`** (new package):

| Module | Holds |
|---|---|
| `protocols.py` | The 8-value `Protocol` discriminator; per-protocol volatile fields; `DEFAULT_PROTOCOLS` = http + llm |
| `models.py` | `Exchange` — one request/response pair; HTTP-shaped fields nullable; `MAX_BODY_BYTES` 256 KB |
| `context.py` | The `ContextVar` (D-19): attribution, the check's `policy`/`suite`, and the scan's `settings` |
| `hashing.py` | Normalisation (uuid / timestamp / epoch to placeholders), `probe_hash`, `content_hash`, `apply_hashes` |
| `redaction.py` | `redact()` — secret headers, token shapes, named JSON fields |
| `store.py` | `EvidenceStore` under the workspace `evidence/<scan_id>/<id>.json`; `truncate_body`, `apply_size_cap`, `delete_scan` |
| `probes.py` | `probe()` — the chokepoint for the socket and resolver checks |
| `curl.py` | `to_curl()` — one exchange as a reproducible command |
| `settings.py` | `CaptureSettings` — **`enabled=False` by default**; `from_request()`; `effective_policy()` |
| `writer.py` | `EvidenceWriter.record()` / `commit_check()` / `flush_index()`; process-wide `record()` |

**The database half.** `EvidenceRecord` (`app/db/models.py`, table `evidence`) —
scalars, both hashes, and `document_path`, FK to `scans.id` with cascade delete,
indexed on `scan_id`, `(scan_id, check_name)`, `probe_hash` and `content_hash`.
Bodies and headers stay on disk: files rather than blobs is what keeps a corpus
`rsync`-able. `EvidenceRepository` queries it; `EvidenceIndexWriter`
(`app/db/writers.py`) writes it.

**Producers wired:** the `AsyncHttpClient._request` interceptor in
`app/lib/http.py`, on both the success and failure return paths; the **9** checks
that open their own sockets, via `capture.probe(...)` (11 sites: A, AAAA, PTR ×2,
TCP banner, TLS cert + 2 version probes, `web_http2_detection`'s ALPN handshake,
traceroute, WHOIS + RDAP); and the agent LLM path in `app/lib/llm.py`.

`web_http2_detection` is the one §5.1 names that is not among the 8 executor-using
checks: its ALPN handshake is a *synchronous* call from an async method, so the
`ContextVar` is in scope and no executor boundary is crossed. It records like the
rest.

**Attribution wired:** `BaseCheck.execute()` opens the capture context;
`app/engine/scanner.py` seeds `scan_id` and the scan's `capture_settings` into
the check context dict so both are reachable from inside a check without every
check knowing about `ScanSession`.

**The read surface** (phase 47): `GET /api/v1/scans/{scan_id}/check-io`
(`check`, `protocol`, `limit`, `unredacted`), the Log-tab Raw I/O block in
`static/scan-history.html`, and copy-as-curl.

Five implementation notes:

- **The size cap is applied before hashing.** Hashing the full body and storing a
  truncated one would make `content_hash` unverifiable from the corpus, which is
  the one property it exists to provide.
- **`redact()` carries the hashes through unchanged.** They identify what was
  *captured*; recomputing them on the redacted copy would fork identity between
  what a viewer sees and what a grader graded.
- **The curl command is built server-side, from the exchange the viewer was
  shown.** A redacted view therefore yields a command carrying `<redacted>`
  rather than the operator's real bearer token. Building it in the browser would
  have meant shipping the unredacted headers to the page.
- **`record()` is synchronous and buffers its index rows.** It is called from
  inside an HTTP interceptor and from socket checks, so it cannot await the
  database. `BaseCheck.execute()` awaits `capture.flush_index()` once per check —
  one batch per check, never in the request path — and `run_scan` drains once
  more at the end for producers that run outside a check.
- **Capture is instrumented on `LLMClient.chat`, not in each provider.**
  Providers implement `_chat`; the base class times, delegates, and records. A
  client added later is covered without its author knowing capture exists.

### 0.4 Capture is off by default, deliberately

`CaptureSettings.enabled` is `False`, so **nothing writes a byte of evidence
today** and no scan's behaviour changed. Turning it on is per scan and explicit:
`--capture` on the CLI, or a `capture` block on `POST /api/v1/scan`. The
posture travels with the scan rather than sitting in a module-level singleton —
concurrent scans share one process, and one scan's `--capture` must not change
what another scan records.

Flipping the *default* waited on the §9 growth number (D-21). It is now measured
(§0.22, ~9.7 MB per full fakobanko scan), and the operator kept the default off
until retention exists.

### 0.5 What 57.2 built, item by item

All six items from the previous handoff are done:

1. **The DB row.** `EvidenceRecord` + `EvidenceRepository` + `EvidenceIndexWriter`,
   above. There is deliberately **no scratch-space fallback**, unlike
   `ObservationWriter`: by the time the index is written the document is already
   durable on disk, so an index failure costs queryability rather than the
   corpus, and the index can be rebuilt from the store.
2. **The remaining producers.** The 8 socket/resolver checks named in §0.5 of
   the previous handoff, plus `web_http2_detection` (§5.1 lists it and the old
   item did not), and the agent LLM path. Those `llm` rows are the corpus phase
   58 actually needs.
3. **The phase-47 read surface.** `GET /api/v1/scans/{scan_id}/check-io`, the
   Log-tab Raw I/O block, copy-as-curl. Redacted by default;
   `unredacted=true` is a privileged read and is logged at warning (§5.3(3)).
   A corpus whose index write failed still reads — the endpoint falls back to
   the store directory.
4. **Capture settings reachable from a scan.** `CaptureInput` on
   `ScanStartInput`; `--capture`, `--capture-protocol`, `--capture-full`,
   `--capture-failures` on the CLI; `run_scan(capture=...)` seeding the check
   context. Per-check policy is reachable the same ways `on_critical` is —
   `CheckOverride.capture` for one scan, `PUT /api/v1/checks/{name}/config` to
   persist it, and the WebUI modal for both.
5. **`scan_id` on traffic/violation records.** `TrafficEntry.scan_id` and
   `ViolationEntry.scan_id`; `Guardian` carries the scan it is gating and stamps
   its violations; `get_entries` / `get_violations` / the compliance report and
   the two compliance read routes all filter by it. A report generated *without*
   a scan id still aggregates, which is the honest answer for a workspace-wide
   report.
6. **The `evidence_fmt.py` rename** (§8.1). `EvidenceBundle` and its only
   constructor `bundle_http_response` had zero users and were deleted;
   `app/lib/evidence.py` became `app/lib/evidence_fmt.py`; 11 check modules had
   their import line repointed. The capture domain now owns the `evidence` name.

**Three gaps left open on purpose.**

- `TrafficLogger.log_request` still has **no callers** — traffic logging was
  never wired to the HTTP client. Item 5 was about making those records
  *scopeable*, and they now are; wiring the producer is separate work.
- **The swarm path is not capture-aware.** *Partly closed after 57.4 — see
  below.* A swarm task payload (`app/swarm/agent.py`) carried no explicit
  `scan_id`, so the agent-side Guardian could not stamp its window violations.
  Local scans — the default — are unaffected.

  *Closed (2026-09-12):* `SwarmTask` and `TaskPayload` now carry `scan_id`,
  stamped by the coordinator from the session. The agent treats it as
  authoritative, puts it in the check context and builds its window Guardian
  with it. Two corrections to what this bullet used to say. First, a remote
  check was **not** missing its id: the scanner puts `scan_id` in the scan
  context and the coordinator snapshots that whole dict into
  `upstream_context`, so capture attribution and grading already saw it, by
  accident rather than contract. The agent still falls back to that copy for a
  payload from an older coordinator. Second, per-check `on_critical` is **not**
  the same seam: 56.15 deferred it as a coordinator-side hook over completed
  results, and it needs no scan id (`app/swarm/runner.py` docstring). *Still
  open:* the coordinator's `--capture` posture does not reach agents (O-4).
  `capture_settings` does ride in the snapshot, but as a JSON dict, which the
  writer ignores (it honours only a `CaptureSettings` instance). So an agent
  captures by its own default — off — and whatever it does capture stays in the
  agent's store, not the scan's corpus.
- **Retention is designed, not implemented.** §5.3 says evidence "defaults to the
  workspace's lifetime" and that is true today only because nothing deletes it.
  `EvidenceStore.delete_scan` and `EvidenceRepository.delete_scan` both exist and
  are tested; no policy calls either, and no `retention` setting is read.
  Deliberate: a retention *period* is a guess until the D-21 growth number says
  what it is retaining.

### 0.6 Decisions taken

**D-20 — what gets captured. Settled: a per-check `capture:` policy.**
The §5.2 rule as written ("observation-linked exchanges by default") is not
knowable at request time, and the volume case it names — `network_port_scan`,
`network_dns_enumeration` — is already covered by protocol gating, since `tcp`
and `dns` are opt-in and off by default. What was not covered is HTTP
path-probing: `web_path_probe`, `web_config_exposure`, `web_default_creds`,
`web_debug_endpoints` and friends fire many requests each, mostly 404s, over a
protocol that captures by default. The check author knows their own volume; a
scan-level flag cannot.

So `config.yaml` gained `capture: all | observations_only | none | inherit`,
resolved through the same component → suite → global chain as `on_critical`
(default `all`) and carried to the writer on the capture context.
`CaptureSettings.full_capture` overrides it; the AI, MCP, agent, RAG and CAG
suites are never narrowed by it — that corpus is the entire point of phase 58,
and `ALWAYS_FULL_CAPTURE_SUITES` finally has a caller.

It rides everywhere `on_critical` already does, because it is the same kind of
thing — a policy about a component, not a knob an operator retunes per
engagement: the provenance block, `dev show-config`, the `config` block on
`/api/v1/checks`, the layer-6b per-scan scalpel (`CheckOverride.capture`), the
"save as default" endpoint, and the WebUI check-detail modal. Layer 5
(`workspace.yaml`) deliberately does **not** carry it, for the same reason it
does not carry `on_critical`.

**`observations_only` is run-scoped, not exchange-scoped.** Deferred writes were
rejected as a *global* mechanism; scoped to the checks that ask for them they are
exactly right, and `EvidenceWriter` holds those exchanges keyed by
`(scan_id, check_name)` until `BaseCheck.execute()` calls `commit_check()`. The
rule it commits on is *"did this run produce observations"*, so a check that
found something keeps every exchange of that run — including the ones that found
nothing, which are the context the finding sits in. **Per-exchange linkage was expected from
57.3's candidate binding and did not arrive**: the binding as built is
grade-side (D-22), and grading happens after `commit_check()` has already
decided. `observations_only` is therefore still run-scoped, and stays that way
— see D-22 for why that trade was taken knowingly. It solves the volume case the
knob was added for either way. No check ships with a non-default policy yet —
setting them is a tuning pass once the growth number exists.

**D-22 — how an exchange learns which candidate it supports. Settled: the
grade side names it.**
Two directions were possible. A probe could declare `with capture.candidate(id)`
around its requests, which gives per-exchange scoping *before* anything is
written — that is what `observations_only` would need to become exchange-scoped.
Or the grader can name the exchanges it read, and the stage stamps them
afterwards. The second was chosen: it is exact rather than declarative (the
grader knows what it actually used; a probe only knows what it intended),
it costs check authors nothing across the ~120 migrations in 57.4, and it works
for the single-shot majority whose discriminator is not knowable until the
response has been parsed — which is the whole reason parsing moved to `grade()`.

The price is paid in two places and is worth naming. `observations_only` stays
**run-scoped** (D-20), because the commit decision happens before grading. And a
binding only exists once something has graded — a corpus captured with grading
deferred has unstamped rows until it is graded. Both are recoverable later by
adding a probe-side declaration for the checks that want it; neither blocks 57.4.

`Verdict.evidence_ids` carries the join, defaulting to "everything this grader
was shown" when a grader does not narrow it.

**D-23 — where the grading stage runs. Settled: outside the check.**
`CheckLauncher` calls `grade_result()` after `execute()` returns, rather than
`BaseCheck.execute()` grading its own result. The deciding argument is that
offline re-grading and in-scan grading must be the same code path, and a stage
welded inside `execute()` makes the in-scan path the privileged one. Placing the
call *before* the launcher's severity scan keeps `on_critical` reading a graded
severity whenever a grader ran, so §6.1's provisional value is a fallback rather
than the normal input.

**D-24 — one candidate, one observation? Settled: one candidate, several
verdicts.**
§6.1 frames a Candidate and an Observation as 1:1. Held strictly, that forces a
probe to know *how many* candidates to emit, which means parsing on the probe
side — exactly what §6.2 moves to the grader — or one request per judgement. One
HTTP response carries CSP, HSTS, CORS and Server, and each is an independent
judgement. So a Candidate is the **subject** a probe recorded, `grade()` returns
a list, and each `Verdict` names its own discriminator. Identity is unchanged:
the observation id is still `{check_id}-{host}-{discriminator}`, now composed at
grade time. The 1:1 case — one probe, one judgement — is just a list of one.

**D-21 — measure before or after enabling. Measured 2026-09-12 (§0.22).**
`CaptureSettings.enabled` stays `False`. The per-scan `--capture` flag made the
measurement possible without changing the default posture. Two pairs of full
fakobanko scans put the cost at **~9.7 MB per scan** after record v2 (~13.3 MB
before). The operator kept the default off until retention exists.

### 0.7 Files touched

**Created (57.1):** `app/workspace.py`; `tests/core/test_workspace.py` (33
tests), `tests/core/test_workspace_config.py` (23).

**Created (57.2):** `app/capture/` (`__init__`, `protocols`, `models`, `context`,
`hashing`, `redaction`, `store`, `probes`, `curl`, `settings`, `writer`);
`tests/capture/test_capture.py` (92), `tests/db/test_db_evidence.py` (17),
`tests/db/test_check_io_api.py` (10), `tests/core/test_proof_scan_scoping.py` (14).

**Renamed:** `app/lib/evidence.py` → `app/lib/evidence_fmt.py`.

**Modified:** `app/config.py`, `app/cli.py`, `app/cli_client.py`, `app/main.py`,
`app/api_models.py`, `app/proof_of_scope.py`, `app/customizations.py`,
`app/db/models.py`, `app/db/repositories.py`, `app/db/writers.py`,
`app/checks/base.py`, `app/engine/scanner.py`, `app/lib/http.py`,
`app/lib/llm.py`, `app/component_loader.py`, `app/components/config_models.py`,
`app/components/config_resolver.py`, `app/scan_overrides.py`,
`app/gates/guardian/gate.py`, `app/routes/scan.py`, `app/routes/checks.py`,
`app/routes/scan_history.py`, `app/routes/compliance.py`,
the 8 socket/resolver checks under `app/checks/network/`,
`app/checks/web/web_http2_detection/check.py`, the 11 check modules importing
`evidence_fmt`; `static/js/api.js`, `static/index.html`,
`static/scan-history.html`, `static/css/scan-history.css`;
`tests/core/test_config.py`, `tests/core/test_workspace_config.py`,
`tests/db/test_db.py`, `tests/scanning/test_scan_overrides.py`,
`app/gates/guardian/tests/test_guardian.py`.

**Created (57.3):** `app/grading/` (`__init__`, `models`, `evidence`, `stage`);
`tests/grading/test_grading.py` (31).

**Modified (57.3):** `app/checks/base.py` (grading fields on `Observation`,
`CheckResult.candidates`, `create_candidate`, `provisional_severity`, the
`commit_check` condition, candidate accumulation in `ServiceIteratingCheck`),
`app/check_launcher.py` (the stage call), `app/swarm/agent.py` (the same call
before serializing), `app/capture/store.py` + `app/capture/writer.py` +
`app/capture/__init__.py` (`bind_candidate`), `app/db/models.py` +
`app/db/repositories.py` (grading columns, `bind_candidate`,
`get_for_candidate`), `app/models.py` + `app/lib/observations.py` (grading
fields across the layer boundary, `partition_by_verdict`, `suppression_note`),
`app/reports.py` + `app/engine/adjudication.py` + `app/engine/triage.py` (the §2
corollary), `app/checks/web/web_header_analysis/check.py` and its two test
modules (the pilot), `tests/db/test_db_evidence.py` (+6),
`tests/scanning/test_scans_api.py` (the observation-shape contract).

**Created (57.4 wave 1):** `tests/checks/test_severity_contract.py` (24).

**Modified (57.4 wave 1):** `app/components/contracts.py` (`SeverityLevel`,
`SEVERITY_ORDER`, `SeverityModel`, `SeverityBlock`, `CheckContract.severity`),
`app/component_loader.py` (`_verify_severity` + its call in pass 3;
`ComponentMeta.severity` and its population in `discover_component_metadata`),
`app/checks/base.py` (the `severity` class attribute and its per-instance copy,
the contract read in `from_config`, `provisional_for`, `create_candidate`),
`app/engine/scanner.py` (`severity` on `get_check_info`),
`app/routes/checks.py` (the same key on a disabled check, for shape parity),
`app/grading/models.py` (the `GradeContext.severity` note),
`app/checks/web/web_header_analysis/` (`contract.yaml` gains the first
`observations:` map; the class-level `provisional_severity` is deleted),
**and all 133 `app/checks/**/contract.yaml`** (the `severity:` declaration).

**Modified (57.4 wave 2, network suite):** `app/capture/probes.py`
(`Probe.exchange`, `record_exchange`, `_handoff`), `app/capture/__init__.py` (the
export), `app/capture/protocols.py` (the `local` comment, now that `network_geoip`
uses it), **all 13 `app/checks/network/*/check.py`** (probe/grade split), **all 13
`app/checks/network/*/contract.yaml`** (the `observations:` map and the rationale
comment), and all 13 co-located test modules (a `probe_and_grade()` helper, plus
exchange-shaped mocks where a private helper's return type changed).

Nothing was created in wave 2 — the two new tests are in
`app/checks/network/network_port_scan/tests/`, which had no run-behaviour coverage
at all before the split changed what `run()` returns.

**Schema note (57.3).** The `observations` table gained seven columns and an
index. There is no migration tooling — `Base.metadata.create_all` only — so an
existing workspace database will not grow them. Backwards compatibility is a
non-goal here (§3); a workspace predating 57.3 wants a fresh database.

**Frontend note:** the Log-tab Raw I/O block, copy-as-curl and the modal's
`capture` selector are **syntax-checked only** (`node --check` over the extracted
inline script). They have had no operator live-smoke.

**Pre-existing, not from this phase:** `app/db/repositories.py` and
`tests/db/test_db_repositories.py` fail `ruff format --check` on one line each
(`display_id[len(prefix):]`). They came from the earlier attack-chains commit and
were deliberately left alone.

### 0.8 Running the gates

Anaconda is required — the bare `python` shim on this machine routes to the
Microsoft Store installer. `conda run` also needs `CONDA_NO_PLUGINS=true` here,
or it crashes into an interactive error-report prompt and hangs.

```bash
CONDA_NO_PLUGINS=true conda run --no-capture-output python -m pytest -q
CONDA_NO_PLUGINS=true conda run --no-capture-output python -m ruff check app tests
PYTHONPATH=. CONDA_NO_PLUGINS=true conda run --no-capture-output python -m app.cli dev verify-contracts
```

Note `pytest` alone, not `pytest tests/` — per-component tests live inside the
component folders under `app/`, and `tests/` on its own misses about a thousand
of them.

### 0.9 What 57.3 built

**`app/grading/`** (new package):

| Module | Holds |
|---|---|
| `models.py` | `Candidate`, `Evidence`, `Verdict`, `GradeContext`, `GradingState`, `GradingTier` |
| `evidence.py` | `load_scan_evidence()` / `evidence_for()` — where a grader's bytes come from; `exchange_from_response()` / `exchange_from_payload()` for the probe's hand-off |
| `stage.py` | `grade_result()` — the stage itself, plus `is_graded_check()` and the binding call |

**The stage runs outside the check.** `CheckLauncher._run_one` calls
`grade_result(check, result, context)` immediately after `check.execute()`
returns, and `app/swarm/agent.py` does the same before serializing its result.
It is deliberately *not* a step inside `BaseCheck.execute()`: the function that
grades during a scan is the same one that will grade a stored corpus offline,
and welding it into the check would have made the in-scan path the privileged
one. Running it before the launcher's severity scan means `on_critical` acts on
a **graded** severity when a grader ran, and on the candidate's provisional one
when none did.

**Observations carry their own grading state** (§6.3). `Observation` — the check
dataclass, the pydantic model, the `observations` table, and both converters —
gained `provisional_severity`, `confidence`, `grading_state`, `grading_tier`,
`grading_reasoning`, `evidence_ids`, `evidence_source` and `signals`. `severity`
stays the *effective* value: graded once a grader placed it, provisional until
then, with the pre-grade value kept beside it so *"provisional low, graded high"*
is inspectable rather than a silent overwrite. No scan status was touched;
`TERMINAL_STATUSES` is untouched, as §6.3 requires.

**The candidate binding** (D-22). `EvidenceStore.bind_candidate()`,
`EvidenceWriter.bind_candidate()`, `EvidenceRepository.bind_candidate()` and
`get_for_candidate()`. The document is stamped first and the index second — the
document is the evidence — and exchanges still held by `observations_only` are
stamped in their buffer so a binding survives `commit_check()`.

**The §2 corollary landed**: `partition_by_verdict()` and `suppression_note()` in
`app/lib/observations.py`. Nothing was removing observations outright — the
Verifier only ever set a status — but adjudication and triage narrowed to
`verified` silently, and the technical report presented a rejected observation
exactly like an upheld one. Now the narrowing is logged with a count, the report
carries *"3 observations suppressed by Verifier"* and marks each one
`[SUPPRESSED — rejected]` in place, and the JSON report gained `suppressed` and
`ungraded` counts. The record still holds everything.

**The pilot.** `web_header_analysis` is split: `check_service()` sends one
request, records it, and returns a `Candidate` with a provisional `low` and no
judgment; `grade()` re-reads the recorded response and returns one `Verdict` per
judgement. The classifier moved across unchanged — a straight move, as §6.2
predicts for a single-shot check — and gained a per-judgement confidence, which
is the first place in the codebase where *"the header is absent"* (0.99) and
*"the Server header contains a digit"* (0.80) are no longer asserted identically.
Its 25 co-located tests now call a `probe_and_grade()` helper and otherwise
assert exactly what they did before.

Four implementation notes that are not obvious from the design sections:

- **Grading works with capture off**, which is the default posture (§0.4). The
  probe hands its exchanges to the candidate in memory as well as recording
  them; `evidence_for()` prefers the corpus copy — matched by `content_hash`,
  which is precisely the question that hash exists to answer — and falls back to
  the hand-off. `Evidence.source` (`corpus` / `memory` / `empty`) is on the
  observation, because a verdict graded from the corpus is reproducible and one
  graded from memory is not. Without this, 57.4 would have had to force capture
  on for everyone.
- **`commit_check` now keys on candidates too.** `BaseCheck.execute()` resolves
  `capture: observations_only` on `bool(result.observations or result.candidates)`
  — a migrated check has no observations yet at that moment, and the old
  condition would have thrown away the evidence of every check 57.4 touches.
- **`ServiceIteratingCheck` accumulates candidates** alongside observations, so
  a probe iterating services emits one per service and the stage grades them
  together.
- **A candidate may yield several verdicts** (D-24), which is a small departure
  from §6.1's 1:1 framing.

### 0.10 What 57.4 wave 1 built

57.4 was split in two on execution. **Wave 1 is the schema and the declaration**;
**wave 2 is the probe/grade migration** (§0.11). The split is not in the original
plan and is worth the sentence: bundling them per check, as §8's row describes,
would have left the *"which checks are contextual"* question — the one that
bounds phase 58 entirely — undecided until the last suite landed. Declaring it
first settles the scope now, and costs nothing, because a declaration of
`model:` + `default:` duplicates nothing the check code already owns.

**The schema.** `SeverityBlock` in `app/components/contracts.py` — `model`
(`fixed` | `contextual`), `default`, `observations`, `range`, `rubric`,
`signals`, `extra="forbid"` like every contract model — and
`CheckContract.severity`, which is **optional**: an undeclared check keeps its
class attributes and runs, because the migration is incremental and both states
have to work. `SeverityLevel` is a `Literal` of the five levels, so a typo is a
`contract-schema` parse error rather than a severity nothing renders.

**Six violation codes** in `verify_contracts`, all cross-field — shape is
pydantic's job, and pass 1 already reports it:

| Code | Rejects |
|---|---|
| `severity-contextual-without-default` | `model: contextual` with no `default:` |
| `severity-fixed-without-severities` | `model: fixed` with neither `observations:` nor `default:` |
| `severity-contextual-field-on-fixed` | `rubric` / `signals` / `range` on a fixed check |
| `severity-observations-on-contextual` | the fixed-model map on a contextual check |
| `severity-range-malformed` | a `range:` that is not `[weakest, strongest]` |
| `severity-default-outside-range` | a `default:` the declared range does not contain |

Only the first is load-bearing, and it is the one §0.10 named: `on_critical`
reads severity the moment a check finishes (56.15), long before a grader has
placed one, so a contextual check with no default takes that input away exactly
where it is used. The other five are anti-drift. `rubric` on a `fixed` check is
inert *forever* — not "inert until 58" — so an author who wrote one picked the
wrong model, and silence would leave it in the tree looking load-bearing.

**Contract → instance.** `BaseCheck.from_config` fills `severity` (the whole
declared block) and `provisional_severity` (from `default:`) from the contract,
not from `config.yaml` — §7's placement argument, held to. The class attributes
survive as the default for an undeclared contract.

**`provisional_for(discriminator)`** is what §6.1 means by *"for `model: fixed`
the provisional severity is free"*: the `observations:` map states what each
discriminator is worth, so a fixed check's probe names its subject and the
answer comes out of the contract. Precedence is explicit argument → the map →
`default:` → the class attribute, and `create_candidate` routes through it.

**The declaration, all 133 checks.** 94 `fixed`, 39 `contextual`. The contextual
set is the *attack-compliance* line: every check whose question is "did the
target comply with the payload's intent, or refuse?" — 12 `ai`, 11 `agent`,
8 `rag`, 3 `cag`, 5 `mcp`. **All of `network` and all of `web` are fixed**, as
§7.1 predicted. That set is phase 58's scope, and it is now readable off the
tree rather than inferred.

Four notes that are not obvious from the design sections:

- **Wave 1 declares `model:` and `default:` only — never the `observations:`
  map.** Until a check is split into probe/grade its code still owns
  per-observation severity, so a map declared now would be a second copy of it
  with nothing keeping the two in step. The map lands per check in wave 2,
  which is exactly when `provisional_for()` starts reading it. This is why
  `severity-fixed-without-severities` accepts a bare `default:`.
- **Wave 1 is behaviour-neutral, and that is checkable.** `default:` reaches
  runtime only through `provisional_severity`, which only `create_candidate`
  reads — and only the pilot emits candidates. Every other check still appends
  observations directly at the severities its code always used.
- **A fixed check's `default:` is the *lowest* severity it emits**, read off its
  own call sites. The pre-grade value should never over-escalate `on_critical`:
  an ungraded observation is marked ungraded and visible (§6.3), which is the
  honest failure, where a provisional `critical` that no grader confirmed would
  stop a scan on a guess.
- **Every contextual check declares `default: medium`, `range: [info, critical]`**
  — §7.2's own example, and right for the whole set: a clean refusal is `info`,
  compliance that also discloses a system prompt or credentials is `critical`.
  Deriving the range from what each check's rule tier emits today was
  considered and rejected: it would freeze the grader to what the code it is
  meant to replace happens to produce.

`rubric:` and `signals:` are declared empty. §8's exit condition asks only that
contextual checks be *declared* with `default:` live and rubric/signals inert,
and a rubric is authored content — whoever wrote the payload knows what
compliance means for it (§7.2). They are written with phase 58, against the
checks' payloads, not generated in bulk here.

### 0.11 What 57.4 wave 2 still has to do

Wave 2/3/4 is the mechanical bulk that remains: **split ~120 checks into probe
and grade**, the way `web_header_analysis` was, and fill each contract's
`observations:` map as its check lands. Suite by suite; `network` (13),
`web` (23), `ai` (28), `agent` (17), `rag` (17), `cag` (17) and now **`mcp`
(18) are done** (§0.12–§0.18). **No suite remains** — every one of the 133
checks is split. This section is kept as the record of the per-check unit of
work; what is still open is the list at its end.

**Read §0.12, §0.13 and §0.14 before starting one.** The network, web and ai
suites settled several conventions that are not in the design sections and that
the next suite should hold to — where the parsed answer lives, what a dynamic
discriminator means for the contract's map, what `confidence` is actually for,
how a probe/grade split exposes unfaithful test mocks (web), and — for every
remaining suite, which are all LLM-facing — how a grader reads the prompt,
dialect and payload back off the recorded *request* (ai, §0.14).

Per check, the unit of work is:

1. `check_service()` / `run()` sends, records, and returns a `Candidate` — no
   judgment (`create_candidate`, which now resolves severity from the contract).
2. `grade()` re-reads the recorded bytes and returns one `Verdict` per
   judgement, each with a **real** per-judgement confidence.
3. The contract's `observations:` map gains one entry per discriminator.
4. The class-level `provisional_severity`, if any, is **deleted** — the
   contract is the single source of truth once a block is declared, which is
   what the pilot now models. No `network` check had one; `grep` before assuming
   the same of a suite.
5. Co-located tests call a `probe_and_grade()` helper and keep their original
   assertions (the pilot's 25 tests are the pattern).

Two things wave 2 should expect:

- **The 39 contextual checks are migrated to probe/grade like the rest.** They
  keep their existing rule logic inside `grade()` and stay at
  `GradingTier.RULE`; declaring `contextual` does not mean phase 58 has to exist
  first. `GradeContext.severity` now carries their `range:` for when it does.
- **A probe that branches on a parsed value parses twice** (§6.2). The network
  suite had several and they are settled: the probe reads its answer off the
  exchange it just recorded, so there is one representation of what the target
  said rather than two that can drift, and where the reading is more than a
  field access the two halves share one parser (§0.12). Accepted, and cheap.

Still open from 57.2 and unchanged by 57.3 and 57.4: `TrafficLogger.log_request`
has no callers, and retention is designed but not implemented. The swarm
`scan_id` gap is closed (§0.5); what remains of swarm parity is the capture
posture not reaching agents (O-4) and per-check `on_critical` not being
enforced on the swarm path (56.15).

### 0.12 What 57.4 wave 2 built: the network suite

**All 13 `network` checks are split into probe and grade**, and each contract's
`observations:` map is filled. Behaviour is preserved — every check's co-located
tests keep their original assertions, routed through a `probe_and_grade()` helper
— and what is *added* is a per-judgement confidence with a written reason for
why it is not 1.0.

#### The plumbing wave 2 needed first

The pilot is an HTTP check and gets its exchange from `exchange_from_response()`.
The socket and resolver checks had no equivalent, so two things were added to
`app/capture/probes.py`:

- **`Probe.exchange`.** `probe()` now sets it on exit: the stored row when capture
  wrote one, an equivalent unstored `Exchange` when it did not. A migrated check
  writes `candidate.attach(prb.exchange)` and never asks which. `prb` stays bound
  inside an outer `except`, because the context manager sets `handle.exchange`
  *before* re-raising — so a failed resolve hands over its failure.
- **`capture.record_exchange(protocol, host, **fields)`.** Record-and-hand-back
  for a probe that already holds its result and does not need `probe()`'s timing
  context manager: a TCP connect that either completed or raised, a library call
  that returns a parsed object. It always returns an exchange — a build failure
  logs and returns an attribution-only one — because capture never breaks a scan
  and a probe must not have to branch on that.

#### Three checks gained capture they never had

`network_port_scan` had none: it now records one `tcp` exchange per **open** port
and deliberately records nothing for closed or filtered ones. This is the only
check in the suite whose negative count is unbounded — a `full` profile against a
quiet host is thousands of refused connects — and a corpus of refusals is volume
without evidence. The absence of a row is what "closed" means here.

`network_http_method_enum` drives `httpx` directly rather than going through
`app/lib/http.py`, so the 57.2 interceptor never saw it. It now records all
eleven method probes.

`network_geoip` is the **first user of the `local` protocol**, and it is worth
saying why a database lookup is capture at all: a grader reads evidence and
nothing else, so a verdict derived from a GeoLite2 row needs that row on the
record — and the corpus copy pins *which* row answered, which matters because
those databases are reissued weekly and an ASN's classification moves between
releases.

`network_banner_grab` gained something smaller but sharper: the exchange now
carries the banner **twice**, decoded in `response_body` and verbatim in a
`raw_hex` response header. Two of its signatures match on raw bytes, and a binary
handshake does not survive `decode(errors="replace")`. Before wave 2 the hex was
computed in `_grab_banner` and thrown away, so a stored banner could not be
identified as exactly as a live one.

#### Conventions the next suite should hold to

- **The parsed answer lives on the exchange, not in a return value.**
  `_resolve()`, `_ptr_lookup()`, `_resolve_aaaa()`, `_trace_route()`,
  `_get_cert_info()` and friends now return `Exchange | None`, and the probe
  reads `response_body` for its own outputs. One representation of what the
  target said, which is what makes §6.2's double parse safe rather than a second
  copy that can drift.
- **Better still: one parser, called twice.** `network_http_method_enum` has
  `_summarise(exchanges)` and `network_banner_grab` has `_banner_from(exchanges)`;
  `run()` calls it over the responses it just received and `grade()` calls it
  again over the stored copies. Prefer this wherever the probe needs a parsed
  value for an output.
- **Preserve observation ids.** Where a check emitted one undiscriminated
  observation per host, the candidate stays undiscriminated. Where a check
  already had discriminators, they are kept verbatim, value suffixes included
  (`ptr-93.184.216.34`, `trace-8080`, `cert-443`).
- **A dynamic discriminator cannot be a key in the contract's `observations:`
  map.** `port-443`, `custom-header-x-model`, `aaaa-2001:db8::1` and the rest are
  unbounded sets. Those contracts record one entry per *family* and say so in the
  comment; `provisional_for()` falls through to `default:`, which is correct
  because `grade()` places every value anyway.
- **Every verdict states a confidence, and the comment says why it is not 1.0.**
  This is the main thing wave 2 adds beyond the shape, and it is where the real
  thinking goes. Worth reading as models: `network_geoip`'s `geo` verdict is
  *less* confident with a city (0.75) than with only a country (0.9), because
  GeoLite2 is good at the coarse claim and wrong at the specific one;
  `network_http_method_enum` carries 0.7 throughout because "not 405" is a weak
  proxy for "accepted"; `network_geoip`'s `other-hosting` carries 0.5 because it
  is the *absence* of a match against forty hand-listed ASNs.
- **Two judgements are honestly not reproducible**, and both say so in their
  `reasoning`: TLS certificate expiry and WHOIS `recent-registration` compare
  stored evidence against *now*, so re-grading the same corpus next month yields
  a different verdict. This is the first place the corpus's limits are stated in
  the record rather than assumed away.

#### One incidental cleanup

`network_banner_grab._grab_banner` had its protocol-probe block written out
twice, verbatim and under identical conditions, so the second copy only ever
acted as a retry. It is now one loop with `for _attempt in range(2)` and a
comment — same two attempts, named.

### 0.13 What 57.4 wave 2 built: the web suite

**All 23 `web` checks are split into probe and grade**, and each contract's
`observations:` map is filled. Behaviour is preserved — every check's co-located
tests keep their original assertions, routed through a `probe_and_grade()`
helper — and, as with `network`, what is *added* is a per-judgement confidence
with a written reason for why it is not 1.0. Gates after the suite: web pytest
**221 passed**, `ruff check` clean, `dev verify-contracts` OK. `web_header_analysis`
was the pilot (57.3) and was already split; the other 22 landed here.

#### The convention the web suite added: faithful test mocks

The web checks are HTTP, so they get their evidence from
`exchange_from_response()`, which copies `HttpResponse.url` onto the exchange —
and a migrated check then reads the request URL *back off the recorded exchange*
to know which path it is grading (`web_path_probe`, `web_auth_detection`,
`web_redirect_chain` and others all key on it). Almost every co-located test mock
returned **one hard-coded URL for every request**, which was invisible while the
check read the live `HttpResponse` object and became a bug the moment the grader
read the recorded URL instead.

The fix is to make the mock faithful, never to weaken the assertion: each mock's
dispatcher now stamps the requested URL onto the response it returns
(`dataclasses.replace(response, url=url)`). This is the web analogue of
[[feedback_no_modify_checks]] — the check code is the source of truth, and a test
that passed only because its mock was unfaithful was testing the wrong thing. A
few tests (`web_redirect_chain`) also dispatched on **call count**, which encoded
a request *sequence* the split changed (the root is no longer fetched twice); those
were rekeyed on the URL, which is what they were really describing.

#### Duplicate-fetch cleanups the split surfaced

Reading the output back off the recorded exchanges made three latent
double-fetches obvious, each now fetched once: `web_vcs_exposure` probed
`/.svn/entries` twice (once to decide, once inside `_check_svn`);
`web_config_exposure` probed its fallback config paths and then fetched them
again in the main loop; and `web_redirect_chain` fetched the root twice (the
HTTP→HTTPS check and the chain's first hop are the same request).

#### Where confidence did the most work

The web suite is entirely `model: fixed` — the [[phase57_status]] contextual
line puts every `web` and `network` check on the fixed side — so `grade()` never
escalates past the rule tier. The confidence is therefore the whole added value,
and the recurring theme is the **catch-all route**: a server that answers 200
with its index page for every path makes `/.env`, `.git/config`, an SVN working
copy or a directory listing all look present, and several of those escalate to
`high` or `critical`. The migrated checks read the *body* to tell an exposed
artefact from a catch-all (git-config syntax, an HTML body where a config file
was expected, autoindex furniture vs a bare `SimpleHTTP` substring) and drop the
confidence — never the severity — when the evidence is a status code alone. The
other recurring softener is the **absence claim bounded by what was looked at**:
"no favicon", "HTTP/1.1 only", "all external resources use SRI", "framework not
identified" and "mass assignment not detected" each carry a confidence that says
how small the search was (two static pages, one path, a fixed signature table).

### 0.14 What 57.4 wave 3 built: the ai suite

**All 28 `ai` checks are split into probe and grade** — 16 `fixed`, 12
`contextual` — and each contract's `severity:` block is finalised. Behaviour is
preserved (co-located tests keep their assertions, routed through
`probe_and_grade()` / `run_and_grade()` helpers) and what is added is a
per-judgement confidence with a written reason. Gates after the suite: full
pytest **2509 passed / 5 skipped**, `ruff check` clean, `dev verify-contracts`
OK.

#### The plumbing wave 3 needed first

Every ai check is an LLM POST, so the grader has to know *which payload* produced
the response it reads. Three additions, all in `app/lib/ai_helpers.py` unless
noted:

- **`exchange_from_response(..., request_json=payload)`** (in
  `app/grading/evidence.py`). Both hashes cover the normalised request body, so a
  probe that POSTs JSON and records it with an empty `request_body` builds an
  exchange the corpus copy can never match — every verdict silently degrades
  `corpus`→`memory`. Passing the payload serialises it exactly as the interceptor
  does. **Every migrated ai probe passes `request_json=` AND
  `request_headers=JSON_HEADERS`.**
- **Request read-back**: `prompt_from_request`, `messages_from_request`,
  `dialect_from_request`, `response_text_from`. The ai analogue of the web
  suite's URL read-back (§0.13): a grader recovers the prompt, the conversation,
  the API dialect and the answer text off the recorded *request/response* rather
  than from the loop that sent it. `dialect_from_request` matters most — taking
  the dialect from scan context would work during a scan and fail re-grading a
  corpus six months later with no context, which is the case the capture line
  exists for.

#### The two test-mock bugs the split exposed

All 17 co-located ai test files shared one byte-identical `mock_client_factory`,
and both bugs were invisible until a grader read the record:

1. **`make_response` hard-coded the response URL** — the web §0.13 problem.
   Fixed with a `_stamp(resp, url)` helper (`dataclasses.replace`) on every
   dispatcher.
2. **`mock.__aexit__ = AsyncMock()` returned a truthy MagicMock**, which
   *suppresses* every exception raised inside `async with AsyncHttpClient(...)`.
   Each check that blew up mid-probe looked like one that completed, its own
   `except` never ran, and `result.errors` came back empty — so no probe error
   was ever testable. Fixed to `AsyncMock(return_value=False)`.

#### Conventions the remaining suites should hold to

- **Read the test back off the recorded request.** Where a probe sends N
  payloads down one endpoint, `grade()` pairs each response with its payload via
  the request body (`prompt_from_request`, or a param/system-message/temperature
  read-back), never positionally against a list the probe remembers. This is what
  makes the §6.2 double-parse safe for the LLM suites.
- **One parser, called twice** (§0.12) wherever the check `produces` an output —
  `_reading()` / `_endpoints_from()` / `_tools_from()`: `run()` calls it for the
  output, `grade()` over the stored copies.
- **Fixed check obs-map value = the *lowest* severity a discriminator can emit.**
  Where one discriminator spans severities (`tools-discovered` medium→high,
  `models-enumerated` info→medium), the map declares the floor — a map entry is
  the pre-grade provisional value, and declaring the ceiling would let a deferred
  grade over-escalate `on_critical`.
- **The 12 contextual checks are migrated like the rest**, with their rule logic
  inside `grade()` at `GradingTier.RULE` and `default: medium` / `range:
  [info, critical]` kept — no `observations:` map (the verifier rejects one on a
  contextual check), `rubric`/`signals` inert until phase 58. Their confidence is
  where the rule tier's weakness is stated honestly: the leak/bypass/compliance
  indicators are substring and phrase matches, and several payloads instruct the
  model to emit the very keyword the detector looks for, so a benign compliance
  and a genuine failure look alike — the gap phase 58's grader closes.

#### Where confidence did the most work

The recurring ai softeners: **self-report is not proof** (a model asked what it
is, or for its cutoff, can be made to say anything — `ai_model_behavior_fingerprint`
self-id 0.5); **the keyword is the instructed output** (many jailbreak/injection
payloads ask for "HACKED", so `hacked` in the response is compliance-shaped, not
proof of a safety failure); **not-rejected ≠ honoured** (`ai_api_parameter_injection`
splits verifiers that read a real effect, 0.8, from those that only see a 200,
0.4 — a gateway ignoring an unknown field returns 200 too); and the
**catch-all/echo** family carried over from web. `ai_framework_fingerprint` is
the model for confidence-from-signal-kind (header 0.9 / error 0.8 / endpoint 0.6
/ body 0.45, runner-up within one point caps 0.4).

### 0.15 What 57.4 wave 4 built: the agent suite

**All 17 `agent` checks are split into probe and grade** — 6 `fixed`, 11
`contextual`. Behaviour is preserved (co-located tests keep their assertions,
routed through a `probe_and_grade()` helper) and each verdict carries a
per-judgement confidence with a written reason. All agent checks are LLM-facing
HTTP POSTs, so the §0.14 ai plumbing applies verbatim — every probe passes
`request_json=` + `request_headers=JSON_HEADERS`, and every grader reads the
prompt/payload back off the recorded request body, never a remembered list.

The **fixed** six and their maps: `agent_context_overflow`
(`guardrail-bypass`:high / `role-change`:medium),
`agent_multi_agent_detection` (`management-endpoint`:medium /
`delegation-detected`:medium / `agent-ids`:low). The other four fixed checks
embed their discriminator (a probe id, a framework+version, an exploit id, a
path), so — like `ai_model_info_check` — they declare **no `observations:` map**
and `grade()` places the real severity: `agent_framework_version` (`default:
info`), `agent_framework_exploits` (`default: high`), `agent_loop_detection`
(`default: medium`), `agent_discovery` (`default: info`).

The **contextual** eleven keep their wave-1 contracts unchanged (`model:
contextual` / `default: medium` / `range: [info, critical]`, no map) and run
their rule logic inside `grade()` at `GradingTier.RULE`.

#### Conventions this suite adds (hold for rag/cag/mcp)

- **Context read at grade time, not probe time.** Checks whose severity depends
  on scan context — `agent_cross_injection` and `agent_trust_chain` read
  `multi_agent_topology` to pick critical-vs-high — take it from
  `GradeContext.context`, not a flag stamped during the probe. `probe_and_grade`
  forwards the same context to `grade_result` so a re-grade sees it.
- **One candidate per subject when `target_url` must survive.** `grade()` runs
  once per candidate and the observation's `target_url` comes from the
  *candidate*, not the verdict — so `agent_goal_injection`, which tests several
  endpoints, makes **one candidate per endpoint** (the web_path_probe pattern)
  rather than one per service. A single-candidate check (most of the suite)
  emits several verdicts with distinct discriminators instead.
- **Timing is read back, not re-measured.** `agent_loop_detection` recovers
  elapsed time from the recorded exchange's `elapsed_ms`, so a re-grade
  reproduces the same runaway/no-timeout call rather than re-timing a request
  that no longer runs.
- **Order disambiguates identical requests.** `agent_context_overflow` sends the
  same injection twice (baseline, then post-fill); the two requests are
  byte-identical, so which is which is recovered from their recorded *order*,
  not a flag.
- **Ignore-on-read-back beats track-by-position.** Where a probe sends messages
  that are not themselves graded — `agent_memory_poisoning`'s cleanup messages —
  they carry prompts that match no payload and are simply skipped when `grade()`
  re-reads, rather than being counted and stepped over.
- **The test mock must stamp the request URL** (`_stamp` via
  `dataclasses.replace`) for any check that attributes exchanges by path
  (`agent_discovery`, `agent_state_manipulation`, `agent_memory_extraction`,
  `agent_memory_poisoning`), and **`__aexit__` must return `False`** everywhere
  (a bare `AsyncMock()` suppresses probe exceptions — the §0.14 bug, present in
  every agent test file too).

#### Where confidence did the most work

The recurring agent softeners, all variants of the ai ones: **the keyword is the
instructed output** (goal-injection/context-overflow payloads ask for
`INJECTED`/`OVERFLOW_SUCCESS`/`ADMIN_ACCESS_GRANTED`, so the keyword in the reply
is compliance-shaped — capped at 0.75 where the check computes its own score);
**echo ≠ effect** (cross-injection's marker echo is a real delivery vector, but
no downstream agent is observed consuming it; trust-chain/reflection "exploited"
rests on the claim's own words reappearing); **accepted ≠ exploited** (state /
kickoff / batch endpoints return 2xx without the write's effect being read
back); **hallucinated output** (tool-abuse RCE indicators can be a fabricated
`/etc/passwd` with no tool run); **refusal ≠ capability** (tool-abuse "has tool
access but refused" overreads a polite decline). Confidence-from-signal-kind
carries over in `agent_discovery` (header 0.9 / error-class 0.8 / body 0.55 /
shared path 0.4) and `agent_framework_version` (header 0.9 / metadata 0.75 /
error scrape 0.6).

### 0.16 What 57.4 wave 5 built: the rag suite

**All 17 `rag` checks are split into probe and grade** — 9 `fixed`, 8
`contextual`. Behaviour is preserved (co-located tests keep their assertions,
routed through a `probe_and_grade()` helper) and each verdict carries a
per-judgement confidence with a written reason. All rag checks are HTTP, and the
retrieval/ingestion ones are LLM-facing POSTs, so the §0.14 ai plumbing applies.
Gates after the suite: full pytest **2509 passed / 5 skipped**, `ruff check`
clean, `dev verify-contracts` OK.

The **fixed** nine. Three declare a full `observations:` map (closed enums):
`rag_fusion_reranker` (`reranker-headers`:low / `reranker-scores`:info /
`no-reranker`:info), `rag_source_attribution` (`citation-urls-suspicious`:medium
/ `citation-structured`:low / `citation-unstructured`:low / `no-citations`:info),
`rag_cache_poisoning` (`cache-poisoned`:high / `cache-detected`:medium /
`cache-varied`:low / `no-cache`:info), `rag_embedding_fingerprint`
(`embedding-model`:low / `embedding-unknown`:info). The other five embed their
discriminator (a size, a store type, a credential kind, a path) and so declare
**no map** with `grade()` placing the real severity (the `ai_model_info_check`
pattern): `rag_chunk_boundary` (`default: info`), `rag_collection_enumeration`
(`info`), `rag_vector_store_access` (`info`), `rag_discovery` (`info`),
`rag_auth_bypass` (`info`). The **contextual** eight keep their wave-1 contracts
unchanged and run their rule logic inside `grade()` at `GradingTier.RULE`.

#### Conventions this suite adds (hold for cag/mcp)

- **grade() never sees the candidate's discriminator.** It gets `Evidence` and a
  `GradeContext` (scan/check/host/target/target_url/tier/severity/context) — no
  discriminator. When one check emits *many* candidates on the *same*
  service/host (`rag_collection_enumeration`, `rag_vector_store_access`: one per
  store), which candidate is which cannot come from the context. It is recovered
  from the evidence's own recorded request URLs — the store's signature paths
  (`_infer_store_type`) — and the rest is then read from `GradeContext.context`
  (the upstream `accessible_stores` / `vector_stores` output). `ctx.severity` is
  the contract's severity block, not a place to stash per-candidate identity.
- **A random per-run token is recovered from the evidence.**
  `rag_corpus_poisoning`'s canary id is a fresh `uuid` each run, embedded in
  every ingestion payload; `grade()` recovers it from a recorded request body
  (regex) so a re-grade reconstructs the exact payloads it must match against.
- **Byte-identical retrieval queries are paired by order.** Several checks
  (`rag_metadata_injection`, `rag_multimodal_injection`) issue the *same*
  verification query after each of N distinct writes, so the query exchanges are
  identical; each is paired with the write that precedes it in recorded order
  (the `agent_context_overflow` rule, §0.15), while the writes themselves are
  told apart by a filename or document id in their bodies.
- **Two checks own a `_build_mock_client`** (`rag_discovery`,
  `rag_indirect_injection`) rather than the suite-shared one; both needed the
  §0.14 fix (`_stamp` + `__aexit__` returning `False`) applied to their own copy.

#### Where confidence did the most work

The recurring rag softeners: **regex category ≠ leak** (`rag_document_exfiltration`
matches PII/credential *patterns* over raw text, so a documentation example or a
public FAQ scores like a real exposure); **the keyword is the instructed output**
(carried from ai/agent — metadata/multimodal/indirect payloads ask the model to
emit the exact indicator the detector looks for, so a compliant echo and a benign
mention are indistinguishable at the rule tier); **different results ≠ attack**
(`rag_retrieval_manipulation` / `rag_adversarial_embedding`: a query returning
new document ids is what any retriever does answering a different question, not
proof the extra documents were off-limits); **accepted ≠ persisted**
(`rag_corpus_poisoning` / `rag_multimodal_injection`: a 2xx to a write says the
endpoint accepted the bytes, not that they were indexed and later retrieved);
**not-rejected ≠ honoured** (`rag_retrieval_manipulation`'s empty filter, carried
from ai). Confidence-from-signal-kind carries over in `rag_source_attribution`
(explicit `sources` field 0.85 / generic `metadata` 0.4), `rag_fusion_reranker`
(header 0.9 / score-shape 0.35) and `rag_discovery` (header 0.9 / field 0.75 /
body 0.4).

### 0.17 What 57.4 wave 6 built: the cag suite

**All 17 `cag` checks are split into probe and grade**: 14 `fixed`, 3
`contextual`. Behaviour is preserved. Co-located tests keep their assertions,
routed through a `probe_and_grade()` helper, and each verdict carries a
per-judgement confidence with a written reason. Every cag check is HTTP and most
are LLM-facing POSTs, so the §0.14 plumbing applies (`request_json=` +
`request_headers=` on every recorded exchange). Gates after the suite: full
pytest **2510 passed / 5 skipped**, `ruff check` clean, `dev verify-contracts`
OK.

The **fixed** fourteen. Four declare a full `observations:` map (closed sets),
each at its floor: `cag_cache_eviction` (nine `eviction-*` / `eviction-key-*`
entries, all `medium`, `default: medium`), `cag_cache_key_reverse`
(`key-excludes-system-prompt`:high / three `key-ignores-*`:medium /
`key-detailed`:low, `default: low`), `cag_cache_probe` (three
`cache-vuln-*`:high / four `cache-issue-*`:low, `default: low`) and
`cag_stale_context` (`stale-role_context` / `stale-ttl_staleness`, both `info`).
The other ten embed an endpoint path in their discriminator, so they declare
**no map** and `grade()` places the real severity: `cag_discovery`,
`cag_serialization`, `cag_distributed_cache`, `cag_ttl_mapping`,
`cag_side_channel`, `cag_multi_layer_cache`, `cag_provider_caching`,
`cag_cache_warming`, `cag_semantic_threshold` (all `default: info`) and
`cag_cache_quota` (`default: low`). The **contextual** three
(`cag_cross_user_leakage`, `cag_injection_persistence`, `cag_cache_poisoning`)
keep their wave-1 contracts unchanged and run their rule logic inside `grade()`
at `GradingTier.RULE`.

#### Conventions this suite adds (hold for mcp)

- **Timing is `elapsed_ms`, and only `elapsed_ms`.** A large share of cag is
  timing inference: cold/hot, TTL expiry, semantic threshold, side channel,
  quota eviction, cache layers. Every check that wrapped its requests in
  `time.time()` now drops the wall-clock delta and reads
  `Exchange.elapsed_ms`, which the transport already measures and which is the
  only latency a corpus can reproduce. `time.time()` survives in several probes
  only as a source of per-run unique ids (cache-buster keys, session markers),
  and `grade()` never recomputes those. It recovers each one from the recorded
  request body, like `rag_corpus_poisoning`'s canary (§0.16). Six checks build
  their ids from a `uuid` instead (`cag_cache_warming`, `cag_stale_context`,
  `cag_cache_quota` and the three contextual ones); either source works for
  that reason.
- **Timing tests drive `elapsed_ms`, never patch the clock.** Several
  co-located tests patched `time.time()` with counted iterators, or stubbed an
  internal analyser (`_map_ttl`, `_detect_layers`, `_analyze_provider_caching`)
  to hand back a prebuilt reading. Neither survives the split: the clock is no
  longer read, and the stubbed method no longer exists because `grade()`
  re-derives the reading. The tests now return a faithful per-response
  `elapsed_ms` (and headers) from the mock and assert on what the real parser
  derives. That is stronger than before: a stub that returned a dict, followed
  by an assertion that the dict came back out, tested nothing.
- **Several named sub-tests down one endpoint → recovered from request
  signature.** `cag_cross_user_leakage` (four isolation tests), `cag_cache_probe`
  (four sub-tests), `cag_cache_poisoning` (exact + semantic) and
  `cag_serialization` (Redis-path GET / octet-stream POST / `?key=` traversal
  GET) each tell sub-tests apart by a distinguishing header, body field, method
  or content type on the recorded request, never by position and never by the
  discriminator. Within a sub-test, the two byte-identical-bodied requests that
  differ only in a session header are paired by recorded order (§0.15). Cleanup
  writes carry no signature and are skipped on read-back.
- **Candidate per endpoint; grade may return nothing.** `cag_cache_eviction`
  emits a candidate for every endpoint it tried and lets `grade()` return no
  verdict for a 404, an error or an irrelevant status, so the judgement stays in
  the grader. It recovers which endpoint an exchange hit from its method and URL,
  with the longest matching path winning so `DELETE /cache/{key}` is never read
  as `DELETE /cache`.
- **One GET, two verdicts.** `cag_discovery` used to probe some paths (e.g.
  `/cache`) twice, once per detection pass. It now requests each URL once, emits
  one candidate per URL, and `grade()` runs both parsers over it, keyed on
  path-set membership.
- **cag test mocks are a different shape.** The shared cag helper is
  `make_mock_client(**overrides)`, which `setattr`s plain async functions and
  sends DELETE through `client._request("DELETE", url)`. The §0.14 fix is applied
  by wrapping *every* method, defaults and overrides, in `_stamped()`, which
  takes the URL from `url=` or the first positional string containing `://`,
  plus `__aexit__` returning `False`. `cag_discovery` and `cag_cache_probe` build
  their mocks inline and were fixed by hand.

#### Where confidence did the most work

The dominant cag softener is **latency is not a cache hit**. Most cag checks
infer caching, expiry, eviction or layering from response time alone, and
jitter, a warm connection or backend load produce the same shape, so those
verdicts sit at 0.3–0.55 unless a cache header corroborates (`cag_ttl_mapping`
0.4 → 0.65 with a header; `cag_multi_layer_cache` CDN-by-header 0.85 vs latency
ratio 0.35). The others carry over from earlier suites. **Identical text ≠ cache
hit at temperature 0** (`cag_cross_user_leakage` 0.35, `cag_stale_context`).
**The marker is the instructed echo** (`cag_cache_poisoning` /
`cag_injection_persistence` 0.4: the payload asks the model to repeat the very
marker the detector looks for). **Accepted ≠ served**
(`cag_cache_warming` 0.45, `cag_injection_persistence` 0.45: a 2xx to a store is
not the entry being served to someone else). **Not-rejected ≠ honoured**
(`cag_cache_eviction`: an unauthenticated 2xx is 0.45 without an acknowledging
body, 0.3 for an HTML catch-all, and nothing reads the cache back to show an
entry gone). **Self-report ≠ proof** (`cag_provider_caching`'s `cached_tokens`
is the provider's own claim, which a proxy can fake: 0.6). **Error string ≠
deserialisation** (`cag_serialization` pickle / type-confusion rest on an error
a WAF or generic 500 can carry: 0.5 / 0.4). Confidence-from-signal-kind carries
over in `cag_discovery` (header 0.9 / structured field 0.7 / body substring
0.4–0.55).

### 0.18 What 57.4 wave 7 built: the mcp suite

**All 18 `mcp` checks are split into probe and grade**: 13 `fixed`, 5
`contextual`. (Earlier plans counted 17; the suite has 18.) **With it every suite
is migrated, and the probe/grade half of 57.4 is done.** Behaviour is preserved.
Co-located tests keep their assertions, routed through `probe_and_grade()` /
`run_and_grade()`, and each verdict carries a per-judgement confidence with a
written reason. Gates after the suite: full pytest **2510 passed / 5 skipped**,
`ruff check` clean, `dev verify-contracts` OK.

The **fixed** thirteen. Six declare a full `observations:` map (closed sets),
each at its floor, all with `default: info`: `mcp_protocol_version`
(`protocol-downgrade`:low / `protocol-current`:info), `mcp_transport_security`
(`no-tls` / `cors-wildcard` / `cors-reflect`:high, `no-origin-check` /
`sse-no-auth`:medium, `transport-ok`:info), `mcp_undeclared_capabilities` (four
`undeclared-*`:high, eight `nonstandard-*`:medium, `caps-clean`:info),
`mcp_resource_traversal` (traversal and SSRF families at critical, leak family
medium, protocol high, `resource-safe`:info), `mcp_shadow_tool_detection`
(`list-changed-accepted`:high / `namespace-flat`:medium / `name-collision` and
`reinitialize-accepted`:low / `namespace-safe`:info) and
`mcp_tool_chain_analysis` (six chain categories, five critical and
recon+lateral high; `partial-chain-source`:medium; `no-chains`:info). The other
seven embed a tool name, path, implementation or key in their discriminator, so
they declare **no map** and `grade()` places the real severity (`default:
info`): `mcp_tool_enumeration`, `mcp_schema_leakage`, `mcp_discovery`,
`mcp_server_fingerprint`, `mcp_websocket_transport`, `mcp_auth_check`,
`mcp_tool_rate_limit`. The **contextual** five (`mcp_tool_invocation`,
`mcp_prompt_injection`, `mcp_template_injection`, `mcp_sampling_abuse`,
`mcp_notification_injection`) keep their wave-1 contracts unchanged and run their
rule logic inside `grade()` at `GradingTier.RULE`.

#### Conventions this suite adds

- **A check with no request records what it analysed, as a `local` exchange.**
  `mcp_schema_leakage` and `mcp_tool_chain_analysis` make no requests at all:
  they analyse the upstream `mcp_tools`. Following `network_geoip` (§0.12), each
  records the tool fields it reads (not the whole dict) as a `local` exchange and
  `grade()` parses them back, so a re-grade of a stored corpus needs no scan
  context. The same rule covers probes whose verdict rests partly on upstream
  *facts*: `mcp_server_fingerprint` (`serverInfo` / capabilities),
  `mcp_prompt_injection` (the text-tool set), `mcp_sampling_abuse`
  (`has_sampling`) and `mcp_shadow_tool_detection` (tool names). This is
  stricter than §0.16, where rag reads `GradeContext.context` to *identify* a
  candidate. Here, context that is *evidence* goes on the record. The one
  remaining context read is `mcp_tool_invocation`'s probe type, re-derived from
  the tool in context with a payload-marker fallback.
- **JSON-RPC is read back from the request body, not the URL.** Most MCP traffic
  is JSON-RPC to one endpoint, so the URL attribution of §0.13/§0.17 rarely
  applies. Graders pair each response with its test through the recorded
  request's `method`, `params.name`, `params.arguments`, `params.uri`,
  `protocolVersion` or `params.systemPrompt`. Only `mcp_websocket_transport`'s
  mock needed URL stamping as a result.
- **Byte-identical requests that belong to different tests get different
  candidates.** `mcp_auth_check` sends the same plain `tools/list` for its
  no-auth and scope tests. Rather than pairing them by order (§0.15, which suits
  repeats *within* one test), it makes one candidate per (server, test), and
  `grade()` recognises the test from the shape of its evidence.
- **Cross-server summaries became per-server verdicts.** `transport-ok`,
  `ws-not-found` and `resource-safe` were each emitted once across every server.
  `grade()` runs per candidate and cannot see sibling servers, so each is now
  graded per server. The two shapes are identical for one server. For several
  MCP servers on the *same host*, the shared discriminator yields repeated
  observation ids, which nothing dedupes; `tool-<name>` in
  `mcp_tool_enumeration` already behaved that way before this wave. Recorded,
  not fixed.
- **Burst timing is summed `elapsed_ms`.** `mcp_tool_rate_limit` reports the sum
  of its recorded per-request latencies rather than a wall-clock span: close, not
  identical, and the only figure a corpus reproduces (§0.17).
- **mcp test mocks are inline.** Each test builds its own `AsyncMock()`, and all
  18 files carried the §0.14 `__aexit__` bug. A scratch script applied
  `AsyncMock(return_value=False)` and the grading-helper reroute. There was no
  shared mock helper to fix once.

#### Where confidence did the most work

The dominant mcp softener is **declared ≠ reachable**. Tool enumeration, schema
leakage and tool-chain analysis read the server's *description* of its tools,
and nothing is invoked. `mcp_tool_enumeration` takes confidence from what
classified the tool: a name pattern matched as a whole token 0.7, the same
pattern inside a longer word (`cmd` in `cmdb_lookup`) 0.5, description 0.6,
parameter name 0.45. A dangerous capability chain is 0.55, and in schema leakage
a parameter merely *named* `token` is 0.4 against a published default *value*
like `prod-db.internal:5432` at 0.7.

The rest carry over from earlier suites:

- **Self-report ≠ proof**: `serverInfo` name 0.85 against a known SDK, 0.6 raw.
- **Not-rejected ≠ honoured**: protocol downgrade 0.45–0.6, notification
  acceptance 0.4–0.5, `list_changed` 0.4, spoofed-Origin POST 0.5, no rate limit
  after a ten-request burst 0.55.
- **Returned text ≠ tool ran**: a model fronting a tool can fabricate
  `uid=0(root)` (`mcp_tool_invocation` 0.4–0.7), and a 200 to a sampling request
  is not a client model running (0.55).
- **The keyword is the instructed output, or coincidence**: a template `49` 0.35,
  a command marker 0.4.
- **The bytes are the disclosure**: plain-HTTP scheme 0.95, CORS wildcard or
  reflection 0.9, unauthenticated tool list 0.9.

Confidence-from-signal-kind carries over in `mcp_discovery` (`Mcp-*` header 0.9
/ JSON-RPC result 0.75 / method string 0.6 / bare 401 0.55 / keyword 0.4).

### 0.19 The 57.4 exit condition

§8's exit condition is now enforced rather than merely true, and the success
criteria the split made assertable (§10) are asserted. Gates after: full pytest
**2786 passed / 5 skipped** (+276), `ruff check` clean, `dev verify-contracts`
OK.

- **Severity is required — for built-in checks.** `verify_contracts` gains
  **`severity-undeclared`**: a check with no `severity:` block has no provisional
  severity for `on_critical` and no model for a grader to honour. The **`custom`
  suite is exempt**, and the pydantic field stays optional, for one reason: the
  Chainsmith agent scaffolds custom checks *without* a severity block (O-5,
  parked), and `discover_components` raises on *any* violation, so a
  schema-level requirement would let one scaffolded folder fail discovery for
  every check in the tree. A custom check that does declare a block still gets
  every cross-field rule. The requirement is check-only; agents, advisors and
  gates have no severity model.
- **A suite-wide guard keeps the split from regressing**
  (`tests/checks/test_probe_grade_coverage.py`). For every built-in contract: the
  entry class has a `grade()`, and its `check.py` never calls
  `build_observation`, `create_observation` or `Observation(...)`. The second is
  what makes criterion 1 hold for all 133 checks rather than for the few a unit
  test exercises. The grading stage is the only code that stamps grading state,
  tier, evidence ids and evidence source, so an observation built in a probe
  would trace to nothing.
- **Criteria 1 and 4 are asserted where they are claims — in a scan**
  (`tests/grading/test_launcher_grading.py`). Three checks run through
  `CheckLauncher.run_all()`: one whose grader raises, one with no grader and one
  graded check depending on the first. The scan completes with nothing in
  `failed`, the raising check's output still reaches its dependent, both
  ungraded records carry their provisional severity with no confidence, and
  every persisted record names its grading state, tier and evidence. Assertions
  read what `run_all()` returns, which is the `to_dict()` record the writer
  persists, not the in-memory object.
- **Criterion 4's second half is not built.** There is no offline re-grade entry
  point, so "a later re-grade pass fills them in without re-scanning" remains a
  design claim. `grade_result()` is shaped for it (§0.9: the same function grades
  a stored corpus), but nothing loads a scan's observations and corpus, rebuilds
  candidates and calls it. *Built since: §0.20.*

One fixture changed with the requirement: `tests/checks/test_config_validation.py`
builds synthetic "clean" check trees and asserts zero violations, so its helper
now declares `severity: {model: fixed, default: info}`, as any post-57.4 contract
must.

### 0.20 The offline re-grade pass

Criterion 4's second half — *"a later re-grade pass fills them in without
re-scanning"* — and the diff criterion 2 asks for now exist, as
`chainsmith dev regrade <scan_id>` over `app/grading/regrade.py`. Gates after:
see §0.1.

**Operator decisions (2026-09-12); do not re-litigate:**

- **Persist what grading needs at scan time**, rather than reconstruct it from
  observations. Reconstruction was rejected as lossy twice over: one candidate
  may become several observations (D-24) and the discriminator is not stored,
  and 24 of the 133 graders read `ctx.context`, which nothing persisted.
- **A diff by default; `--apply` writes.**
- **CLI only.** An API endpoint and a WebUI surface are later work.
- **Nothing is deleted on `--apply`.** A placeholder the re-grade replaces under
  different ids is marked with a new grading state, `superseded`, because chains
  store observation ids and §2 says nothing subtracts.

What was built:

- **A grading record per check**, `evidence/<scan_id>/grading/<check>.json`
  (`app/grading/record.py`). `grade_result()` writes it *before* grading — so a
  grader that raises still leaves something a fixed grader can replay — and only
  when the scan captures. It holds each candidate (identity, provisional
  severity, target, `raw_data`) and the scan context the check was graded
  against. **Exchanges are referenced by `content_hash`, never copied**: a copy
  would store bytes the check's capture policy (D-20) chose not to keep. The
  context is serialised the way `SwarmCoordinator._snapshot_context` already
  does it, so a grader sees on re-grade the shape a swarm agent grades against;
  `capture_settings` is omitted and any unserialisable key is dropped and named
  in `dropped_context_keys`. The document carries `version: 1`.
- **`grade_result(..., stored=, bind=, persist=)`.** Keywords that belong to the
  re-grade; a scan never passes them. It is still one function for in-scan and
  offline grading (D-23).
- **`regrade_scan()`** replays each recorded candidate through its check's
  *current* `grade()`, one candidate per call so every verdict is attributable,
  and diffs against the stored rows (`ObservationRepository.get_records`, which
  deliberately skips post-scan severity overrides). Kinds: `unchanged`,
  `changed` (with a per-field before/after), `added`, `superseded`,
  `not_reproduced`. It compares only grader-owned fields — not `raw_data`, which
  the launcher annotates after grading — and runs each re-graded record through
  `apply_pre_run_override` so the comparison is like for like. A candidate is
  **skipped and named** when its check is gone, its record version is unknown,
  or any exchange it referenced is not in the corpus (it was graded from memory
  at scan time, so it is not reproducible).
- **`apply_regrade()`** writes in one transaction
  (`ObservationRepository.apply_regrade`): rewrite `REGRADE_COLUMNS` (the
  grader-owned columns plus `fingerprint`, which hashes title and evidence),
  insert new verdicts, stamp `superseded` with the ids that replaced it, then
  rebind evidence (D-22). **Idempotent**: a `superseded` row is settled and the
  next pass skips it.
- **`superseded` is narrow.** Only an `ungraded` or `grading_failed` row whose
  candidate re-graded under different ids, or into no verdict at all. A *graded*
  row the re-grade does not reproduce is reported `not_reproduced` and left
  alone.
- `EvidenceStore.delete_scan` removes grading records with the exchanges.
  `bulk_create`'s row construction moved into `_observation_row` /
  `scoped_observation_id` so the re-grade shares it; no behaviour change.
- Tests: `tests/grading/test_regrade.py` — record written iff capturing,
  unchanged/changed/context-reading/not-reproduced/skipped, criterion 4 end to end
  through `CheckLauncher.run_all()`, `--apply` in place and superseding without
  deleting (and idempotent), no socket opened and no workspace file touched on a
  dry run, CLI wiring.

**Limits, stated rather than discovered:**

- **Capture is off by default, so by default there is nothing to re-grade.**
  Scans run before this landed, and every non-`--capture` scan, have no records;
  the CLI says so and exits 1.
- **Check config is not recorded.** A grader that reads a tunable grades against
  today's value, not the scan's.
- ~~Reports do not yet filter `superseded`.~~ **Closed by §0.21.**
- ~~The context is written once per check.~~ **Closed by §0.22:** D-21
  measured it at 56% of record bytes, and record v2 stores each context value
  once per scan (4.72 MB -> 1.14 MB).
- A pre-run override changed since the scan shows as a severity diff.
- Swarm workers capture by their own default (O-4), so remote checks leave no
  records.
- Criterion 2's *"re-read offline with no target access"* is asserted against a
  synthetic corpus only; against a real one it waits on D-21, like criteria 6
  and 7.

### 0.21 Superseded rows in reports, reads and history

§0.20 left `superseded` rows visible to everything downstream: counted twice,
labelled "ungraded", a phantom in comparisons and trends. This closes that
limit. Scoping and the decision table live in `phase57-superseded-in-reports.md`
(§3 and §3.1).

**Operator decisions (2026-09-12); do not re-litigate:**

- **S-1** One chokepoint: `ObservationRepository.get_observations` /
  `get_observations_by_host` exclude superseded rows by default, with an
  `include_superseded=True` opt-in.
- **S-2** Superseded rows are **excluded from every count and risk score**. This
  is where supersession deliberately parts from §2 suppression, which counts
  its rows: a suppressed row is the only copy of its finding, but a superseded
  row always has a successor (or a re-grade that produced no verdict).
- **S-3** Technical report (md/html/json): a count note plus a
  **"Superseded by Re-grade"** appendix naming each row's successors.
  Executive and compliance: the count only. CSV and SARIF: excluded.
- **S-4** API routes exclude by default; `?include_superseded=true` opts in. The
  WebUI counts severity client-side, so the API default fixes it with no JS
  change.
- **S-5 Cascade recompute.** `regrade --apply` rebuilds `ObservationStatusHistory`
  and `ScanComparison` for the re-graded scan **and every later complete scan of
  its target**, oldest first. History is data rebuilt from observation rows and
  check logs, so rewriting it loses nothing.
- **S-6** Chain rows are never rewritten. A chain naming a superseded id is
  *rendered* through to its successors.

What was built:

- **Shared helpers** (`app/lib/observations.py`, beside the suppression helpers):
  `is_superseded`, `is_placeholder`, `partition_by_grading`,
  `supersession_note`, `superseded_by`, `resolve_superseded_ids`.
  `PLACEHOLDER_STATES` moved to `app/grading/models.py`, and the re-grade imports
  it instead of defining its own copy.
- **The NULL-safe predicate** `not_superseded()` (`app/db/repositories.py`).
  `grading_state` is nullable and rows from before 57.3 hold NULL. A bare
  `!= 'superseded'` would silently drop them all. The data layer spells the
  state as `SUPERSEDED_STATE` rather than import the grading package, and a test
  holds the two equal. It is applied to: both default reads, every fingerprint
  query in `compute_observation_statuses` and `compare_scans`, the trend data
  point, trend MTTR severity, and the targeted export's raw select (which
  bypassed the repository).
- **Successors are structured.** `apply_regrade` records them in
  `raw_data["superseded_by"]` as well as in the reasoning, so chain rendering
  and the appendix never parse prose.
- **Three latent bugs in `compute_observation_statuses`**, all of which blocked
  S-5. None showed while it ran only once, at scan completion:
  1. **Not idempotent.** A rerun appended history rows, and it collided on
     `uq_scan_comparison`. It now replaces its own rows.
  2. **The previous-scan lookup had no start-time bound.** A rerun on an older
     scan paired it with a *later* one. It is now `started_at <=` this scan's.
  3. **Regression detection reads `resolved` history across all scans.** So
     `ComparisonRepository.recompute_statuses_from` clears the whole run before
     rebuilding any of it. As at completion, only complete scans that recorded
     observations are compared.
- **`apply_regrade` returns `statuses_recomputed`**, and the CLI prints it. The
  history is rebuilt only when something was written.
- **`!= "graded"` misclassification fixed.** The technical report's ungraded note,
  per-row grading line and JSON `ungraded` now test `is_placeholder`, so a
  superseded row is never called ungraded.
- **Reports:** technical (md/html/json notes, appendix, chain ids resolved in
  markdown), executive and compliance (`superseded_count`, and a note when it is
  non-zero). Delta and trend inherit the exclusion through the repository.
- **Routes:** `include_superseded` on `/api/v1/observations`, `/by-host`,
  `/export/csv`, and the `/api/v1/scans/{id}/observations*` equivalents.
  `GET /api/v1/observations/{id}` still finds a superseded row by id, because
  nothing is counted there and a chain or old link may name one. Chain detail
  resolves superseded ids and lists the ones it substituted in
  `superseded_observation_ids`.
- **Callers that keep reading superseded rows:** `get_records` (the re-grade
  diffs against it) and the scratch import in `app/cli.py`, which dedupes
  against existing fingerprints and would otherwise re-import them.
- **Tests:** `tests/db/test_superseded_rows.py` (helpers, default/flag/NULL row,
  comparison, rerun idempotency, previous-scan bound, the cascade across four
  scans with an earlier one left alone, trend totals).
  `tests/reports/test_report_superseded.py` (counts/risk, note, appendix, no
  ungraded label, chain rendering, JSON, HTML, CSV/SARIF omission, executive,
  compliance, targeted export). `tests/grading/test_regrade.py` (successors
  recorded, default read, history rebuilt end to end).

**Limits:**

- **The scratch import's superseded dedupe has no test.** No test of that command
  existed to extend.
- **WebUI not live-smoked.** The fix is the API default; no JS changed.
- **Chain rendering in HTML reports** shows no observation ids at all, so there
  is nothing to resolve there. The engine's chain *analysis* reads the default
  (current) rows. Chains built before a re-grade keep their stored ids until
  they are re-run.

### 0.22 D-21: the growth number, and criterion 6 against a real corpus

Measured 2026-09-12 on a dev VM (Debian 13, Docker 29) against the **full
fakobanko range** (`./range/start-range.sh fakobanko --all`: 10 services), from
inside `chainsmith-recon` with
`chainsmith scan fakobanko.local --scenario fakobanko --capture`, which means
default protocols (`http`, `llm`), per-check capture policy, and the `lab` port
profile. Two back-to-back pairs were run: one before the fixes below and one
after. The measurement scripts were throwaway and are not in the tree.

**Operator decisions (2026-09-12); do not re-litigate:**

- **Normalise Chainsmith's own per-run markers** for hashing, rather than make
  the checks mint deterministic ones.
- **Seed fakobanko's vector scores**, so that an unchanged range really is
  unchanged.
- **Slim grading records now** (format v2, below).
- **Capture stays off by default.** Revisit once retention exists, because a
  default-on workspace would grow without bound.

#### The growth number

Per full fakobanko scan: 123 checks (97 run, 26 skipped for unmet
prerequisites), 295 observations, about 8.7 minutes.

| | First pair (record v1) | Second pair (record v2) |
|---|---|---|
| Exchanges | 4,642 (all `http`; 0 `llm`, 0 truncated) | 4,637 / 4,638 |
| Exchange documents | 4.83 MB (mean 1.04 KB, median 956 B, max 17 KB) | 4.82 MB |
| Grading records | **4.72 MB** | **1.14 MB** (1.03 MB records + 0.11 MB context store, 54 values) |
| Evidence directory | 9.55 MB | 5.97 MB |
| Database growth | ~3.8 MB | ~3.75 MB |
| **Total per scan** | **~13.3 MB** | **~9.7 MB** |

- **The database cost is the index.** After one scan, the `evidence` table and
  its five indexes were about 4 MB of the 4.9 MB file, roughly 0.8 KB per
  exchange. Observations were 0.44 MB.
- **By suite (exchange bytes):** web 1.52 MB, rag 1.34, ai 0.72, agent 0.67,
  mcp 0.23, cag 0.21, network 0.14. The heaviest checks are
  `rag_corpus_poisoning`, `rag_discovery`, `agent_discovery` and
  `web_path_probe`.
- **Rule of thumb:** about 2 KB of disk plus database per captured exchange, or
  about 10 MB per full scan of a 10-service AI target. This is the number
  retention and the 256 KB cap were waiting on. No exchange came near the cap.
- **Exchange documents are still pretty-printed** (`indent=2`). Compacting them
  is the next obvious saving and has not been measured.

#### Grading record v2 (the §0.20 context limit, fixed)

In v1, 56% of the grading-record bytes were scan context copied into every
check's record, and the rest was mostly indentation. The context a check sees
is everything upstream checks have produced, so each late `rag_*` record
carried about 118 KB of *other suites'* results (`vulnerable_rag_endpoints`,
`indirect_injection_results`, `vulnerable_agents`, `goal_injection_results`).

- **`RECORD_VERSION = 2`** (`app/grading/record.py`). A record holds
  `context_refs` (key -> SHA-256 of the value's canonical JSON), and each value
  is stored once per scan at `evidence/<scan>/grading/context/<sha256>.json`
  (`EvidenceStore.write_context_value` / `read_context_value`). Values are
  written before the record that references them, and records are written as
  compact JSON.
- **v1 records still replay** (`READABLE_VERSIONS = {1, 2}`,
  `context_from_record`).
- **A missing context value skips the check and names the key.** Grading
  against a partial context would grade something different from the scan.
- `EvidenceStore.delete_scan` removes the context store as well.
- **Result:** 4.72 MB -> 1.14 MB per scan (-76%). Identical across both scans
  of the second pair.

#### Criterion 6

**The first pair failed on 10 checks, for two causes.**

1. **probe_hash: per-run markers the normaliser did not know.**
   `rag_corpus_poisoning` mints `chainsmith-canary-<8 hex>`, `web_error_page`
   requests `/chainsmith-probe-<8 hex>`, and `mcp_websocket_transport` sends a
   random `Sec-WebSocket-Key`. The normaliser recognised only full UUIDs.
2. **content_hash on `model: fixed` checks: the target changed.** fakobanko's
   `vector_db.py` `/search` returned `random.uniform(0.7, 1.0)` scores, which
   broke five fixed `rag_*` checks. Six contextual `rag_*` differences had the
   same cause, so they were not evidence of model stochasticity.

**Fixes:**

- `normalise_text` substitutes `chainsmith-(canary|probe)-<hex>` with a
  placeholder. The hex suffix is required, so the constant `chainsmith-probe`
  that MCP payloads echo is untouched.
- `http` volatile headers gain `sec-websocket-key` and `sec-websocket-accept`
  (RFC 6455).
- The vector service's score is `sha256(query, doc id)` mapped into
  [0.7, 1.0].

**Second pair: 1 check differs, and it is not hashing.** `web_path_probe` has
418 vs 419 exchanges. All 418 paired exchanges are identical; the extra one is
`GET vector.fakobanko.local:8087/.env`, recorded only in the second scan.
fakobanko-vector's access log shows the first scan's request **never
arrived**. The check `continue`s on `resp.error`, and capture without
`--capture-failures` does not record a failed probe, so **one transient
transport failure silently removed one exchange from the corpus.** (The first
pair recorded 421 in both scans of this check.) Contextual checks now show
**zero** content differences, but that is one pair against a mostly
deterministic range, not evidence that phase 58's sampling has nothing to
measure.

**What this means for the criterion.** *"Identical `probe_hash`es
throughout"* cannot hold across real network noise under the default capture
posture: a probe that fails in one run is absent rather than different. Two
ways to make it assertable: run the measurement with `--capture-failures`, so
the failed probe is recorded with the same `probe_hash` and a different
`content_hash`; or restate the criterion over the probes both runs completed.
**Neither decided; not yet run.**

#### Also found

- **No `llm` exchanges were captured.** CLI scans made no Chainsmith-side model
  calls (the LLM traffic went target-side, to fakobanko's chat and agent
  services, and is captured as `http`). **Criterion 7 is still unverified**
  against a real corpus.
- **Deployment:** `docker-compose.chainsmith.yml` now mounts `./workspace` as
  `CHAINSMITH_WORKSPACE=/workspace`, so the database and evidence survive
  container recreation. The ignored `RECON_DB_PATH` was removed, and
  `/workspace/` is gitignored.
- **`chainsmith.sh start` exits 1** after `up` for every non-`ollama` profile:
  the trailing `[ ... = "ollama" ] && pull_ollama_model` is false under
  `set -e`. The container still starts, but the health wait never runs.
  **Not fixed.**

**Tests:** `tests/capture/test_capture.py` covers the short-hex markers, the
constant probe string not treated as a marker, and the WebSocket headers
(protocol and probe-hash). `tests/grading/test_regrade.py` covers record v2,
context values stored once across checks, compact records, v1 replay, and a
missing value skipping its check.

---
