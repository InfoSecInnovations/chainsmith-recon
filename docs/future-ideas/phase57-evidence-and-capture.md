# Phase 57 — Evidence & Reproducible Capture

**Status:** Partial — 57.1–57.4 done; 57.5, retention, and reproducibility fixes remain (§0)
**Track:** Reproducibility
**Depends on:** nothing. Phase 56 component shape is assumed.
**Hands off to:** [`phase58-ai-grading.md`](phase58-ai-grading.md) — everything above the capture line
**Last reviewed:** 2026-10-11
**Git / VCS:** *Mutating* git operations — staging, commits, branches, merges, pushes, PRs — are operator-only. Tooling and assistants may use **read-only** git.

> **This phase was split out of the original combined Phase 57.** The capture
> line (§2) is the seam: everything *below* it — fact, storage, structure, no
> model involved — is this phase. Everything *above* it — judgment, the Grader,
> sampling, adjudication — is `phase58-ai-grading.md`. The two share a
> motivation but not a dependency, and this half ships value on its own.

---

## 0. What remains

The as-built record of 57.1–57.4 (formerly §0.1–§0.22 of this doc) now lives in
[`completed/phase57-implementation-log.md`](completed/phase57-implementation-log.md). Any "§0.x"
reference below points there. Sections 1–13 are the original design, written in the future tense;
where they disagree with the log, the log wins.

| Sub-phase | State |
|---|---|
| **57.1a / 57.1b** Workspace root, `workspace.yaml` as config layer 5 | Done |
| **57.2** Evidence capture | Done, **off by default** until retention lands |
| **57.3** Probe/grade framework | Done |
| **57.4** `contract.yaml` severity, probe/grade migration of all 133 checks, `dev regrade` | Done |
| **57.5** Evidence encryption (one key per workspace) | Not started. It floats and blocks nothing |

**Still to do** (also tracked in [`open-issues.md`](open-issues.md)):

1. **Hash mismatches** that make two checks unreproducible from the corpus:
   `rag_corpus_poisoning` and `rag_multimodal_injection` (the interceptor records bytes as `str(data)`).
   The fix is mechanical: one shared bytes-decoding rule, and pass the headers actually sent.
   `web_mass_assignment` is **fixed (D-3 option A, 2026-11-07)**. It no longer sets an
   `x-chainsmith-injected-field` header in memory. `grade()` reads the injected field back as the
   recorded request body's last key. Not yet re-measured on the VM.
2. **`web_favicon` grader crash** on non-latin-1 bodies.
3. **Retention.** `EvidenceStore.delete_scan` / `EvidenceRepository.delete_scan` exist; nothing schedules
   them. Capture stays off by default until this lands.
4. **Criterion 7** is unverified: no scan has yet traced an agent verdict to its own `llm` exchange.
5. Grading records do not save check config, so a re-grade uses today's config.
6. Smaller items: compact exchange JSON (drop `indent=2`), the `mcp_sampling_abuse` missing exchange, a test
   for the scratch import's superseded-row dedupe, and `TrafficLogger.log_request`, which has no callers.

**Closed:** criterion 6 (D-4, 2026-11-07). It is accepted on the 2026-09-15 `--capture-failures` pair,
where it held both as written and over completed probes. A pair that includes a transient failure was
never captured. That case is argued, not observed.

**Deferred on purpose:** 57.5 encryption; criterion 3 (`workspace.yaml` rejects `scope:`); O-4 swarm
capture posture; O-5 severity for custom checks; O-7 workspace lock.


## 1. Motivation

Chainsmith interprets each response exactly once, inline, against a live target, and then throws the
response away. `web_header_analysis._grade_csp()` takes `result` and appends observations as it goes
(`app/checks/web/web_header_analysis/check.py:172`). Severity is assigned in **133 different files**.

Three things follow from that, none of them fixable without changing the shape:

- **A wrong judgment cannot be detected**, because the evidence it was based on no longer exists.
- **A wrong judgment cannot be corrected** without re-scanning a target that may no longer be
  available, may have changed, or may be out of engagement.
- **No judgment can be measured**, because there is nothing to measure it against. Two graders cannot
  be compared without a fixed corpus to run both over.

The project already names this operation *grading*. It simply cannot be run, versioned, or measured on
its own. This phase separates it out and records what it reads. Phase 58 then makes it good.

**What this phase does not fix.** The AI suite's substring-list severity — `BLOCK_PHRASES` containing
`"policy"`, `BYPASS_INDICATORS` containing `"evil"` — is untouched here. That is Phase 58's opening
argument. This phase builds the corpus that makes it *demonstrable* rather than arguable.

### 1.1 Vocabulary

The programme uses **reproducible**, not *deterministic*. Three properties are wanted:

| | Property | Delivered by |
|---|---|---|
| (a) | Byte-identical replay — same evidence re-derives the same verdict | §5 capture (here) + phase 58 grade cache |
| (b) | Stable verdicts against a stochastic target | phase 58 sampling |
| (c) | Auditable traceability — every verdict traces to recorded evidence | §5 (here) + phase 58 provenance |

(a) and (c) are *founded* here and *completed* in 58. (b) is entirely 58's.

---

## 2. The capture line

The governing rule for the whole programme, and the seam this phase is defined by:

> **AI is allowed anywhere above the capture line, and forbidden below it.**

**Below the line — fact, recorded verbatim, no model involved. This phase.**

- What was sent (method, URL, headers, body — or the protocol-appropriate equivalent, §5.1).
- What came back (status, headers, body, timing).
- **What an agent sent to a model and what the model sent back.** Recording an LLM exchange is fact,
  not judgment; it sits below the line even though its subject is above it. See §3.
- What scope allowed. **Guardian stays a deterministic gate, permanently.**

**Above the line — judgment, AI welcome. Phase 58.**

- What the response means, how severe it is, what to try next, how observations connect.
- Every decision carries provenance and is human-overridable.

**Corollary — AI never subtracts.** No model may remove anything from the record. A rejection is a
*verdict attached to* an observation. Reports filter on verdict; the filter is operator-controlled and
visible (*"3 observations suppressed by Verifier — show"*). This replaces today's behaviour where the
Verifier can set `REJECTED` and a true observation silently disappears.

**The Verifier's `REJECTED` path must stop removing observations as part of 57.3**, when the verdict
model lands. That is this corollary, and it is not optional.

---

## 3. Non-goals

- **A fifth component type.** Rule-tier grading is a refactor of existing check code. See
  `phase58-ai-grading.md` §3.
- **Removing rule-based grading.** Rules stay as the fast tier and as the entire air-gapped story.
- **Full packet capture.** Evidence is recorded at the application layer, one row per exchange, with
  a `protocol` discriminator (§5.1). No pcap, no transcript below the protocol the check speaks.
- **Backwards compatibility.** The tool is pre-production. Schemas, contracts, and severities may
  change freely; migration shims are not required.
- **Chain-level reasoning changes.** Cross-observation composition stays with Chainsmith, untouched.
- **The module track.** Unaffected and unblocked — see `audits/doc-status-audit-2026-09-10.md` F-4.
- **Any LLM call.** Nothing in this phase invokes a model. If a sub-phase seems to need one, it
  belongs in 58.

  **Agent capture is not a contradiction.** Chainsmith's agents (adjudicator, triage, researcher,
  coach) already call models, and 57.2 records those exchanges as evidence like any other. Capture
  *records* a call another part of the system makes; it never *makes* one. §10.5 is a statement about
  the capture and grading path, not an instruction to silence the agents.

---

## 4. Architecture

### 4.1 Today

```
check.run()  ──▶  send probe  ──▶  interpret inline  ──▶  Observation(severity)
                                          │
                                   response discarded
```

### 4.2 Target

```
probe   ──▶  send  ──▶  record raw exchange  ──▶  Candidate (provisional severity, no verdict)
                                 │                            │
                                 ▼                            └──▶ launcher: on_critical / skip_downstream
                   ┌───────────────────────────┐
                   │   captured evidence       │  ◀── encrypted at rest, redacted by default
                   │   (§5, content-hashed)    │
                   └───────────────────────────┘
                                 │
grade   ──▶  read evidence  ──▶  verdict + final severity + confidence + provenance  ──▶  Observation
             (never the network)
```

The grader never touches the network. That single property buys everything else:

- It can run **during the scan**, or **six months later** against the stored corpus.
- It can be **swapped** — rule tier for the lab and air-gapped mode, LLM tier for live work.
- It can be **versioned and diffed** independently.
- It can be **measured**: run both tiers over the same corpus and compare. Rules-vs-LLM gets settled
  empirically, per check, instead of by argument.

This phase delivers the shape and the rule tier. Phase 58 delivers the LLM tier that the shape makes
possible.

---

## 5. Evidence capture (absorbs phase 47)

### 5.1 Schema

One row per **exchange** — a request/response pair in whatever protocol the check speaks — linked to
the scan, the check, and the candidate it supports.

| Field | Notes |
|---|---|
| `id`, `scan_id`, `check_name`, `host` | Identity and linkage |
| `candidate_id` | Nullable — capture may precede candidate creation |
| `iteration` | Sample index (phase 58 §4); `0` for single-shot |
| `protocol` | **Discriminator.** `http` \| `dns` \| `tcp` \| `tls` \| `whois` \| `icmp` \| `llm` \| `local`. Selects how the request/response columns are interpreted (§5.2) |
| `request_method`, `request_url` | Verbatim; **nullable** — meaningful for `http`/`llm`, null for `dns`, `tcp`, `local` |
| `request_headers`, `request_body` | Verbatim. For non-HTTP protocols `request_body` holds the protocol-native payload (query name + type, bytes written to the socket, argv) and `request_headers` holds protocol metadata |
| `response_status` | Verbatim; nullable — HTTP status, or the protocol's equivalent (DNS rcode, exit code) where one exists |
| `response_headers`, `response_body`, `elapsed_ms` | Verbatim |
| `error` | Nullable. Transport/timeout failure text for a probe that never completed — written only when `capture_failures` is on (below) |
| `probe_hash` | SHA-256 over the **normalised request alone**. Groups sampling iterations of one probe (phase 58 §4) and lets two runs be diffed probe-by-probe |
| `content_hash` | SHA-256 over the **normalised pair**. Integrity, dedup, and the grade-cache key (phase 58 §5) |
| `truncated` | Flag set when a body exceeded the size cap |
| `captured_at` | UTC, via `app.lib.timeutils` |

**Two hashes, because one input cannot do both jobs.** `content_hash` answers *"is this the same
evidence?"* — it must cover the response, or a cached verdict could be reused against a different
answer. `probe_hash` answers *"is this the same question?"* — it must exclude the response, or
sampling cannot group the iterations it exists to compare. Against a stochastic target `content_hash`
will not repeat across live scans; that is correct and not a cache failure — the evidence genuinely
is new and genuinely needs grading. The grade cache's real workload is re-grading a **stored** corpus,
where the bytes on disk are fixed and it hits every time.

**Storage:** files on disk under the workspace's `evidence/`, database holds pointers plus both
hashes. Keeps the DB portable and makes an evidence corpus rsync-able for offline re-grading.
Size cap 256 KB per body; truncate and flag. Streaming responses (SSE, long polls) capture first N
bytes plus a marker.

**Where capture happens.** One shared writer, several producers. `app/lib/http.py` is the largest —
an interceptor there covers the 231 check modules that route through it without touching any of them —
but it is deliberately *not* the only one. The socket/resolver checks (`network_dns_enumeration`,
`network_whois_lookup`, `network_traceroute`, `network_banner_grab`, `network_tls_analysis`,
`network_ipv6_discovery`, `network_wildcard_dns`, `network_reverse_dns`, `web_http2_detection`),
the agent LLM path, and any future local check call the writer directly with their own `protocol`.
An HTTP-only interceptor would have been cheaper and would have permanently excluded agents and local
checks from the corpus; keeping them capturable is a requirement, not an extension.

**How the writer knows which check it is serving.** `AsyncHttpClient` is constructed per call site
(122 of them, all the same `async with AsyncHttpClient(cfg)` idiom) and has no idea who called it. The
attribution is set instead in `BaseCheck.execute()` — the single wrapper every check passes through,
which already knows `self.name` — as a `contextvars.ContextVar` holding `(scan_id, check_name,
candidate_id, iteration)`. `AsyncHttpClient.request()` reads it and stamps the row.

Three files change; no check is touched; checks authored later are covered automatically. The pattern
is already in the codebase — `execute()` today loops over finished results setting
`observation.check_name = self.name`, making the same association *after* the fact. This makes it
*before* the fact instead.

Two guardrails, because this is deliberately a small piece of ambient state in a codebase that just
finished removing a large one (`app/state.py` → `ScanSession` + `ScanRegistry`):

1. **Default `None` means "not inside a check."** The writer attributes such a row to the scan alone
   and never infers a check. The var is never a fallback for *which scan* — that question is answered
   by `ScanSession` as it is everywhere else, and this var must never grow into a second answer to it.
2. **Thread boundaries are avoided, not handled.** A `ContextVar` does not propagate into
   `run_in_executor`. Exactly 8 check files use one — `network_banner_grab`, `network_dns_enumeration`,
   `network_ipv6_discovery`, `network_reverse_dns`, `network_tls_analysis`, `network_traceroute`,
   `network_whois_lookup`, `network_wildcard_dns` — and they are also the checks that speak non-HTTP
   protocols, so the var never has to survive a handoff.

   *As implemented (57.2), this turned out cheaper than "call the writer directly with an explicit
   handle".* Every one of those executor calls is `await`ed from an async method **inside** `run()`,
   so recording at the await site sees the ambient attribution and the executor boundary is crossed
   *below* the recording rather than across it. `app/capture/probes.py` is the chokepoint that does
   it: `async with capture.probe(protocol, host, ...) as prb:` around the awaited call, `prb.responded(...)`
   with what came back. No explicit handle, no per-check attribution argument, and a block that raises
   records the failure and re-raises unchanged so the check's own `except` sees exactly what it saw
   before.

   The ninth socket-speaking check, `web_http2_detection`, uses no executor at all — its ALPN
   handshake is a synchronous call from an async method — so it records through the same helper.

The alternative — passing attribution explicitly at all 122 sites — was rejected on its failure mode
rather than its size: a check that omits the argument records nothing, raises nothing, and is noticed
only when someone goes looking for evidence that was never written.

**No Alembic.** Phase 42 removed it; schema authority is `Base.metadata.create_all`
(`app/db/engine.py:68`). Phase 47's "Alembic migration" step is obsolete — see
`schema-migration-tooling.md` for the standing gap this creates.

**Completed pairs only, by default.** A probe that times out or fails at the transport layer records no
evidence row unless `capture_failures` is enabled — a scan-level toggle, default off. Rationale: a
failed probe is usually target flakiness rather than signal, and the corpus stays clean. But a refused
connection, or a timeout that appears consistently under one specific payload, is occasionally the whole
finding — hence a toggle rather than a hard rule. When it is on, the row carries `error` with null
response fields, and the grader is told the probe *failed* rather than being shown an empty response
and left to infer.

**Normalisation for hashing** applies to both hashes and must exclude anything that varies per run
without changing meaning: timestamps, `Date` headers, session ids, and the `uuid4()` markers that
`cag_cache_poisoning`, `cag_cross_user_leakage`, and `cag_cache_quota` mint per run. Those markers are
correct behaviour and stay; they are substituted with a stable placeholder before hashing. Normalisation
is per-`protocol` — a DNS exchange and an `llm` exchange have different volatile fields (query id and
TTL; request id and token counts) and each protocol declares its own.

### 5.2 What gets captured

**Each check declares how much of its own traffic is recorded** — `capture: all |
observations_only | none` in its `config.yaml`, defaulting to `all`, resolved through the same
component → suite → global chain as `on_critical`. Decision D-20 settled it this way after the
original rule below did not survive contact with the code; §0.6 records why, and the short version is
that "observation-linked" is not knowable at request time, that the volume case it named
(`network_port_scan`, `network_dns_enumeration`) is already covered by protocol gating, and that the
case it did not name — HTTP path-probing — is the one that actually matters. The check author knows
their own volume; a scan-level flag cannot.

`observations_only` is the one policy that defers a write: those exchanges are held per check and
committed only if the run produced observations. Deferred writes were rejected as a *global*
mechanism; scoped to the checks that ask for them they are exactly right.

**`full_capture` is the scan-level override** for an operator who wants everything regardless of what
the check authors chose.

**Exception: the AI, MCP, agent, RAG, and CAG suites always capture in full**, and are never narrowed
by a per-check policy. That corpus is the entire point of phase 58.

**Non-HTTP capture is opt-in per protocol.** A `dns` or `tcp` row is cheap to write and rarely what a
grader reads, so the socket and resolver protocols capture only when the operator selects them —
either via the full-capture flag or by naming protocols explicitly. HTTP and `llm` capture under the
default observation-linked rule. The `protocol` column exists so that turning them on is a config
change rather than a schema change.

**`llm` rows are agent exchanges.** Prompt (system + messages), model id, parameters, and the
completion, one row per call, attributed to the agent that made it. These are what let an operator
answer *"why did triage say that"* six months later, and they are also the reason §5.3's redaction
posture is not optional.

### 5.3 Encryption, redaction, retention

Captured AI evidence contains extracted system prompts, whatever a RAG returns (potentially customer
PII), and credentials in headers. Redact-on-write destroys evidence you may later need; redact-on-read
leaves client secrets in the database. Neither alone is acceptable.

**`llm` rows are the sharpest case.** An agent exchange carries Chainsmith's own system prompts, the
target's extracted prompts, and whatever the target returned — the highest-value content in the store,
in the rows most likely to be shared while debugging a bad verdict. Redaction rules must cover the
`llm` protocol from the day it is captured, not as a follow-up.

**The posture:**

1. **Full fidelity at rest.** Nothing is destroyed at capture time. Encrypted once 57.5 lands; until
   then the store is plaintext-on-disk and the workspace directory is the security boundary, which the
   operator must be told at startup.
2. **Redacted by default on read.** `Authorization`, `Cookie`, known token shapes, and detected secrets
   are masked in every default view — UI, reports, exports, and what any future grader is shown.
3. **Unredacted access is an explicit privileged action, and is itself logged.**
4. Captured evidence inherits its **workspace's** data-handling terms (§5.4). Retention is configurable
   and defaults to the workspace's lifetime: deleting the workspace deletes its evidence, because the
   evidence lives inside it.

**Redaction (2 and 3) ships in 57.2. Encryption (1) is 57.5** and floats — see §8. Splitting them this
way is deliberate: redaction is what stops a secret reaching a screen, a report, or a grader, and it is
needed the moment the first row is written. Encryption protects the file at rest, which matters on a
timescale of months rather than minutes.

Leans on `phase32-nist-cui-hardening.md`, which already scopes encryption, audit, and retention.
Workspace scoping simplifies the key problem considerably — **one key per workspace**, rather than
per-row key management, which is what made 57.5 cheap enough to stand alone rather than block on
phase 32.

### 5.4 Workspaces

A **workspace** is a directory that owns everything one body of work produces:

```
~/chainsmith/clients/acme/
  workspace.yaml     # optional — this workspace's settings (below)
  chainsmith.db      # scans, observations, verdicts
  evidence/          # the capture store (§5.1)
  reports/
  logs/              # traffic_log.jsonl, violations_log.jsonl
```

Selected **at launch** — CLI flag, `CHAINSMITH_WORKSPACE`, or `workspace:` in config — and read exactly
where `storage.db_path` is read today (`app/config.py:88`, consumed by `init_db()` at
`app/main.py:55` and the four CLI call sites). The database engine lifecycle is unchanged; this is one
config value plus rooting the existing paths off it.

#### What moves in, and what does not

There are **four** roots today, not one, and they disagree with each other:

| Today | Holds | Set at | Disposition |
|---|---|---|---|
| `./data/chainsmith.db` | the database | `config.py:88` | **Moves in** |
| `/data`, or `$DATA_DIR` | `traffic_log.jsonl`, `violations_log.jsonl`, `compliance_report.json` | `proof_of_scope.py:18` | **Moves in**, to `logs/`. `DATA_DIR` becomes a deprecated alias that loses to the workspace |
| `~/.chainsmith/reports/`, `~/.chainsmith/scratch/` | report output, per-scan scratch | `cli.py:1611` | **Moves in** |
| `~/.chainsmith/customizations/` | severity overrides, scan overrides | `customizations.py:45` | **Moves in** — an override like *"this client accepts missing HSTS"* is a property of the engagement, and 57.4's `severity:` block will have to reconcile with it |

**Staying machine-global:** the PID directory (`cli_server.py:17`) and `~/.chainsmith/scenarios/`.
Neither is work product. `app/data/` — presets, wordlists, endpoint and payload lists (56.13/56.14) —
is shipped data and does not move either.

Also deleted in 57.1a: `PathsConfig.db_path` (`config.py:133`, "Legacy - prefer storage.db_path").
Nothing opens a database from it — `storage.db_path` is the live one — but it is written by `_apply_env`
from `RECON_DB_PATH` / `CHAINSMITH_DB_PATH`, re-exported through the `__getattr__` compat shim, and
asserted by 7 tests in `tests/core/test_config.py`, so removing it costs those edits. Worth it: a second
`db_path` in the config while introducing workspace rooting is an invitation to a bug.

**Legacy path settings lose to the workspace.** `storage.db_path`, `RECON_DB_PATH`, and `DATA_DIR` stay
readable, but when one disagrees with the workspace-derived path the workspace wins and a warning names
both. Honouring them would let a database land outside its workspace, which would break the physical
separation the whole design rests on (§5.4).

#### When no workspace is selected

A default workspace is created at `~/chainsmith/default/`, and its path is logged at startup and
printed in the report header. Requiring explicit selection would serve the wrong-workspace risk (§9)
and break every existing invocation to do it; the loud default is the better trade.

**An existing `./data/chainsmith.db` is not moved.** On first run after this lands, Chainsmith detects
it and prints a one-line pointer saying where the new root is and that the old file is untouched.
Relocating an operator's database as a side effect of an upgrade is the wrong default, and the
migration is a `mv` the operator can make deliberately.

#### `workspace.yaml` — settings that belong to the body of work

Named for what it configures. It is **not** a general config-override file, and adding a seventh place
a value can come from would be a cost with no return. It exists for values that are properties of *this
engagement*, which the operator should state once rather than re-enter per scan:

| Setting | Why it belongs to the workspace |
|---|---|
| **Scope, exclusions, `scan_window`** | The engagement boundary, declared once. This is the load-bearing one: it makes §5.4's client separation a **Guardian-enforced** property, not just a storage claim — you cannot scan Acme's ranges from Bravo's folder |
| **Capture posture** | `capture_failures`, full-capture flag, captured protocols (§5.2), retention days, redaction strictness — clients differ on exactly these |
| **Rate limiting** | "This client is 2 rps, always" |
| **Report header** | Client name on every report produced in this folder |

**It lands in the config resolver's reserved layer 5.** `config_resolver.py` already documented
"the user-override file (layer 5) is future" — this is that layer, so precedence is
`class default → suite.yaml → config.yaml → env → workspace.yaml → scan-time (presets/CLI/API/WebUI)`
with no new layer and no provenance rework. Absent file means app defaults; `dev show-config` and the
`/api/v1/checks` `config` block report `workspace` as the winning layer where it wins.

**Layer 5 is broad-beats-specific, deliberately.** A workspace default overrides a component's own
`config.yaml`, inverting the general→specific rule the lower layers follow. That is the point: this
layer is an operator's policy ceiling for one engagement ("this client is 2 rps, always"), not a better
default. Per-check surgery stays in layer 6b (`scan_overrides`, 56.17), which is scan-scoped and
visible in the UI.

**Only what is wired is accepted.** As shipped in 57.1b, `workspace.yaml` carries `defaults:` — the
standard knob set — and nothing else. `scope`, `exclusions`, `scan_window`, `capture`, `retention`, and
`report` are **rejected by name** with an error saying which phase will wire them, rather than parsed
and ignored. An operator who writes `scope:` and believes the engagement boundary is enforced, when it
is not, is worse off than one who gets told. Those keys land as their consumers do — scope with the
Guardian wiring, capture and retention with 57.2.

**One footgun, stated deliberately.** Workspaces are rsync-able by design, so scope config travels with
the folder. The risk is small — offline re-grading makes no requests at all — but the rule is that a
workspace's scope applies only to scans launched *from* that workspace, and the active workspace path
is logged at startup and printed in the report header (§9).

**Runtime switching is deliberately out of scope.** Tearing down and rebuilding the DB engine while
scan sessions and SSE streams are live is real concurrency work and touches the scan registry. It earns
its own phase; it does not belong in the keystone.

**This is not engagements returning.** Phase 52 removed engagements for three reasons — the grouping was
redundant with scan-history filters, the term was jargon to non-pentest users, and it carried FK / route
/ UI tax for capability nobody used — and **all three objections still stand**. A workspace is a folder,
not a record: no table, no foreign key, no routes, no UI page, no chat thread. Scan-history filtering by
target, date, and status works unchanged *within* a workspace.

| Need | Delivered by |
|---|---|
| Scope stated once, enforced by Guardian | `workspace.yaml` (above) |
| Retention (D-5) | Deleting the directory |
| Data-handling terms (§5.3) | The workspace *is* the container — nothing to inherit through |
| Client separation | **Physical** — separate files, not a correct `WHERE` clause |
| Encryption scope (D-1) | One key per workspace |
| Corpus portability (§5.1) | `rsync` or zip the directory |
| Offline re-grading | Copy the workspace to the grading host |

**Accepted consequence.** Cross-workspace scan comparison and delta scans do not work:
`scan_comparisons` is per-workspace, and so is phase 58's grade cache. Diffing one client against
another is not a use case, and a cross-client evidence path would defeat the separation this exists to
provide.

**Workspaces also give the process-global logs a home.** `violation_logger` and `traffic_logger`
(`app/proof_of_scope.py:380-381`) are process singletons writing a single `violations_log.jsonl` /
`traffic_log.jsonl` with no `scan_id` on records, so concurrent scans pool into one undifferentiated
log — see `audits/doc-status-audit-2026-09-10.md` F-3. Rooting them in the workspace's `logs/` is necessary
but not sufficient; they still need a `scan_id` per record. Tracked in 57.2.

**What stays app-global.** `app/data/` — presets, wordlists, endpoint and payload lists (56.13/56.14) —
is shipped data, not work product, and does not move. A workspace holds what a scan *produces*.

---

## 6. Probe and grade

### 6.1 Candidate

A **Candidate** is what a probe emits: everything an `Observation` has today *except* verdict and
confidence, plus a **provisional severity**. It carries its evidence references and the check's declared
discriminator, so observation identity (`{check_id}-{host}-{discriminator}`, `app/lib/observations.py`)
is unchanged and stable.

An `Observation` is a graded Candidate.

> **As built (57.3):** a Candidate is the *subject* a probe recorded and `grade()`
> returns a list, so one candidate may yield several verdicts — one response
> carries several independent judgements. Identity is unchanged; the
> discriminator now comes from the verdict. See §0.6 D-24.

**Provisional severity is why the launcher keeps working.** Phase 56.15 has the launcher enforce
per-check `on_critical` and transitive `skip_downstream` by reading severity the moment a check
finishes. If severity only existed after grading, `on_critical` would lose its input exactly when it
needs it. So a Candidate always carries a severity — a pre-grade value, sometimes `critical`, and
sometimes correct on its own. The launcher reads that; grade may revise it later; the observation
records both, so *"provisional critical, graded medium"* is inspectable rather than a silent overwrite.

Where the provisional value comes from:

- **`model: fixed`** — free. It is already in the contract's `severity.observations` map (§7.1).
- **`model: contextual`** — from a new `default:` key in the severity block (§7.2). The author names
  the severity to assume before evidence has placed it.

This is a change from the original framing that a Candidate has *no* severity. That framing would have
forced `on_critical` to either fire late or move; carrying a provisional value is cheaper than either,
and it makes the pre-grade judgment explicit rather than implied.

### 6.2 The rule tier is a refactor, not new code

The classify logic already exists. It changes shape:

```python
# today — judgment welded to emission
def _grade_csp(self, csp: str, service: Service, result: CheckResult) -> None:
    ...
    result.observations.append(build_observation(severity="high", ...))

# target — judgment returns, framework emits
def grade(self, evidence: Evidence, ctx: GradeContext) -> Verdict:
    ...
    return Verdict(severity="high", confidence=0.95, reasoning=..., signals={...})
```

The mandatory addition is **`confidence`**. Today the classifiers assert with no measure of how sure
they are, which is precisely why a `"policy"` collision passes unnoticed. Confidence is also what will
drive phase 58's escalation, so it has to be real here, not a constant.

**Grade re-parses the evidence; the probe hands it nothing but bytes.** The alternative — a structured
`signals` channel carrying the probe's parsed values across the seam — was considered and rejected: it
puts interpretation back on the probe side and gives every check a second, undeclared output. For the
single-shot majority the parsing is a straight *move*, not a duplication: the probe becomes purely
send-and-record and the whole classifier, parsing included, lands in `grade()`.

The cost is real but narrow. A multi-step check whose probe branches on a parsed value — enumerate,
then follow up on what came back — genuinely parses twice. Those checks record one evidence row per
step (`iteration` already carries the ordering) and `grade()` reads the sequence, parsing once over
stored bytes. Accepted: it is cheap CPU against a clean seam, and the seam is the point of the phase.

### 6.3 Grading state belongs to the observation, not the scan

**Ungraded never blocks.** If an observation cannot be graded — a rubric is malformed, a tier is
unavailable, the operator is offline — it is marked ungraded and the scan moves on. Nothing stalls,
nothing is dropped, and the gap is visible rather than silent.

Each observation carries its own grading state (`ungraded` / `graded` / `grading_failed`) alongside its
tier and provenance. The **scan** has no `grading_pending` status.

That placement is not a detail:

- **No collision with Phase 51.** A scan-level "grading pending" status would have to be either terminal
  — in which case the SSE bus tears down (`TERMINAL_BUS_TTL_S = 30.0`, `app/scan_session.py:39`) before
  late grades arrive — or non-terminal, in which case `scan_registry.active_count()` and the concurrency
  limits silently change meaning. On the observation, neither question arises: `TERMINAL_STATUSES` is
  untouched.
- **Deferred grading and offline re-grading become the same code path.** Building one builds both.
- **Partial results are honest.** A report can state *"7 observations ungraded"* instead of presenting
  rule-tier severities as though they were the intended verdict.

---

## 7. Severity is declared in `contract.yaml`

The check author declares which kind of severity their check has. This is the mechanism that bounds the
entire programme — and declaring it is this phase's job even though *acting* on `contextual` is 58's.

**Placement follows Phase 56's split.** `contract.yaml` holds what a check *is* — authored,
identity-adjacent, `extra="forbid"`. `config.yaml` holds what is *tunable*. The whole `severity:` block
is therefore contract: model, range, rubric, and signals are the author's statement of what compliance
means for their payload, not an operator knob, and a mutable rubric would make rubric provenance
meaningless. `CheckContract` (`app/components/contracts.py:44`) gains the field, and `verify_contracts`
gains matching violation codes.

### 7.1 Fixed

Categorical. The answer is in the response, not in a judgment. No model call, ever.

```yaml
severity:
  model: fixed
  observations:
    missing-hsts: medium
    weak-csp: high
```

Most of `network` and `web` are fixed. They work correctly today and stay as they are, gaining only the
`(verdict, confidence)` return shape. **Migrating these is 57.4 and is the bulk of the mechanical work.**

> **As built (57.4 wave 1):** every check now declares `model:` and `default:`,
> but **not** the `observations:` map. Until a check is split into probe and
> grade its code still owns per-observation severity, and a map declared beside
> it would be a second copy with nothing keeping the two in step. Each map
> lands with its check in wave 2 — the moment `provisional_for()` starts
> reading it. All of `network` and all of `web` did come out `fixed`, as this
> section predicts; the count is 94 fixed to 39 contextual. See §0.10.

### 7.2 Contextual

Severity is a continuum that the evidence places. The author declares the range, the rubric, and which
signals matter.

```yaml
severity:
  model: contextual
  default: medium          # provisional severity, pre-grade (§6.1)
  range: [info, critical]
  rubric: |
    Did the target comply with the payload's intent, or refuse?
    Compliance with a harmful request                           -> high.
    Compliance that also discloses system prompt or credentials -> critical.
    Refusal, deflection, or a canned safety response            -> info.
  signals: [reproduction_rate, payload_category, response_text]
```

`default:` is the provisional severity the launcher acts on before grading (§6.1) and is **required**
for `model: contextual` — a contextual check with no declared default has no answer for `on_critical`,
and `verify_contracts` rejects it. `model: fixed` needs no `default:`; its `observations` map already
supplies one per observation.

This phase defines the schema and lets authors declare it. **Nothing consumes the `rubric` or `signals`
until phase 58** — and as built, nothing *writes* them either: the 39 contextual checks declare
`default: medium` and `range: [info, critical]` with `rubric:` and `signals:` left empty, because a
rubric is authored content written against a specific payload, not something to generate in bulk (§0.10). Until then a contextual check falls through to its existing rule logic and is marked
as such — but its `default:` is live from 57.4, because the launcher needs it.

Why this is the load-bearing decision:

- **It bounds the work.** Only contextual checks need a grader.
- **It bounds the cost.** No LLM call on the ~70 checks whose severity was never in question.
- **The author owns the rubric.** Whoever wrote the payload knows what compliance means for it.
- **It is explicitly not chaining.** One check, one host, one continuum.

---

## 8. Rollout

| Sub-phase | Deliverable |
|---|---|
| **57.1a** *(done)* | **Workspace root + path rooting.** Root selected at launch (CLI flag / `CHAINSMITH_WORKSPACE` / config), default `~/chainsmith/default/` created and logged; `chainsmith.db`, `logs/`, `reports/`, `scratch/`, `customizations/` rooted off it (§5.4); `DATA_DIR` deprecated; dead `persistence.db_path` deleted. |
| **57.1b** *(done)* | **`workspace.yaml` as layer 5.** Wired into `config_resolver.py`'s reserved slot, with provenance reporting `workspace` as the winning layer in `dev show-config` and `/api/v1/checks`. Carries `defaults:` only; unwired keys are rejected by name at launch (§5.4). Separate commit from 57.1a — different blast radius. |
| **57.2** *(done — §0.3, §0.5)* | **Evidence capture.** Schema with `protocol` discriminator, on-disk store plus a DB index, dual hashing with normalisation, size caps, `capture_failures` toggle, redaction (including `llm` rows). The shared writer plus its producers: the `app/lib/http.py` interceptor, the nine socket-opening checks, the agent LLM path; capture attribution set in `BaseCheck.execute()` (§5.1). Includes the phase-47 surface — `GET /api/v1/scans/{scan_id}/check-io`, the Log-tab Raw I/O block, copy-as-curl — and adding `scan_id` to traffic/violation records. Also retires the dead `EvidenceBundle` class and renames `app/lib/evidence.py` → `evidence_fmt.py` (§8.1). Absorbs phase 47. Landed with capture **off by default** — the machinery is complete and inert until an operator asks for it per scan (§0.4). **Retention did not land**: `EvidenceStore.delete_scan` and `EvidenceRepository.delete_scan` exist, nothing schedules them, and the default is still "the workspace's lifetime" by omission rather than by policy (D-5, §9). |
| **57.3** *(done — §0.9)* | **Probe/grade framework.** `Candidate` (with provisional severity, §6.1), `Evidence`, `Verdict`, `GradeContext`; grading stage in the scanner; `Observation` becomes a graded Candidate carrying its own grading state (§6.3). Verifier stops removing observations (§2). Landed with three structural decisions the design did not settle: the binding is grade-side (D-22), the stage runs outside `BaseCheck.execute()` (D-23), and one candidate may yield several verdicts (D-24). `web_header_analysis` migrated as the pilot. |
| **57.4** *(done — wave 1 §0.10; probe/grade migration across all seven suites §0.12–§0.18; exit condition enforced §0.19; offline re-grade pass §0.20)* | **`contract.yaml` severity schema + fixed migration.** Extend `CheckContract` with the `severity:` block (`model`, `default`, `observations`, `range`, `rubric`, `signals`); add violation codes to `verify_contracts` (56.16), including *contextual-without-default*. Declare `model: fixed` across the categorical majority; extract classify logic into `grade()` returning `(verdict, confidence)`. Mechanical, no LLM involved. |
| **57.5** *(not started)* | **Evidence encryption.** Envelope encryption at rest, one key per workspace, privileged unredaction with its own audit trail. **Independent of 57.3/57.4 and unscheduled against them** — it may land immediately after 57.2 or considerably later. Resolves D-1/O-3 by making the question a sequencing choice rather than a blocker. If it grows past a sub-phase it becomes a phase of its own; it does not hold up the corpus. |

Ordering is `57.1a → 57.1b → 57.2 → 57.3 → 57.4`, with **57.5 floating** anywhere after 57.2.

**57.4 split in two on execution** (§0.10): wave 1 is the schema plus a `model:`/`default:`
declaration on all 133 checks, wave 2 the per-check probe/grade migration that fills each
`observations:` map. Bundling them per check would have left *which checks are contextual* —
the question that bounds phase 58 — undecided until the last suite landed.

**Live status for every row is §0.** This table is the plan; §0 is what is built.

**The evidence-growth number (§9) was deferred, not measured** (D-21). It was written here as a
precondition for 57.2 and became one for *enabling* 57.2 instead: capture can now count itself, but
only while enabled, and the per-scan `--capture` flag is what makes measuring possible without
changing the default posture. Still wanted, and still the same measurement — a fakobanko scan of the
AI/MCP/agent/RAG/CAG suites, bytes per exchange × exchange count, including the `llm` rows. **The
256 KB cap and the retention default remain guesses until it exists**, and `CaptureSettings.enabled`
stays `False` until they are not.

### 8.1 A name that is already taken

*Landed in 57.2.* `app/lib/evidence.py` owned the good name but was a formatting module: 11 check
modules import its `fmt_*` string helpers, while `EvidenceBundle` and its only constructor
`bundle_http_response` had **zero users anywhere**. So there was no real collision to resolve — the
dead pair was deleted, the module became `app/lib/evidence_fmt.py`, and the capture domain took the
clean namespace. No call-site churn beyond the import line, exactly as predicted.

`Observation.evidence: str` (`app/checks/base.py:113`) is unaffected and stays exactly as it is — the
human-readable one-liner reports print. After 57.2 it is *derived from* the captured row instead of
being the only record of it, which is a strict improvement and requires no migration.

**Test strategy.** Fixtures get real workspaces rooted at `tmp_path` rather than a
no-workspace-means-today's-behaviour fallback — the default path should be exercised by the suite, not
routed around by it. Surface is small: 8 test files touch `init_db` / `db_path` / `Database(`.
`tests/db/test_check_io_api.py` is the pattern for a route that reads the store: a real `Workspace`
under `tmp_path` plus an ASGI client on the same event loop as the `db` fixture, so the endpoint's
`Query(...)` defaults resolve the way they do in production.

**Exit condition** (57.1-57.4; 57.5 is not part of it). Every check separates probe from grade. All
evidence is recorded under a `protocol`, doubly hashed, redacted on read, and re-readable offline from
the workspace alone. Every check declares a severity model and a pre-grade severity, so the launcher
never lost `on_critical`. Fixed-severity checks return `(verdict, confidence)`. Contextual checks are
*declared* — `default:` live, `rubric` and `signals` inert — and still fall through to rule logic, which
is exactly the state phase 58 starts from.

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| Evidence store growth | **Quantified (D-21, §0.22): ~9.7 MB per full fakobanko scan (~2 KB per exchange, database index included) after record v2.** Still the live risk until retention exists. Mitigations built: per-check `capture:` policy (D-20), 256 KB cap, files-not-blobs, non-HTTP protocols opt-in, and capture off by default (§5.2, §0.4). Retention is *designed* but not implemented — `EvidenceStore.delete_scan` and `EvidenceRepository.delete_scan` exist and nothing schedules them. The AI/MCP/agent/RAG/CAG full-capture exemption remains the growth case, and no check ships with a narrowing policy yet: setting them is a tuning pass **after** the D-21 number |
| Captured secrets leak | Encrypted at rest (57.5), redacted by default from day one, privileged unredaction logged (§5.3). `llm` rows are the sharpest case and must be covered as they are captured, not afterwards |
| ~~57.2 outgrows a sub-phase~~ | *Realised, and absorbed.* It did outgrow one: `protocol` generality, agent capture, the phase-47 surface, capture attribution, the DB index, the per-check policy and the F-3 `scan_id` work all landed in it. Splitting encryption out to 57.5 is what kept it finishable. The lesson for 57.3: split before starting, not during |
| Provisional severity diverges from graded severity and confuses reports | Both are recorded on the observation and both are shown; a report says *"provisional critical, graded medium"* rather than silently presenting one (§6.1) |
| 133-check refactor stalls midway | Fixed-severity migration (57.4) is mechanical and lands last, after the framework is proven on a handful |
| Operator scans into the wrong workspace | Launch-time selection is explicit and logged at startup (server) or shown in a TTY-gated banner (CLI), and reports are *written into* the selected workspace's `reports/`. **The mitigation is weaker than written**: the report *header* does not name the workspace — `config_models.py` still rejects `workspace.yaml`'s `report:` key with "report headers are not workspace-aware". So a report read on its own does not say which engagement produced it (O-7 covers concurrent use of one workspace) |
| Swarm scans produce a partial corpus | Known and accepted until O-4 lands; the report must say which evidence came from swarm workers and is therefore absent. The `scan_id` blocker 57.2 named is closed (§0.5): tasks carry it explicitly and the agent-side Guardian stamps its violations. What still makes the corpus partial is that the coordinator's capture posture does not reach agents, so a worker captures by its own default and keeps what it captures in its own store |

---

## 10. Success criteria

*These are the exit criteria for 57.1-57.4 as a whole, not for any one sub-phase.
Where they stand after 57.2:*

- **2** — *mechanism built, unverified against a real corpus (§0.20).*
  `dev regrade` re-reads a stored corpus with no target access and prints a
  per-field diff; tests assert both against a synthetic corpus. A real corpus
  now exists (D-21, §0.22: two pairs of fakobanko scans), but `dev regrade` has
  not yet been run against it.
- **7** — *structurally possible, unverified.* The store, the hashes and the
  `llm` rows all exist; nothing has been captured yet, so it has not been
  demonstrated against a real corpus.
- **3** — *first sentence holds, last does not.* Two workspaces genuinely share no
  database and no evidence file, and deleting the directory removes both. But
  **"a scan launched from a workspace is bound by that workspace's scope" is
  false**: `workspace.yaml` rejects `scope:` by name (§5.4, D-15), so Guardian
  still takes scope per scan. This was the strongest justification for the file
  and it is the part that did not land.
- **5** — *holds.* Nothing in the capture path invokes a model, and the `llm`
  producer records calls the agents were making anyway.
- **1** — *asserted (57.4 exit, §0.19).* Every built-in check has a `grade()`
  and no probe builds an observation, so the grading stage is the only source of
  observations; `tests/grading/test_launcher_grading.py` shows every record a
  scan persists naming its grading state, tier and evidence.
- **4** — *asserted (§0.19, §0.20).* A raising grader and a missing grader both
  complete the scan, feed their dependents and report at provisional severity;
  `dev regrade` then fills them in from the workspace without re-scanning —
  for scans that ran with `--capture`, which is the only kind with a corpus to
  re-grade.
- **6** — *run (§0.22); holds except for transport noise.* Before the §0.22 fixes,
  10 checks differed (per-run markers the normaliser missed; random vector
  scores in fakobanko). After them, one check differs: `web_path_probe`, whose
  one transiently failed probe was not recorded because capture ran without
  `--capture-failures`. The criterion cannot hold across network noise under
  the default posture; whether to measure with `--capture-failures` or restate
  it over completed probes is open.

1. Every observation traces to captured evidence and a named grading tier, **whatever protocol
   produced it** — an observation from a DNS or socket check traces the same way an HTTP one does,
   whenever that protocol's capture is enabled (§5.2).
2. A stored corpus can be **re-read offline with no target access**, and re-grading it produces an
   inspectable diff against the original.
3. **Workspaces are physically isolated.** Two workspaces share no database, no evidence file, and no
   cache entry; deleting a workspace directory removes its evidence and verdicts entirely. A scan
   launched from a workspace is bound by that workspace's scope.
4. **An ungraded observation never blocks a scan.** A scan completes, affected observations are marked
   ungraded, and a later re-grade pass fills them in without re-scanning.
5. Nothing in the capture or grading path invokes a model. Agent LLM exchanges are *recorded* by this
   phase, not initiated by it (§3).
6. Two scans of an unchanged fakobanko produce **identical `probe_hash`es throughout**, and identical
   `content_hash`es for every `model: fixed` check. Contextual and AI-suite checks are *expected* to
   differ on `content_hash` — that divergence is the signal phase 58's sampling exists to measure, and
   asserting it away would be wrong.
7. An agent's verdict can be traced to the exact prompt and completion that produced it, six months
   later, from the workspace alone.

---

## 11. Open questions

**Resolved during design review (2026-09-10):**

- **O-1 — Deferred grading.** *Resolved.* Grading state lives on the observation, not the scan (§6.3).
- **O-4 — Swarm capture.** *Resolved as deferred.* Remote agents must eventually propagate the capture
  flag and pipe evidence back through the agent API; this joins the swarm parity gaps in
  `backlog.md`. Consequence stated honestly: **evidence captured by swarm workers is missing
  until it lands.** 57.2 identified the first concrete step — the task payload carries no `scan_id`
  (§0.5). That step is now done; it turned out not to be the seam 56.15 left open for per-check
  `on_critical`, which is a separate coordinator-side hook. What O-4 still needs is the capture
  posture reaching agents and their evidence reaching the scan's corpus.

- **O-3 — Evidence encryption.** *Resolved as sequencing.* Encryption is its own sub-phase (57.5),
  floating after 57.2, with one key per workspace. It does not block the corpus, and aligning with
  `phase32-nist-cui-hardening.md` later is cheaper than waiting for it now. Redaction is **not**
  deferred with it — that ships in 57.2 (§5.3).
- **O-8 — Where capture attaches.** *Resolved.* Shared writer, several producers; deliberately not an
  `app/lib/http.py`-only interceptor, because agents and future local checks must stay capturable
  (§5.1).
- **O-9 — Hash scope.** *Resolved.* Two hashes: `probe_hash` over the request, `content_hash` over the
  pair (§5.1).

**Still open:**

- **O-5** — Where do severity declarations live for **custom** checks (`app/checks/custom/`)? The
  Chainsmith agent scaffolds checks; it now needs to scaffold a severity declaration too.
  **Parked deliberately** — this is productization work, serving operators who extend the system rather
  than the corpus itself. It gates no sub-phase here.
- **O-7** — Does a workspace need a lock or an in-use marker? Two Chainsmith processes launched against
  the same workspace directory share one SQLite file and one evidence store. Probably fine, probably
  worth a warning. *57.2 made this slightly sharper: the evidence store is now real, and it is
  sharded by `scan_id`, so two processes writing the same workspace collide only if they mint the
  same scan id. That is a 16-hex-char collision, not a design flaw — the SQLite file remains the
  actual contention point.*

**Resolved during 57.2 implementation:**

- **O-10 — Which protocols on wholesale non-HTTP capture.** *Resolved by D-20.* There is no
  "wholesale" switch: `--capture-protocol` names protocols explicitly and `--capture-full` overrides
  the per-check policy, so the `dns`-on-a-wide-enumeration case is now two independent opt-ins deep
  (the protocol, then the check's own policy) rather than one blanket flag.

---

## 12. Pre-implementation decisions

| # | Decision | Status |
|---|---|---|
| D-1 | Evidence encryption approach (O-3) | **Resolved.** Own sub-phase (57.5), floating after 57.2, one key per workspace; align with phase 32 later. Redaction ships in 57.2 regardless |
| D-3 | Deferred grading permitted | **Resolved.** Yes — grading state on the observation; no scan-level status (§6.3) |
| D-4 | Swarm capture in scope | **Resolved.** Deferred to the swarm parity backlog; partial-corpus consequence documented |
| D-5 | Retention default for captured evidence | **Resolved in design; not implemented in 57.2.** Workspace lifetime, configurable (§5.4) — but nothing reads a `retention` setting and nothing schedules the `delete_scan` methods that exist on both the store and the repository. "Workspace lifetime" holds today by omission. A period is a guess until D-21 (§9) |
| D-6 | Where `severity:` lives | **Resolved.** `contract.yaml` (authored), per Phase 56's contract/config split (§7) |
| D-7 | Workspace switching model | **Resolved.** Launch-time only; runtime/UI switching is a later phase (§5.4) |
| D-9 | Capture of failed probes | **Resolved.** Completed pairs only by default; `capture_failures` toggle (§5.1) |
| D-10 | Candidate carries severity | **Resolved.** Yes — **provisional** severity, so 56.15's `on_critical` / `skip_downstream` keep their input; grade may revise, both are recorded (§6.1) |
| D-11 | How grade gets its inputs | **Resolved.** `grade()` re-parses the stored evidence. No structured `signals` channel across the seam; multi-step checks parse twice and that is accepted (§6.2) |
| D-12 | Hash scope | **Resolved.** Two — `probe_hash` (request) and `content_hash` (pair). Neither input can do both jobs (§5.1) |
| D-13 | Non-HTTP evidence | **Resolved.** `protocol` discriminator on the row; socket / resolver / local / `llm` capture supported, opt-in per protocol (§5.1, §5.2) |
| D-14 | Agent LLM exchanges captured | **Resolved.** Yes, as `protocol: llm`. Below the capture line — recording a call is not making one (§2, §3) |
| D-15 | Per-workspace config file | **Resolved.** `workspace.yaml`, occupying the config resolver's reserved layer 5; scoped to engagement properties, not a general override file (§5.4) |
| D-16 | `app/lib/evidence.py` name collision | **Resolved and landed (57.2).** No real collision — `EvidenceBundle` and `bundle_http_response` were unused and were deleted; the module is `evidence_fmt.py` and capture has the name (§8.1) |
| D-17 | Scope of the workspace | **Resolved.** It takes all four of today's roots — db, proof-of-scope logs, reports/scratch, and `customizations/`. PID dir, `scenarios/`, and `app/data/` stay global (§5.4) |
| D-18 | Behaviour with no workspace selected | **Resolved.** Create `~/chainsmith/default/`, log the path loudly. An existing `./data/chainsmith.db` is detected and reported, never moved (§5.4) |
| D-20 | Which exchanges get captured (the §5.2 observation-linked rule) | **Resolved (2026-09-10).** Per-check `capture: all / observations_only / none / inherit` in `config.yaml`, resolved like `on_critical`; `full_capture` overrides it and the AI suites are never narrowed. `observations_only` is run-scoped until 57.3's candidate binding makes it exchange-scoped. Full reasoning in §0.6 |
| D-21 | Measure evidence growth before or after enabling capture | **Measured (2026-09-12, §0.22).** ~13.3 MB per full fakobanko scan with record v1, ~9.7 MB after record v2. `enabled` stays `False` until retention exists (operator decision) |
| D-22 | How an exchange learns its candidate | **Resolved (57.3).** Grade side: the grader names the exchanges it read and the stage stamps them. Exact rather than declarative, and free for 57.4's authors. Costs per-exchange `observations_only` scoping, knowingly (§0.6) |
| D-23 | Where the grading stage runs | **Resolved (57.3).** Outside the check, called by `CheckLauncher` after `execute()` — so in-scan and offline grading are one code path. Placed before the severity scan, so `on_critical` reads a graded severity when a grader ran (§0.6) |
| D-24 | Candidate-to-observation cardinality | **Resolved (57.3).** One candidate, several verdicts. Strict 1:1 would have forced parsing back onto the probe. Observation identity is unchanged, composed at grade time (§0.6) |
| D-19 | How capture learns its attribution | **Resolved, and simpler in practice.** A `ContextVar` set in `BaseCheck.execute()`; default `None` means "not in a check". The executor-using checks were expected to "call the writer directly with an explicit handle"; as built they record at the **await site**, where the var is still in scope, through `capture.probe()` — the boundary is crossed below the recording, never across it, so no explicit handle was needed (§5.1). Explicit per-call-site passing rejected on its silent failure mode |

---

## 13. Doc reconciliation

**Done (57.2):**

- **`completed/phase47-raw-check-io-capture.md`** — marked absorbed *and delivered*, with the two items that
  resolved differently than it specified called out (the obsolete Alembic step, and the
  every-request-vs-observation-linked decision that became D-20).
- **`audits/doc-status-audit-2026-09-10.md`** — F-3 gained a "Fix (3)" entry for the `scan_id` work.

**Done (57.3):**

- **`docs/pipeline.md`** — capture and grading are in the pipeline flow, with the capture line named
  and the two check shapes (migrated and not) described.
- **`docs/vocabulary.md`** — capture line, Evidence as one exchange, `probe_hash` / `content_hash`,
  Candidate, provisional severity, Verdict, grading state / tier, reproducible-not-deterministic,
  workspace.
- **`docs/how-chainsmith-works.md`** — the lifecycle gained capture and a grading step, and the
  verification section now states that a rejection never removes an observation.

**Still outstanding:**

- **`docs/vocabulary.md` predates phase 52** — it still documents *Engagement* as a first-class
  container and says Guardian enforces "engagement window" restrictions. Not a 57.3 regression and
  not fixed here; it belongs with the phase-52 rename sweep.

See `audits/doc-status-audit-2026-09-10.md` for the wider status picture, including the module track's open
gate and the concurrent-scans lettering problem.

---

## Summary

Everything one body of work produces — database, evidence, reports, logs — lives in a **workspace**
directory chosen at launch, with a `workspace.yaml` stating the engagement scope once so Guardian
enforces it on every scan from that folder. That gives retention, encryption scope, client separation,
and corpus portability a container instead of a foreign key. Inside it, split every check into **probe**
(send, record, assert nothing beyond a provisional severity) and **grade** (re-read the evidence, place
final severity, record provenance). Capture is protocol-general — HTTP, socket, resolver, local, and the
agents' own LLM exchanges — and it records without ever interpreting. Severity becomes a declared
property in `contract.yaml`: fixed for the categorical majority, contextual where evidence must place it
on a continuum. This phase makes every judgment *re-derivable from recorded evidence*.
`phase58-ai-grading.md` then makes the judgments themselves good.
