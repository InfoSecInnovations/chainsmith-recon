# Future Ideas — Index

Design proposals and phase plans for Chainsmith. This page is the source of truth for **what is open and in
what order**. Each doc's own header carries its detailed status.

**Last reviewed:** 2026-10-11, with every status verified against the code.

| Folder | Holds |
|---|---|
| `./` | Open work. One doc per proposal |
| [`completed/`](completed/) | Shipped phases. Archive only, do not edit |
| [`superseded/`](superseded/) | Docs absorbed into or replaced by another doc. Each one carries a banner naming its replacement |
| [`audits/`](audits/) | Dated status snapshots. Historical only |

Start with [`open-issues.md`](open-issues.md): known bugs and the decisions that are waiting on the operator.

---

## Open work

Status values: **Ready** (design done, nothing blocking) · **Proposed** (design exists, may need review) ·
**Partial** (some of it has shipped) · **Parked** (deliberately on hold) · **Backlog**.
Size runs XS–L.

| Track | Doc | Status | Size | Depends on | Summary |
|---|---|---|---|---|---|
| Correctness | [open-issues.md](open-issues.md) | Live | — | — | Bugs and pending decisions |
| Range / checks | [lab-backports.md](lab-backports.md) | Ready | M | — | Fixes made in the SEC536 lab snapshot that main still needs. The range currently plants almost nothing |
| Reproducibility | [phase57-evidence-and-capture.md](phase57-evidence-and-capture.md) | Partial | M left | — | Workspaces, evidence capture, probe/grade split. Remaining: hash mismatches, retention, 57.5 encryption |
| Reproducibility | [phase58-ai-grading.md](phase58-ai-grading.md) | Proposed | L | phase 57 | Grader agent, repeated-trial sampling, grade cache, Adjudicator as a second opinion |
| Concurrency | [concurrent-scans.md](concurrent-scans.md) | Partial | M | — | Inline scope on `/scan`, finish the scan selector UI, per-scan swarm coordinators |
| Swarm | [phase54-swarm-enhancements.md](phase54-swarm-enhancements.md) | Backlog | M each | concurrent-scans §2.3 | Cross-process bus, OPSEC, telemetry, recovery, capabilities |
| Modules | [module-system-design.md](module-system-design.md) | Ready | L | — | External `modules/` root, manifests, extension points, licensing |
| Modules | [phase55-terminal-dashboard-stream-client.md](phase55-terminal-dashboard-stream-client.md) | Ready | S | — | CLI SSE client and `--stream` |
| Modules | [module-terminal-dashboard.md](module-terminal-dashboard.md) | Proposed | M | module system, phase 55 | `chainsmith watch`, a live-scan dashboard in Textual |
| Modules | [module-scan-reporter.md](module-scan-reporter.md) | Proposed | M | module system | Markdown "notebook" report for a completed scan |
| Modules | [module-scope-wizard.md](module-scope-wizard.md) | Proposed | M | module system, concurrent-scans §2.1 | Interactive scope builder |
| Lab | [lab-edition.md](lab-edition.md) | Proposed | M | lab-backports | Generate the SEC536 lab build from main with a preset, so it stops drifting |
| Range | [phase46-fakobanko-semantic-cache.md](phase46-fakobanko-semantic-cache.md) | Ready | S | — | A real CAG service for fakobanko. Mostly covered by lab-backports 2d |
| Checks | [checks-adversarial-ai.md](checks-adversarial-ai.md) | Proposed | L | phase 58 §4 for the statistical helper | New checks and enhancements drawn from the SEC535/536 adversarial-AI course books |
| Compliance | [compliance-framework-selector.md](compliance-framework-selector.md) | Ready | M | — | Filter the compliance report by framework, with per-control gap analysis |
| Compliance / CUI | [phase32-nist-cui-hardening.md](phase32-nist-cui-hardening.md) | Proposed | L | — (aligns with 57.5) | Encryption at rest, auth, audit, retention for CUI |
| Ops | [phase48-oversight.md](phase48-oversight.md) | Partial | L | — | OpenAPI snapshot plus CI, architecture docs, end-to-end workflow tests |
| Ops | [phase49-observability.md](phase49-observability.md) | Proposed | L | — | Structured logs, metrics, introspection. Re-scope first |
| Ops | [schema-migration-tooling.md](schema-migration-tooling.md) | Parked | M | — | Bring back migrations once user data matters |
| Scope | [guardian-interactive-approval.md](guardian-interactive-approval.md) | Parked | S | — | Pause on a scope violation and ask the operator |
| Backlog | [backlog.md](backlog.md) | Backlog | — | — | Small deferred items, grouped by area |

Related design docs that live outside this folder: [`../plan-data-protection-secrets.md`](../plan-data-protection-secrets.md),
[`../plan-instance-auth-nist-cui.md`](../plan-instance-auth-nist-cui.md) (both overlap phase 32), and
[`../plan-third-party-api-auth.md`](../plan-third-party-api-auth.md).

---

## Suggested order for the next round

1. **Correctness first.** Most of these are small, and each makes everything after it more trustworthy.
   - [lab-backports.md](lab-backports.md) §1 and §2: the range session fix, scenario hosts, and the
     `internal.py` crash. Until these land, any scan against fakobanko undercounts.
   - [open-issues.md](open-issues.md) B-9: simulation `emulates:` names predate the check rename, so most scenario simulations never apply.
   - [open-issues.md](open-issues.md) B-3 (`outputs.update`), B-4 (`web_favicon`), B-5 (`chainsmith.sh` exit code).
   - Decide D-2 (duplicate observation ids) and implement the grading-stage guard.
   - The rest of the lab backports: MCP JSON-RPC enumeration, `ai` service types, check error logging, chains before the LLM pass.
2. **Finish phase 57:** hash-mismatch fixes, then retention. Retention is what allows capture to be on by default.
3. **Concurrency:** [concurrent-scans.md](concurrent-scans.md) §2.1 (inline scope). This closes B-1 and unblocks the scope wizard.
   Then §2.2 (UI) and §2.3 (swarm).
4. **Small standalone features, in any order:** the compliance framework selector, then the lab edition build target.
5. **Module track:** module system (narrowed scope), then phase 55, then the dashboard, then the reporter and scope wizard.
6. **Phase 58**, then the adversarial-AI checks (P0 recon checks first).
7. **Longer horizon:** phase 32 together with the `plan-*` docs and 57.5; phases 48 and 49 after a re-scope.

## Key dependencies

- Phase 58 needs phase 57's corpus.
- Turning capture on by default needs retention (phase 57).
- The scope wizard needs inline scope (concurrent-scans §2.1).
- The terminal dashboard needs phase 55 and the module system.
- Phase 54 needs per-scan swarm coordinators (concurrent-scans §2.3).
- A generated lab build should come after lab-backports, or it will regress the course.

---

## Conventions

Every open doc starts with the same header:

```
# <Title>

**Status:** Ready | Proposed | Partial | Parked | Backlog — plus one line of context
**Track:** <one of the tracks above>
**Depends on:** <doc links, by capability. Never by phase letter>
**Size:** XS | S | M | L
**Last reviewed:** YYYY-MM-DD
```

- Give a doc a phase number only once its work is scheduled. Unscheduled docs use a `track-topic.md` name.
- When a phase ships, move its doc to `completed/`. If the doc held a long implementation log, keep the log in
  `completed/` and keep only the "what remains" section in the open doc (see phase 57).
- When a doc is absorbed into another, move it to `superseded/` and add a banner naming its replacement.
- Update this index in the same change.
