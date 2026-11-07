# Phase 58 — AI Grading

**Status:** Proposed
**Track:** Reproducibility
**Depends on:** [`phase57-evidence-and-capture.md`](phase57-evidence-and-capture.md). A hard prerequisite: grading is meaningless without a corpus.
**Absorbs:** [`superseded/phase38-non-deterministic-sampling.md`](superseded/phase38-non-deterministic-sampling.md), which becomes 58.3. Its Option A/B/C question dissolves; see §4.
**Relocates:** the Adjudicator, from a mandatory pipeline stage to an operator-invoked second opinion (§6)
**Size:** L (6 sub-phases)
**Git / VCS:** *Mutating* git operations are operator-only. Tooling and assistants may use **read-only** git.
**Last reviewed:** 2026-10-11

> **This phase was split out of the original combined Phase 57.** Phase 57 is
> everything *below* the capture line — fact, storage, structure, no model.
> This is everything *above* it: judgment, and the machinery that makes
> judgment auditable.

---

## 1. Motivation

Chainsmith's AI suite decides severity with hand-written substring lists. In `ai_jailbreak_testing`,
`BLOCK_PHRASES` contains `"policy"` and `"as an ai"`; `BYPASS_INDICATORS` contains `"evil"`
(`app/checks/ai/ai_jailbreak_testing/check.py:90-113`). A successful jailbreak whose response happens to
contain the word "policy" is silently reclassified as blocked. A benign response containing "evil" is
flagged as a bypass. **14 of the 28 AI checks classify this way**, each with its own private copy of the
pattern; the set is enumerated in §7.

That is already a classifier — an unversioned one, duplicated 14 times, edited silently between
releases, with no provenance. When it reports *"All jailbreak techniques blocked — info,"* nothing in
the artifact records that the verdict hinged on one word.

Two gaps compound it:

- **Single-shot probes against stochastic targets.** A guardrail bypass that lands 4 times in 100 is
  reported as clean. The check sends each payload once.
- **Judgment is assigned in 133 different files**, so there is no single place to fix it.

The fix is not to remove the LLM. It is to **record every judgment so it can be re-derived** — at which
point a pinned, temperature-0, recorded model is *more* reproducible than the substring list it
replaces, because the substring list has no provenance at all.

Phase 57 built the corpus that makes this demonstrable rather than arguable. This phase spends it.

---

## 2. Non-goals

- **A fifth component type.** Considered and rejected — see §3.1.
- **Removing rule-based grading.** Rules stay as the fast tier and as the entire air-gapped story. This
  is rules-first with LLM escalation, not LLM-always.
- **Chain-level reasoning changes.** Contextual severity is a continuum *within one check against one
  host*. Cross-observation composition stays with Chainsmith and is untouched.
- **Backwards compatibility.** Pre-production. Course material is updated to match the tool, not the
  reverse.

---

## 3. The Grader

### 3.1 One agent, not a component type

A fifth component type was considered and rejected. Once severity is declared fixed-or-contextual
(phase 57 §7) and per-check variation lives in `contract.yaml`, there is nothing left for a component
family to hold:

- **Rule tier** — no new component. Existing check classify logic, returning `Verdict` instead of
  appending observations. Delivered by phase 57.
- **LLM tier** — **one** generic `Grader` agent. It reads evidence plus the check's declared rubric and
  range, and returns a point on that continuum with reasoning. Per-check variation is data, not code.

One new agent and a refactor, against a fifth type with its own registry, discovery, and config layer —
same capability, far less machinery. It also keeps the taxonomy honest: the Grader is LLM-powered,
non-deterministic, and costs tokens, which is exactly what `Agent` means in `docs/pipeline.md`.

### 3.2 Rules first, LLM on escalation

The rule tier runs first and returns a confidence. The LLM tier is invoked when confidence is low, or
when tiers disagree. This is the pattern `app/engine/prompt_router.py` already uses — keyword match, LLM
fallback below `LLM_CONFIDENCE_THRESHOLD = 0.6` (line 27) — applied to grading.

Consequences:

- Cost is bounded, and every scan yields a free rule-vs-LLM comparison on the escalated set.
- **Air-gapped is supported, not degraded into uselessness:** rule tier only, fully functional, and the
  report header states which tier graded each observation.

### 3.3 Not a tool-use loop

Grading is a **single structured call per evidence set** — like Adjudicator, unlike Verifier. The
evidence is already in hand; there is nothing to go fetch. The loop is *batching across evidence sets*,
which is framework work, not agent autonomy. A grader that wants to look something up is asking for
Researcher, a different component, still above the line.

---

## 4. Sampling (absorbs phase 38)

Contextual checks may declare multi-sampling, so a guardrail bypass that lands 4 times in 100 is
observed rather than missed.

**Mode is declared; the count is tuned.** The same split as phase 57 §7, for the same reason: only the
check author knows whether their probe is stochastic, but the number of times to run it is a knob.

```yaml
# contract.yaml — authored
sampling:
  mode: multi          # single | multi

# config.yaml — tunable
defaults:
  sampling_iterations: 20
```

The count rides the Phase 56 precedence stack with **nothing added**:

```
L1 class default → L2 suite.yaml → L3 config.yaml → L4 env → L6a preset → L6b CLI/API/WebUI scalpel
```

Presets (`app/data/presets.yaml`, 56.14) set it per profile, and 56.17's save-as-default writes a
changed value back to `config.yaml` like any other knob. No new override path, no new resolver.

Iterations of one check against one target stay sequential and respect `requests_per_second`.

**Phase 38's open question dissolves.** It asked who converts `4/100` into severity — the check (A),
framework bands (B), or metadata only (C). Under probe/grade separation the layers split cleanly and no
choice is needed:

- **The probe records all 100 outcomes and asserts nothing.** Pure fact, no severity. (C's discipline,
  where it belongs.)
- **The grader sees the whole distribution at once** — 4 compliances, 96 refusals, and the text of each
  — and places it on the declared continuum. (A's flexibility, where the judgment lives.)

**Option B is explicitly rejected:** a 4%-reproducible system-prompt leak is not low severity.
Automation makes 4% reliable.

**Negatives carry their sample size.** A multi-sample probe that observed nothing is not a clean bill of
health. `0/20` supports *"not observed in 20 attempts"* — and, via a Wilson score interval, the honest
bound that belongs with it: *"reproduction rate below ~14%, 95% confidence."* The interval is arithmetic
over a sample the probe already recorded, it costs nothing, and it is what makes §9.4 enforceable rather
than a style rule. The Wilson form matters specifically because the naïve interval collapses to zero
width at 0/20 and lies. Single-shot results carry the weaker statement: *"executed once;
non-deterministic behaviour may not be detected."*

**Confidence-target sampling is an explicit stretch, not v1.** Phase 38 proposed replacing the fixed
count with a stopping rule — run a batch, compute the Wilson interval, stop when it is narrow enough, cap
at `max_iterations`. It saves iterations on checks that converge immediately and spends them where the
answer is ambiguous. Worth doing; not worth blocking 58.3 on.

**Progress and ETA must count iterations, not checks.** A scan of 50 single-shot checks plus 5 checks at
20 iterations is ~150 units of work, not 55. Both the progress bar and the SSE progress events (Phase
51) currently count check runs; multi-sampling breaks that arithmetic and makes a busy scan look
stalled. Per-iteration progress within a check is also wanted
(`[47/100] ai_jailbreak_testing: 2 compliances so far`). This is the one place sampling touches the
streaming layer.

**OPSEC.** 20× iterations is 20× target traffic and a louder signature. Mitigated by existing rate
limiting and, where needed, swarm distribution — noting that iterations of one check against one target
stay sequential, so swarm distribution spreads *checks and targets*, not the iterations of a single
probe.

---

## 5. Grade caching by evidence hash

If a re-scan produces evidence whose `content_hash` matches a previously graded pair, **reuse the stored
verdict — no model call.**

- Grading cost scales with **what changed**, not with scan size. A delta scan against an unchanged
  target is nearly free to grade.
- It delivers property (a) literally: identical evidence provably yields the identical verdict, because
  it *is* the same verdict.
- Cache keys must include the grader version and prompt hash, so a grader upgrade correctly invalidates
  and re-grades.
- **The cache is per-workspace** (phase 57 §5.4). A global cache keyed only on content hash would carry
  one client's evidence hashes and verdicts into another client's workspace — precisely the path the
  physical separation exists to close. The cost is that identical evidence appearing in two workspaces
  grades twice; that is the correct trade.

This is why phase 57 §5.1's normalisation matters: per-run `uuid4()` markers must not defeat the hash.

---

## 6. Adjudicator relocation

Adjudicator today is a mandatory pipeline stage, `enabled: true`
(`app/agents/adjudicator/config.yaml`), **one structured LLM call per observation on every scan** —
probably the largest single LLM line item in the product.

It becomes an **operator-invoked second opinion**: a neutral consultant giving a professional opinion on
a specific observation, called when the operator believes the scores are wrong and wants a Chainsmith
component to check the work. It moves off the linear pipeline to where Coach and Chainsmith-validation
already sit, following the existing `trigger: operator_selected` precedent in
`app/advisors/check_proof/config.yaml:12`.

**It keeps its full holistic view, all five factors, evidence included.** A second opinion that may only
read half the file is not a second opinion. An earlier proposal to narrow it to asset-context-only was
considered and rejected for that reason.

What falls out:

- **Cost drops sharply**, and those tokens move to grading, where they buy accuracy.
- **The audit trail improves.** An adjudication is now something an operator *requested* — the record
  shows who disagreed, when, and what the consultant said back. A documented disagreement is strictly
  more auditable than a silent adjustment.
- **`SEVERITY_UPHELD` becomes useful.** Today it is noise. When adjudication is requested, *"I checked;
  the grader was right"* is an answer worth having.

**Triage needs a fallback, and it is not a one-liner.** `app/engine/triage.py` is *remediation* triage:
it reads adjudicated observations and attack chains from the database, loads team/operator context,
matches `app/data/remediation_guidance.json`, and the Triage Agent writes a fix plan (`triage_plans` /
`triage_actions`). Its input type is `AdjudicatedRisk`. When adjudication stops running by default,
triage loses that input on most scans and must fall back to grader severity plus confidence — which
changes triage output on *every* scan, not only adjudicated ones.

**Behaviour:** Adjudicator **proposes, the operator accepts.** The adjudicated severity is written
alongside the grader's; reports show the grader's until accepted. Follows from phase 57 §2's
never-subtract rule. Invocation is per observation, with a batch form (*"re-adjudicate all criticals"*)
if it proves wanted.

### 6.1 Severity ordering

Each layer is non-destructive and answers a question the previous one cannot:

| Layer | Question | Reads | When |
|---|---|---|---|
| Check (fixed) | What is this, categorically? | nothing | always |
| **Grader** | What did the target actually do? | captured evidence | when `model: contextual` |
| **Adjudicator** | How much does that matter *here*? | observation + asset context | on operator request |
| Chainsmith | What do these combine into? | all observations | chain analysis |

---

## 7. Provenance and model drift

Every verdict records: grading tier (rule / LLM), rule-set version or prompt hash, evidence
`content_hash` list, confidence, and reasoning.

**Model pinning cannot be solved** where routing sits behind a proxy you do not own —
`LITELLM_MODEL_VERIFIER=nova-mini` is an alias, and an alias can silently repoint. Model routing is
increasingly common and this is not a problem Chainsmith can fix.

**Drift can be made visible, which is enough for the audit claim:**

- Record the model identity the **API response returns**, not the alias that was sent.
- Hash the grader prompt.
- Flag when either changes between runs over identical evidence.

You do not get *"pinned."* You get *"we can prove when it moved"* — and it is close to free once capture
exists.

---

## 8. Rollout

| Sub-phase | Deliverable |
|---|---|
| **58.1** | **Grader agent.** LLM tier, rubric rendering, escalation on low confidence (§3.2), provenance recording, drift flagging (§7). |
| **58.2** | **Contextual migration — AI suite pilot.** The substring-list checks below, with `ai_jailbreak_testing` as the reference implementation. Includes **activating the 10 dormant AI checks** (Phase 56.4 deferred this pending Phase 56; it is now due) — several migration targets are currently `enabled: false` and cannot otherwise be validated against a live corpus. |
| **58.3** | **Sampling.** Absorbs phase 38. `sampling.mode` in `contract.yaml`, `sampling_iterations` on the existing config stack, distribution handed to the grader, Wilson bounds on negatives, and **iteration-aware progress/ETA**. Confidence-target mode noted as a stretch, not built. |
| **58.4** | **Grade cache.** Per-workspace verdict reuse by evidence hash; grader-version invalidation. |
| **58.5** | **Adjudicator relocation.** Off-pipeline, operator-invoked, propose-not-overwrite. Includes triage's fallback to grader severity + confidence (§6). |
| **58.6** | **Remaining suites.** MCP, agent, RAG, CAG; then any network/web checks that turn out to be contextual. |

**58.2 migration set.** Named rather than counted, because the boundary is fuzzy and the number is the
scope. Thirteen AI checks carry phrase-list constants (`*_PHRASES`, `*_INDICATORS`, `*_MARKERS`):
`ai_adversarial_input`, `ai_content_filter_check`, `ai_conversation_history_leak`,
`ai_function_calling_abuse`, `ai_guardrail_consistency`, `ai_input_format_injection`,
`ai_jailbreak_testing`, `ai_model_info_check`, `ai_multi_turn_injection`, `ai_prompt_leakage`,
`ai_system_prompt_injection`, `ai_tool_discovery`, `ai_training_data_extraction`. A fourteenth,
`ai_error_leakage`, does the same thing with inline lists rather than a named constant. Of these, five
are currently dormant — `ai_adversarial_input`, `ai_conversation_history_leak`,
`ai_function_calling_abuse`, `ai_guardrail_consistency`, `ai_training_data_extraction` — hence the
activation work above. Confirm the set at implementation time; a broader sweep for any substring test
against a response body returns seventeen, and the extra three are incidental string handling rather
than severity classification.

---

## 9. Success criteria

1. Two scans of an unchanged fakobanko produce **identical verdicts**, and the second costs near-zero
   grading compute (§5).
2. Every LLM-graded observation carries a prompt hash and the returned model identity.
3. A stored corpus can be **re-graded offline with no target access**, and the diff against the original
   grading is inspectable.
4. **Negative results state their sample size.** *"Not Observed"* is never rendered as *"Not
   Vulnerable"* — a vulnerable state is asserted only where evidence proves it. Applies to every report
   format.
5. `ai_jailbreak_testing` no longer misclassifies a compliance containing the word `"policy"` —
   demonstrated against a captured corpus.
6. Air-gapped operation completes a full scan on the rule tier, with the report stating the tier used.
7. No LLM call is made by any `model: fixed` check.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| Grading cost at scale | Rules-first escalation (§3.2), grade cache (§5), fixed-severity checks never call a model |
| Rubrics rot as models change | Rubrics are data in `contract.yaml`; re-grade the stored corpus to detect drift |
| Sampling makes scans too slow / too loud | Preset-driven iterations; lab preset is `1`; rate limiting and swarm for OPSEC |
| Re-grading changes SEC536 answers | Expected and accepted — course material updates to match |
| Contextual migration stalls midway | Per-suite and independently shippable; the AI pilot (58.2) proves the pattern before the rest |

---

## 11. Open questions

- **O-2** — Does the Grader see redacted or unredacted evidence? Redacted is the safe default, but a
  redacted credential is exactly the signal that distinguishes *high* from *critical* in several
  rubrics. Leading candidate: a typed placeholder (`<REDACTED:aws_key>`) that preserves the signal
  without the secret. **D-2 default: typed placeholders.**
- **O-6** — Does the substring rule tier stay authoritative for `model: fixed` checks forever, or is
  there a later pass to grade those too? Rules stay for now, with all 133 eventually in scope, phased.
  58.6 covers the network/web checks that turn out to be contextual on inspection.
- **O-8** — Where do rubrics live for **custom** checks? Phase 57 O-5 covers the declaration; this is
  the rubric-authoring half, and it needs the Chainsmith agent's scaffolder to know what a good rubric
  looks like.

---

## 12. Doc reconciliation

- **`docs/pipeline.md`** — move Adjudicator off the linear flow; document the Grader.
- **`docs/vocabulary.md`** — add Grader, grading tier, reproduction rate; revise Adjudicator.
- **`superseded/phase38-non-deterministic-sampling.md`** — mark absorbed.

---

## Summary

One Grader agent serves every contextual check, rules-first with LLM escalation, reading only the
evidence Phase 57 recorded and never the network. Sampling turns single-shot probes against stochastic
targets into distributions the grader can read whole, with honest bounds on what a negative means.
Verdicts cache by evidence hash, so re-grading an unchanged target is nearly free and provably
identical. Adjudicator stops running on every observation and becomes the second opinion you ask for.
The result is a scanner whose every judgment can be re-derived from recorded evidence — which is the
honest version of the claim, and the stronger one.
