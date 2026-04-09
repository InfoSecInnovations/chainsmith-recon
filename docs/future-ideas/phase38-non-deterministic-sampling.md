# Phase 38 --- Non-Deterministic Target Sampling

## Problem

Many AI/LLM security findings are **probabilistic**.  A guardrail bypass
might succeed 3 % of the time.  A model might leak training data on 1 in
200 prompts.  A jailbreak payload might work only when the temperature
sampling lands a certain way.  Infrastructure-level non-determinism
compounds this: load balancers may route to backends with different model
versions, WAF rules may trigger inconsistently, rate-limit windows may
reset mid-scan.

Today every Chainsmith check sends a probe **once** and records the
outcome.  If the single observation happens to be the 97 % safe case, the
finding is missed entirely and the operator ships a clean report while the
target remains exploitable.  This is a **false-negative risk** that
undermines the tool's value on real-world engagements.

## Scope

| Layer | Example non-determinism | Addressable? |
|-------|------------------------|--------------|
| LLM output (temperature, sampling) | Guardrail bypass succeeds ~3 % | Yes --- primary focus |
| Prompt/response filtering | Content filter fires inconsistently | Yes |
| Infrastructure (WAF, CDN, LB) | WAF blocks 70 % of payloads; LB routes to different backends | Yes --- same observe-and-count mechanism |
| Model version drift | Canary deployment serves v2 to 10 % of requests | Yes --- detectable via fingerprint variance |

The mechanism is the same at every layer: send identical input N times,
observe that output varies, report the distribution.  The check does not
need to know *why* the behavior is non-deterministic --- only that it is.


## Design

### 1. Check-declared iteration hints

Each check knows whether its attack surface is inherently probabilistic.
DNS enumeration is deterministic: one probe, one answer.  A jailbreak
check against a guardrailed LLM is probabilistic by nature.

```python
class BaseCheck:
    # Existing attributes
    timeout_seconds: int = 30
    requests_per_second: int = 10
    retry_count: int = 1          # retries on *failure* (phase 17)

    # New --- phase 38
    sampling_mode: str = "single"          # "single" | "multi"
    default_iterations: int = 1            # meaningful only when mode=multi
    confidence_target: float | None = None # alternative to fixed count
```

- `sampling_mode = "single"` --- the check is deterministic (or close
  enough).  The framework runs it once.  This is the default, so existing
  checks are unaffected.
- `sampling_mode = "multi"` --- the check author asserts that a single
  observation is insufficient.  The framework runs it `default_iterations`
  times (or until `confidence_target` is met).

Check authors set these at the class level.  The values act as **hints**
the operator can override.

### 2. Configuration layering (extends phase 17)

Global default in `chainsmith.yaml`, per-check override.  Consistent with
the phase 17 pattern:

```yaml
sampling:                              # global defaults
  default_iterations: 1                # for sampling_mode=single checks
  multi_iterations: 20                 # for sampling_mode=multi checks
  confidence_target: null              # optional; overrides iteration count
  max_iterations: 200                  # hard ceiling (cost/time guard)

checks:
  jailbreak_detection:
    sampling:
      multi_iterations: 100            # override for this check
  guardrail_consistency:
    sampling:
      confidence_target: 0.95          # stop when 95 % CI is narrow enough
```

Precedence: **per-check YAML > global YAML > class-level hint**.

### 3. Confidence-target mode (stretch)

Instead of a fixed iteration count, the operator sets a confidence target
(e.g., 0.95).  The framework uses a sequential sampling strategy:

1. Run an initial batch (e.g., 10 iterations).
2. Compute the Wilson score interval for the observed reproduction rate.
3. If the interval half-width is below the threshold, stop.
4. Otherwise run another batch and re-evaluate.
5. Stop at `max_iterations` regardless.

This avoids wasting iterations on checks that converge quickly (100 %
pass or 100 % fail) while investing more in ambiguous cases.

**Open question:** Is this overkill for v1?  A fixed iteration count is
simpler to explain, implement, and debug.  Confidence-target could be a
later refinement.

### 4. Execution model

```
For each check in scan:
    if check.effective_sampling_mode == "single":
        run once, record result              # same as today
    else:
        observations = []
        for i in range(effective_iterations):
            result = run_check_once(check, target)
            observations.append(result)
            if confidence_target and ci_narrow_enough(observations):
                break
        finding = aggregate(observations)
        finding.reproduction_rate = count_concerning(observations) / len(observations)
        finding.sample_size = len(observations)
        finding.iteration_details = observations   # for drill-down
```

**Rate limiting:** Multi-iteration checks must respect
`requests_per_second` and `delay_between_targets`.  The framework inserts
inter-iteration delays using the same throttle mechanism checks already
use.

**Parallelism:** Iterations of the same check against the same target
are sequential (to avoid self-interference and rate-limit violations).
Different checks can still run concurrently per existing scan logic.

### 5. Aggregation and severity

A check that runs N times produces N observations.  The aggregator must
collapse these into a single finding with metadata:

| Field | Type | Description |
|-------|------|-------------|
| `reproduction_rate` | float | Fraction of iterations that produced a concerning observation (0.0--1.0) |
| `sample_size` | int | Number of iterations actually executed |
| `severity` | str | Determined by check logic + reproduction rate |
| `iteration_details` | list | Per-iteration raw observations (for drill-down) |
| `worst_observation` | object | The single most severe iteration result |
| `first_seen_at` | int | Iteration index where the finding first appeared |

**Severity modulation:**  A finding that reproduces 2 % of the time is
real but different from one that reproduces 90 % of the time.  Options:

- **Option A --- check decides:** The check's `classify()` receives
  the reproduction rate and sets severity accordingly.  Most flexible.
- **Option B --- framework multiplier:** The framework applies a
  severity adjustment factor based on reproduction rate bands
  (e.g., <5 % = downgrade one level, >50 % = no adjustment).
- **Option C --- report-only:** Severity stays as the check set it;
  reproduction rate is informational metadata.

**Open question:** Which option?  Option A is most aligned with how
checks already own their severity logic.  Option B risks masking real
issues.  Option C is simplest but may confuse operators who see a
"Critical" finding that reproduces 1 % of the time.

Recommendation: **Option A** with framework-provided utility functions
so check authors don't have to reinvent the math.

### 6. Reporting

#### Finding card (UI)

```
[!] Guardrail Bypass --- Jailbreak via Role-Play
    Severity: High
    Reproduction rate: 4.0 % (4 / 100 iterations)
    Status: Confirmed-Intermittent

    The target accepted a role-play jailbreak payload in 4 of 100
    attempts.  While the success rate is low, a motivated attacker
    with automation can exploit this reliably.
```

#### Finding classification

| Reproduction rate | Classification | Meaning |
|-------------------|---------------|---------|
| 100 % | Confirmed-Stable | Deterministic finding |
| >0 % and <100 % | Confirmed-Intermittent | Non-deterministic but real |
| 0 % (multi-shot) | Not Observed | Probed N times, never triggered |
| 0 % (single-shot) | Not Observed | Legacy / single-probe |

**"Not Observed" is not "Not Vulnerable."**  The report language must
make this distinction clear, especially for single-shot checks where
the sample size is 1.

#### Report text

For multi-shot findings, auto-generate language like:

> "This finding was observed in {rate}% of {n} test iterations.  While
> the reproduction rate is {low|moderate|high}, automated exploitation
> tools can achieve reliable exploitation through repeated attempts.
> A 3% reproduction rate means an attacker with a simple loop achieves
> near-certain exploitation within ~100 attempts."

#### Attestation / confidence indicator

Single-shot results should carry a confidence disclaimer:

> "This check was executed once.  Non-deterministic vulnerabilities
> may not be detected with a single observation.  Consider re-running
> with `sampling.multi_iterations` for higher confidence."

This gives the operator visibility into the limitation without forcing
every scan to be 100x longer.

### 7. UX: the "dangerous default" problem

The core tension:

- **Default 1 run:** Fast, but false-negative risk.  Operator has
  false confidence in a clean report.
- **Default 100 runs:** Thorough, but a 50-check scan takes 50x longer.
  Operator abandons the tool or skips sampling.

Proposed resolution --- **tiered defaults driven by check hints:**

- Checks that declare `sampling_mode = "single"` run once.  This is
  most checks (network, DNS, config, discovery).
- Checks that declare `sampling_mode = "multi"` run their
  `default_iterations` (set by the check author, typically 10--50).
- The operator can override globally or per-check.

This means the *check author* --- who understands the attack surface ---
decides the minimum viable sample size.  The operator can dial up for
higher confidence or dial down for speed.

**Scan profiles** (a natural extension):

```yaml
# Quick scan --- speed over completeness
sampling:
  multi_iterations: 5

# Standard scan --- balanced
sampling:
  multi_iterations: 20

# Deep scan --- pentester mode
sampling:
  multi_iterations: 100
  confidence_target: 0.95
```

**Open question:** Should the default scan profile be "quick" (safe,
fast, but possibly incomplete) or "standard" (slower, more confident)?
Leaning toward "standard" as the default since the whole point of the
tool is to find vulnerabilities --- a fast scan that misses findings
defeats the purpose.

### 8. Progress and ETA

Multi-shot checks need progress feedback:

```
[  3/100] jailbreak_detection: 0 findings so far...
[ 47/100] jailbreak_detection: 2 findings (4.3 % reproduction rate)...
[100/100] jailbreak_detection: 4 findings (4.0 % reproduction rate) --- done
```

The scan progress bar should account for total iterations, not just
total checks.  A scan with 50 single-shot checks and 5 multi-shot
checks at 100 iterations each is ~550 units of work, not 55.

### 9. Interaction with other phases

| Phase | Interaction |
|-------|------------|
| Phase 17 (check configurability) | Sampling config uses the same YAML layering and per-check override pattern |
| Phase 21 (adjudicator agent) | Adjudicator receives reproduction rate as input; intermittent findings may warrant different adjudication logic |
| Phase 26 (model review) | LLM reviewer should factor reproduction rate into narrative |
| Phase 29 (test authenticity) | Tests for multi-shot checks need deterministic mock iteration counts |
| Phase 33 (triage agent) | Triage priority should factor in reproduction rate and exploitability math |
| Swarm | Multi-shot iterations are embarrassingly parallel across swarm nodes; natural fit for distributing iteration batches |

### 10. Implementation approach

**Wave 1 --- Foundation:**
- Add `sampling_mode`, `default_iterations` to `BaseCheck`
- Add `sampling:` section to config schema
- Framework iteration loop with rate limiting
- `reproduction_rate` and `sample_size` on findings
- Update report templates with reproduction rate display
- Confidence disclaimer on single-shot results

**Wave 2 --- Check adoption:**
- Audit all checks; tag probabilistic ones as `sampling_mode = "multi"`
- Set appropriate `default_iterations` per check
- Update `classify()` methods to use reproduction rate in severity logic
- Add utility functions for reproduction-rate-aware severity

**Wave 3 --- Confidence-target mode:**
- Wilson score interval calculation
- Sequential sampling with early stopping
- Scan profiles (quick / standard / deep)

**Wave 4 --- Visualization:**
- Reproduction rate display on finding cards
- Iteration distribution chart (e.g., mini bar showing pass/fail per iteration)
- Scan profile selector in UI
- Progress bar accounting for iteration counts

## Open questions

1. **Confidence-target vs. fixed count:** Is adaptive sampling worth the
   complexity in v1, or should we start with fixed counts and add
   confidence-target later?

2. **Severity modulation:** Should checks own severity adjustment
   (Option A), should the framework apply a multiplier (Option B), or
   should reproduction rate be informational only (Option C)?

3. **Default profile:** Should the out-of-box default be "quick"
   (1--5 iterations) or "standard" (10--20 iterations) for multi-shot
   checks?

4. **Iteration storage:** Storing 100 raw observations per finding
   could bloat the database.  Should we store all iterations, only
   the concerning ones, or just the aggregate stats?

5. **Cross-run aggregation:** If the operator runs the same scan
   Tuesday and Thursday, should Chainsmith aggregate reproduction
   rates across runs?  (Probably a later concern, but worth noting.)

6. **Attacker-math language:** The report should translate reproduction
   rates into attacker-meaningful statements ("3 % = ~34 attempts for
   50 % chance of success, ~100 attempts for 95 %").  How prominent
   should this be?
