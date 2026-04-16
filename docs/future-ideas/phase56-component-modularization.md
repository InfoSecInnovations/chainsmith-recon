# Phase 56 — Component Modularization

**Status:** Draft / pending implementation
**Supersedes:** `phase17-check-configurability.txt`, `phase43-check-subdirectory-restructure.md`
**Partially supersedes:** `module-system-design.md` (component folder shape + contracts absorbed here; external `modules/` root, routes, DB models, UI slots, and licensing remain future work)
**Prerequisite:** None. Independent of concurrent-scans.

---

## 1. Motivation

Three overlapping plans were heading toward the same physical disruption — restructuring every check, agent, advisor, and gate in the codebase. Doing them separately meant three passes over the same files. Doing them together means **one migration per component**.

What we get in one swing:

- **From phase 43:** subdirectory-per-component, co-located tests, auto-discovery loader replacing the 300-line manual import list in `check_resolver.py`.
- **From phase 17:** externalized per-component configuration (enabled, timeouts, tunables), presets, payload data files, env-var overrides, validation, WebUI config modals.
- **From module-system-design:** `contract.yaml` declaring identity + I/O, consistent folder shape across all component types (check/agent/advisor/gate), door left open for the future external `modules/` root.

The per-component work (new folder, new YAML files, moved tests) would have been the same under any of the three plans. Merging triples the return on a single disruptive pass.

---

## 2. Non-goals

- **External `modules/` root.** The second discovery root under `modules/`, UUID override resolution between roots, and community/paid tier distribution remain future work.
- **Routes / DB migrations / UI slots / licensing.** All multi-component module-system extension points stay out. Revisit after this phase lands.
- **Concurrent-scans dependency.** None. This work is independent.
- **Hot reload.** Component changes still require a restart.
- **Rewriting check logic.** Code files move and get de-duplicated with YAML; `run()` bodies do not change.

---

## 3. Folder shape

Every in-tree component (check, agent, advisor, gate) uses the same shape.

### 3.1 Check example

```
app/checks/network/ports/
├── ports.py                  # check implementation
├── ports.contract.yaml       # identity + I/O contract (loader reads this)
├── ports.config.yaml         # tunables (timeout, rate, enabled, per-check params)
├── tests/
│   └── test_ports.py         # co-located tests
└── README.md                 # optional: deep prose docs, technique notes
```

### 3.2 Agent example

```
app/agents/adjudicator/
├── adjudicator.py
├── adjudicator.contract.yaml
├── adjudicator.config.yaml
├── prompts/
│   ├── system.md             # generic names here — prompts/ path disambiguates
│   └── user.md
├── tests/
│   └── test_adjudicator.py
└── README.md
```

### 3.3 Naming rule

**Component-root files carry the folder-name prefix.** `ports.py`, `ports.contract.yaml`, `ports.config.yaml` — every file identifiable from its name alone. No "look in `check.py`" / "which one?" conversations.

**Well-known subdirs use generic names inside** (`tests/test_ports.py`, `prompts/system.md`, `migrations/001_init.sql`, `templates/detail.html`). The subdir path + parent folder already disambiguate.

**Keep generic** regardless of folder:
- `README.md` — GitHub auto-renders, universal ecosystem convention
- `LICENSE`, `CHANGELOG.md` — ecosystem tooling recognizes exact names
- `__init__.py` — Python requires exactly this name

### 3.4 Loader rule

Discovery is mechanical: `{folder}/{folder}.contract.yaml`. The folder-name-must-match-filename rule is self-validating — a mismatched filename means a malformed component and the loader flags it. Free lint.

---

## 4. `contract.yaml` schema

Machine-parseable. The loader reads this to build the registry.

```yaml
# app/checks/network/ports/ports.contract.yaml

id: 7b3e2a94-1c6f-4d82-9a37-5e8b1f3c0d22   # UUIDv4, assigned once at authorship
name: port_scan                             # human-readable slug
type: check                                 # check | agent | advisor | gate
description: "Scan TCP ports on discovered hosts."

entry: ports.py:PortScanCheck               # code file + class, since ports.py isn't generic

# Check-specific fields
suite: network
phase: 2                                    # execution order within suite
depends_on:
  - output: services
    operator: truthy
produces:
  - open_ports

inputs:
  target: Target
  config: ref(ports.config.yaml)

outputs:
  observations: [Observation]

side_effects: [network]                     # network | filesystem | db | none

tests:
  path: tests/
```

### 4.1 Field differences by component type

| Field | check | agent | advisor | gate |
|---|---|---|---|---|
| `suite` / `phase` / `depends_on` / `produces` | ✓ | — | — | — |
| `role` (adjudicator/coach/planner) | — | ✓ | — | — |
| `triggers` (observation.created, chat.message, …) | — | ✓ | — | — |
| `tools` (db.read, llm.call, …) | — | ✓ | — | — |
| `prompts` (system, user paths) | — | ✓ | — | — |
| `side_effects` | ✓ | ✓ | ✓ | ✓ |
| `outputs` | observations | adjudications/plans/coaching | recommendations | GateDecision |

Mirrors the contracts sketched in `module-system-design.md` §6.

---

## 5. `config.yaml` schema

Tunables only — runtime knobs the operator may override. Identity lives in `contract.yaml`.

```yaml
# app/checks/network/ports/ports.config.yaml

enabled: true                               # false → loader skips the check
on_critical: annotate                       # annotate | skip_downstream | stop | inherit

defaults:
  timeout_seconds: 30
  requests_per_second: 10
  retry_count: 1

parameters:
  port_profile: ai
  scan_intensity: standard
```

### 5.1 Resolution order (last wins)

1. Hardcoded class default
2. `{component}.config.yaml` defaults
3. Suite-level defaults (future — deferred; no concrete need yet)
4. User override file (future)
5. Runtime (CLI flag, API param, preset selection)
6. Env var: `CHAINSMITH_<COMPONENT_NAME>_<PARAM>` (all uppercase, hyphens → underscores)

---

## 6. Auto-discovery loader

Replaces `get_real_checks()` in `check_resolver.py`. New file: `app/component_loader.py`.

```python
def discover_components(
    root: Path,
    component_type: Literal["check", "agent", "advisor", "gate"],
) -> list[BaseComponent]:
    """
    Walk {root} recursively for folders containing {folder}.contract.yaml.
    For each match:
      1. Parse contract.yaml
      2. Parse {folder}.config.yaml if present
      3. Skip if config.enabled is false
      4. Import contract.entry file, find the declared class
      5. Instantiate via from_config() with merged config
      6. Validate filename-folder match; fail loud on mismatch
      7. Return phase-ordered list (for checks; stable sort otherwise)
    """
```

- **Phase ordering** for checks: `(suite_order, phase)`. Agents/advisors/gates don't have execution phases.
- **Validation:** fail loud at startup on missing required fields, mismatched filename/folder, broken entry references, UUID collisions.
- **Caching (deferred):** `.chainsmith/component-index.json` keyed by contract path + mtime, per module-system-design §8.1. Not needed day one; add if startup gets slow.

---

## 7. Rollout phases

| # | Sub-phase | Scope | Risk |
|---|-----------|-------|------|
| 56.1 | **Foundation.** Loader, `contract.yaml` + `config.yaml` schemas, `BaseCheck.from_config()`, filename-folder lint, UUID scaffold helper (`chainsmith dev new-check`). Validate with a single pilot check. | Low |
| 56.2 | **Web suite** (23 checks). First full-suite migration. Exercises loader edge cases at real scale. | Medium |
| 56.3 | **Network suite** (13 checks). | Medium |
| 56.4 | **AI suite** (18 checks). | Medium |
| 56.5 | **MCP suite** (18 checks). | Medium |
| 56.6 | **Agent-check suite** (16 checks). Named to avoid confusion with the agent *component type* in 56.10. | Medium |
| 56.7 | **RAG suite** (17 checks). | Medium |
| 56.8 | **CAG suite** (17 checks). | Medium |
| 56.9 | **Check-resolver cleanup.** Delete `infer_suite()`, shrink `check_resolver.py`, drop dead imports, remove migration-shim re-exports from `__init__.py` files (or keep them — see §11 Q1). | Low |
| 56.10 | **Agents component type.** Port `app/agents/*` (coach, adjudicator, triage, etc.) to the folder shape. | Medium |
| 56.11 | **Advisors component type.** Port `app/advisors/*` to folder shape. | Low |
| 56.12 | **Gates component type.** Port Guardian's gate logic (engagement window, scope, rate limit, etc.) to folder shape. Touches the scan chokepoint — extra care. | Medium |
| 56.13 | **Phase-17 Wave 2:** externalize payload data (`data/payloads/`, `data/wordlists/`, `data/endpoints/`). | Low |
| 56.14 | **Phase-17 Wave 3:** presets (quick, thorough, passive, ai-focused). | Low |
| 56.15 | **Phase-17 Wave 4:** per-component `enabled` flag wired end-to-end + per-check `on_critical` override. | Low |
| 56.16 | **Phase-17 Wave 5:** env-var overrides + startup config validation. | Low |
| 56.17 | **Phase-17 Wave 6:** WebUI check detail modals + per-check parameter editing. | Medium |

**Each sub-phase is a separate PR.** Suites in 56.2–56.8 are independent; one stuck PR doesn't block the others. Component-type phases (56.10–56.12) can run in parallel with the phase-17 waves (56.13–56.17) — different files.

---

## 8. Per-check migration checklist

For each check in a suite:

- [ ] Create `app/checks/<suite>/<check_name>/` folder
- [ ] Move the check file → `<check_name>.py`
- [ ] Write `<check_name>.contract.yaml` (generate UUID if none exists)
- [ ] Write `<check_name>.config.yaml` from existing class attributes
- [ ] Move/split tests → `tests/test_<check_name>.py` (delete the original — do not leave a duplicate)
- [ ] Update suite's `__init__.py` to re-export from the new path (migration shim)
- [ ] Run full suite tests — zero regression

After all checks in a suite are migrated:

- [ ] Remove the suite's entries from `check_resolver.get_real_checks()`
- [ ] Verify the loader picks up the suite in the same phase order as before
- [ ] Verify scan produces identical observations on a reference scenario (fakobanko)

---

## 9. Risks

1. **Wide refactor.** Touching every check is inherently risky. Mitigated by per-suite PRs + full test run after each. Reference-scenario comparison (fakobanko) catches silent behavior drift.
2. **Test discovery.** Co-located `tests/` subdirs must be on `pytest.ini` `testpaths`. Watch for double-collection — delete the original test file as you migrate, don't leave it behind.
3. **Import-path changes.** Existing `from app.checks.web.robots import RobotsTxtCheck` callers work via the folder's `__init__.py` re-export. Keep as a migration shim; removal in 56.9 is optional (see §11 Q1).
4. **UUID authorship burden.** One-time cost per component. The `chainsmith dev new-check` scaffold from 56.1 generates UUID + folder + skeleton files so contributors never hand-write one.
5. **Contract drift from code.** If `contract.yaml` declares `produces: open_ports` but the code never sets it, the loader can't catch that at parse time. Add a test-suite rule that runs each check against a mock target and validates declared outputs match actual. Defer to 56.9 if it slows the migration.
6. **Gate migration touching Guardian.** 56.12 reshapes the scan chokepoint. Carry extra test coverage; validate engagement-window enforcement and scope gating behave identically before/after.

---

## 10. Success criteria

- `pytest tests/` passes with zero regressions across 56.1–56.12.
- `check_resolver.py` drops below 100 lines (from ~300).
- `infer_suite()` deleted.
- Every in-tree component lives in a folder matching §3.
- Every component's filename matches its folder (`{folder}/{folder}.py` + `{folder}/{folder}.contract.yaml`).
- Adding a new check: run `chainsmith dev new-check --name foo --suite web` → edit the generated `foo.py` → done. No `check_resolver.py` edit.
- Operators can disable a check via `{check}.config.yaml: enabled: false` (effective next restart).
- Fakobanko scenario produces bit-identical observation counts pre- and post-migration (or documented diffs for explained behavior changes).

---

## 11. Open questions

1. **`__init__.py` re-export shims: keep permanent or remove in 56.9?** Keeping means `from app.checks.web.robots import RobotsTxtCheck` works forever (good for any external callers). Removing enforces the new path (cleaner). Lean: keep permanent — cost is near zero.
2. **Contract validation depth.** Should the loader validate that `produces:` outputs are actually set by the check at runtime, or is that purely a test-suite concern? Lean: test-suite, with a `chainsmith verify contracts` dev command.
3. **When to add the UUID override mechanism?** Not needed for in-tree work. Defer until the external `modules/` root phase. UUIDs in contracts now are forward-compat — the override wire is the future bit.
4. **Suite-level `suite.yaml`?** Phase 43 proposed it for shared defaults. No concrete need yet — per-check config covers it. Revisit if duplication emerges across a suite.
5. **Template / scaffold location.** `chainsmith dev new-check` needs a template folder. `app/dev/templates/component/` or `tools/templates/`?

---

## Summary

One folder shape across all in-tree components. Every file prefixed with its folder name for conversational and IDE clarity; well-known subdirs and ecosystem conventions stay generic. `contract.yaml` is identity + I/O (machine-parseable); `config.yaml` is tunables; code and tests live next to them. Auto-discovery loader replaces hand-maintained registries. Phase-17's configurability, phase-43's restructure, and the module-system component shape all land in one coherent pass, scoped per suite so the blast radius stays bounded.

The external `modules/` root, routes/DB/UI extension points, and licensing remain future work, tracked in `module-system-design.md`. When that phase lands, in-tree components are already in the right shape — a folder move is all it takes to promote one to a module.
