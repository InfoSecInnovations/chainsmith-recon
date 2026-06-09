# Phase 56 — Component Modularization

**Status:** ✅ Complete (56.1–56.17 landed; all phase-17 waves + every component-type port). Final gates: pytest 2248 passed / 5 skipped / 0 failed, ruff clean, verify-contracts OK, diff-registry CLEAN. Deferred items tracked in `future-improvements.md`.
**Supersedes:** `phase17-check-configurability.txt`, `phase43-check-subdirectory-restructure.md`
**Partially supersedes:** `module-system-design.md` (component folder shape + contracts absorbed here; external `modules/` root, routes, DB models, UI slots, and licensing remain future work)
**Prerequisite:** None. Independent of concurrent-scans.
**Git / VCS:** *Mutating* git operations — staging (`git add`), commits, branches, merges, pushes, PRs — are operator-only. Tooling and assistants may use **read-only** git (`git show`, `git log`, `cat-file`, throwaway read-only worktrees) but must never mutate history, the index, or remotes.

---

## 1. Motivation

Three overlapping plans were heading toward the same physical disruption — restructuring every check, agent, advisor, and gate in the codebase. Doing them separately meant three passes over the same files. Doing them together means **one migration per component**.

What we get in one swing:

- **From phase 43:** subdirectory-per-component, co-located tests, auto-discovery loader replacing the manual import list in `check_resolver.py` (570 lines today).
- **From phase 17:** externalized per-component configuration (enabled, timeouts, tunables), presets, payload data files, env-var overrides, validation, WebUI config modals.
- **From module-system-design:** `contract.yaml` declaring identity + I/O, consistent folder shape across all component types (check/agent/advisor/gate), door left open for the future external `modules/` root.

The per-component work (new folder, new YAML files, moved tests) would have been the same under any of the three plans. Merging triples the return on a single disruptive pass.

---

## 2. Non-goals

- **External `modules/` root.** The second discovery root under `modules/`, UUID override resolution between roots, and community/paid tier distribution remain future work.
- **Multi-type custom components.** In-tree `custom/` is **checks-only** this phase (C9, §6). Custom *agents / advisors / gates* are **required later** — they belong to the external `modules/` work above, where the trust model for user-authored agent (LLM+tools) and gate (Guardian chokepoint) logic gets designed. The loader already supports a `custom/` subdir under any type root, so this is a tooling + trust-policy gap, not a discovery one.
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
├── __init__.py               # re-exports the entry class: `from .check import PortScanCheck`
├── check.py                  # check implementation
├── contract.yaml             # identity + I/O contract (loader reads this)
├── config.yaml               # tunables (timeout, rate, enabled, per-check params)
├── tests/
│   └── test_ports.py         # co-located tests
└── README.md                 # optional: deep prose docs, technique notes
```

The folder's `__init__.py` makes it an importable package whose name is the slug, and **re-exports the entry class so `from app.checks.network.ports import PortScanCheck` resolves to the *same class object* the loader instantiates** — preserving `isinstance` identity for callers like `scanner.py` (§10 risk 3). It is a pure re-export, never a redefinition.

### 3.2 Agent example

```
app/agents/adjudicator/
├── agent.py
├── contract.yaml
├── config.yaml
├── prompts/
│   ├── system.md
│   └── user.md
├── tests/
│   └── test_adjudicator.py
└── README.md
```

### 3.3 Naming convention

**Generic role-based filenames inside named folders** — the Next.js App Router pattern. The folder path carries identity; files inside fill well-known roles.

Per-component-type filenames:
- `check.py` / `agent.py` / `advisor.py` / `gate.py` — implementation
- `contract.yaml` — identity + I/O (loader reads this)
- `config.yaml` — tunables
- `tests/test_<folder>.py` — co-located tests (descriptive filename helps pytest output and `-k` selection)
- `README.md` — prose docs (optional)

**Well-known subdirs use generic names inside** (`prompts/system.md`, `migrations/001_init.sql`, `templates/detail.html`). The subdir path + parent folder already disambiguate.

**Ecosystem-reserved names** stay unchanged: `README.md`, `LICENSE`, `CHANGELOG.md`, `__init__.py`.

**Rationale.** Renaming a component is a single folder rename — no synchronized file renames, no `entry:` drift. Auto-discovery loaders (Next.js App Router, Django apps) use this shape because folder-is-the-unit / files-are-roles maps cleanly to mechanical discovery. Modern IDE tabs, Python tracebacks, grep output, and module-path log lines all carry folder context, so generic filenames don't lose legibility.

### 3.4 Loader rule

Discovery is mechanical: walk `{root}` recursively for folders containing `contract.yaml`. The folder name is the canonical slug. Validation semantics — identity invariants, ordering, and error handling — live in §6, the single authoritative description of loader behavior.

---

## 4. `contract.yaml` schema

**The schema is a Pydantic v2 model, and that model is authoritative.** The loader parses `contract.yaml` into it (`CheckContract(**yaml_data)`), so required/optional fields, types, enums, and UUID format are declared once in code. The YAML below is *illustrative* and generated to match the model — it can't silently drift or omit a field. `model_json_schema()` exports the JSON Schema consumed by the §8.3 local-agent validation gate and `verify_contracts()` (§8.6). (Pydantic at the I/O boundary, dataclasses for runtime domain objects — the split the codebase already uses.)

```python
# app/components/contracts.py  (sketch — the authoritative definition)

class Condition(BaseModel):                 # mirrors the CheckCondition dataclass
    output_name: str
    operator: Literal["exists", "equals", "contains", "truthy", "gte", "lte"] = "exists"
    value: Any = None

class CheckContract(BaseModel):
    # identity
    id: UUID4                               # assigned once at authorship
    name: str                               # slug; must match folder name
    type: Literal["check"]
    description: str
    entry: str                              # "check.py:ClassName"
    # execution wiring
    suite: str
    depends_on: list[Condition] = []        # parsed to runtime CheckCondition at load
    produces: list[str] = []
    # NOTE: no authored `phase`. Execution order is a runtime topological sort over
    # depends_on/produces (check_launcher.py); UI progress phase is derived from `suite`
    # (scan.html determineCurrentPhase). A static phase int would be a third, unbacked
    # source of truth — see §6.
    # safety / applicability / scheduling
    intrusive: bool = False
    service_types: list[str] = []
    parallel_safe: bool = False
    # I/O + metadata
    outputs: dict[str, Any] = {"observations": ["Observation"]}
    side_effects: list[Literal["network", "filesystem", "db", "none"]] = ["none"]
    techniques: list[str] = []
    references: list[str] = []
    reason: str = ""
```

Illustrative `contract.yaml` (matches the model):

```yaml
# app/checks/network/ports/contract.yaml

id: 7b3e2a94-1c6f-4d82-9a37-5e8b1f3c0d22
name: ports
type: check
description: "Scan TCP ports on discovered hosts."
entry: check.py:PortScanCheck

suite: network
depends_on:
  - output_name: services
    operator: truthy
produces:
  - open_ports

intrusive: false
service_types: [http, api]
parallel_safe: false

outputs:
  observations: [Observation]
side_effects: [network]
techniques: []
references: []
reason: ""
```

At load, each `depends_on` `Condition` is converted into a runtime `CheckCondition` dataclass (DTO-at-boundary → domain-object). `config.yaml` is loaded separately as its own `ConfigModel`; the contract never references it inline.

### 4.1 Field differences by component type

The four component types are sibling Pydantic models discriminated on `type` (a discriminated union); `CheckContract` above is the `check` variant. `AgentContract` etc. swap execution wiring for `role` / `triggers` / `tools` / `prompts`. The table shows where they diverge. (Agent/advisor/gate contracts are sketched here and get fully specified before 56.10.)

| Field | check | agent | advisor | gate |
|---|---|---|---|---|
| `suite` / `depends_on` / `produces` | ✓ | — | — | — |
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
# app/checks/network/ports/config.yaml

enabled: true                               # false → loader skips the check
on_critical: annotate                       # annotate | skip_downstream | stop | inherit

defaults:
  timeout_seconds: 30
  requests_per_second: 10
  retry_count: 1

# parameters:  <-- future; see note below. Not populated by the structural migration.
```

**On `parameters` (per-check custom tunables).** The structural migration (56.2–56.8) externalizes only `enabled`, `on_critical`, and the standard `defaults` knobs. Per-check *custom* tunables are **not** externalized here — they stay as class attributes in `check.py` until a later phase-17 wave wires WebUI parameter editing (around 56.15–56.17), at which point the discovery shape is decided (idiomatically, an explicit per-check Pydantic `Parameters` model — the §4 pattern). The earlier draft's example (`port_profile`, `scan_intensity`) was misleading: `port_profile` isn't a per-check config value at all — `ports.py` resolves it at runtime from scan context and `scope` config, not a class attribute.

### 5.1 Resolution order (last wins)

General → specific for the static layers, then ambient, then per-invocation. A more specific layer overrides a broader one.

1. Hardcoded class default
2. Suite-level defaults (`suite.yaml` — see §5.2)
3. `config.yaml` defaults (per-check — more specific than the suite)
4. Env var: `CHAINSMITH__<COMPONENT>__<PARAM>` (uppercase, `__` delimiter — see Notes) — ambient/deployment
5. User override file (future) — persistent operator preference
6. Runtime, most specific wins last:
   - a. Preset selection (a named bundle of params)
   - b. Explicit CLI flag / API param / WebUI field (a scalpel; beats a preset bundle)

**Notes**
- Per-invocation user input (6) is the most intentional signal and wins over an ambient env var (4) — reversed from the earlier draft, where the env var incorrectly sat on top.
- Suite-level defaults (2) sit *below* per-check `config.yaml` (3): the suite sets a broad baseline, the per-check file is the specific override.
- An env var used as a *hard ceiling* (e.g. ops capping max request rate) is **not** part of this chain — it's a clamp applied after resolution. Track separately if that need is real.
- **Env-var namespacing.** Component slugs and param names are already Python identifiers (no hyphens to convert — the old "hyphens → underscores" rule was moot), but they *contain* single underscores (`robots_txt`, `timeout_seconds`), so a single-underscore join is ambiguous. Resolution:
  - **Delimiter `__`** (double underscore) between segments: `CHAINSMITH__<COMPONENT>__<PARAM>`, e.g. `CHAINSMITH__ROBOTS_TXT__TIMEOUT_SECONDS`. Single underscores stay literal within names (pydantic-settings `env_nested_delimiter='__'` convention).
  - **Resolve by construction, not by parsing.** For each known `(component, param)` from the registry, construct the expected key and look it up in `os.environ` — never reverse-parse arbitrary env vars. Sidesteps split-ambiguity entirely.
  - **Lint:** forbid `__` in any component or param name (enforced via §8.6). With that, two distinct pairs can never generate the same key.

**Where resolution happens — two stages.** The six layers don't resolve at one moment:
- **Load-time (layers 1–5)** — class default → suite.yaml → config.yaml → env → user file. All are stable for the process (env is ambient; the user file is a persistent preference), so they resolve once when the component is loaded. A `ConfigResolver` (in `component_loader.py`) merges these Pydantic-validated source models in order; `from_config()` (§6) applies the result as the component's baseline.
- **Scan-time (layer 6)** — preset / CLI / API / WebUI. These vary per scan, so they're layered *on top of* the baseline in the runtime/scan path (ties into `ScanContext`), never baked into the loaded instance.

The resolver carries all five load-time slots from 56.1. **56.1 wires layers 1–4** (env included — a cheap construct-by-key lookup, §5.1); the user-override file (5) is future; scan-time (6) lands in 56.14 (presets) / 56.17 (runtime/WebUI). We use Pydantic for the per-source *models and validation* (§4) but a **thin explicit resolver for the *layering*** — our two-stage split and construct-by-key env diverge from `pydantic-settings`' out-of-the-box behavior, so we borrow its `__` convention without adopting the library.

> Caveat (layer 5): if the user-override file is ever meant as a *per-scan* file (`--config thisrun.yaml`) rather than a persistent dotfile, it moves to scan-time. Decide when layer 5 is actually designed.

### 5.2 Suite-level preferences (`suite.yaml`)

Co-located at `app/checks/<suite>/suite.yaml` (folder-is-the-unit; the loader already walks these dirs). Sets defaults shared by every check in the suite, overridable per-check by `config.yaml`.

```yaml
# app/checks/web/suite.yaml
name: web
enabled: true                 # false → loader skips the entire suite
on_critical: annotate          # suite-wide default; a check's config.yaml on_critical overrides it,
                               #   and a check on_critical: inherit resolves to this value
defaults:
  timeout_seconds: 30
  requests_per_second: 10
  retry_count: 1
```

**Fields:** `name` (must match the suite folder), `enabled` (false → loader skips the whole suite), `on_critical` (suite-wide default, and the parent that a check's `on_critical: inherit` resolves to), `defaults` (same knob set as per-check `config.yaml.defaults`).

**Loader handling:** `suite.yaml` has no `contract.yaml`, so it is never mistaken for a component. The loader reads it once per suite to populate precedence layer 2 (§5.1) before instantiating the suite's checks. A missing `suite.yaml` is fine — the suite simply contributes no layer-2 defaults.

This resolves `config.yaml`'s `on_critical: inherit` (§5): `inherit` → the suite's `on_critical` → (if unset) the global default.

### 5.3 Relationship to `ChainsmithConfig` (`app/config.py`)

There are **two config systems, and they stay separate** — this phase does **not** merge or replace `ChainsmithConfig`.

- **`ChainsmithConfig` (`app/config.py`)** — the existing app/infra config: a dataclass tree (14 sub-configs) loaded `defaults → chainsmith.yaml → CHAINSMITH_* env`, cached via `get_config()`. It uses **41 hand-enumerated single-underscore** env vars (`CHAINSMITH_SWARM_ENABLED`, …). It owns **cross-cutting policy**: `scope`, `storage`, `swarm`, `concurrency`, `scan_stream`, `litellm` (LLM endpoint + all model routing), `target_domain`, `paths`.
- **Per-component `config.yaml` + `ConfigResolver`** (§5/§6) — net-new (no `pydantic-settings`/`BaseSettings` exists in the tree today), Pydantic per-source models, **double-underscore construct-by-key** env (`CHAINSMITH__<C>__<P>`). It owns **per-component tunables**: `enabled`, `on_critical`, `timeout`/`rate`/`retry` defaults.

**Ownership rule:** *per-component knob → `config.yaml`; cross-cutting policy → `ChainsmithConfig`.* The `ConfigResolver` never touches the `ChainsmithConfig` loader; a component reads `ChainsmithConfig` only for genuinely global policy (e.g. `ports` reads `cfg.scope` — the **only** check that reads `get_config()` today). That cross-cutting read is correct, not duplication.

**Env namespaces cannot collide — verified.** Old = `CHAINSMITH_` + non-underscore; new = `CHAINSMITH_` + `_`. There are zero existing `CHAINSMITH__` (double) vars. And because the resolver only *constructs* keys for known `(component, param)` pairs (§5.1) rather than scanning `CHAINSMITH_*`, neither system can read the other's vars even in principle. The §8.6 lint forbidding `__` in component/param names seals it.

**Agents/advisors — the one place the systems overlap, resolved by migration.** `ChainsmithConfig` carries rich per-agent/advisor sub-configs (`adjudicator`, `triage`, `coach`, `researcher`, `scan_analysis_advisor`, `check_proof_advisor`). When those components port to the folder shape (56.10–56.12), their **per-component settings migrate into each component's `config.yaml`** (`enabled`, `context_file`, `context_window`, `kb_path`, …), leaving `ChainsmithConfig` with cross-cutting only. **Per-agent LLM model selection (`litellm.model_adjudicator`, `model_triage`, …) stays centralized in `ChainsmithConfig.litellm`** — model routing is treated as cross-cutting infra (one block to audit/swap all assignments), not a per-agent tunable. The ~12 affected `CHAINSMITH_*` env vars get a back-compat shim (old name still honored, deprecation-logged) so deployments don't break on the rename. Checks (56.1–56.9) have **no** `ChainsmithConfig` representation, so this overlap doesn't exist for them — the two systems are fully disjoint through the check phases.

---

## 6. Auto-discovery loader

Replaces `get_real_checks()` in `check_resolver.py`. New file: `app/component_loader.py`.

Two identity mechanisms, doing different jobs:
- **UUID** — the canonical, global collision-prevention identity. The deepest invariant; forward-compatible with the future multi-root module world where two components may share a slug across roots, disambiguated by UUID.
- **`folder_name == contract.name`** — in-tree naming *hygiene* (anti-drift, legibility). Not a collision mechanism — it just asserts the folder is named after its slug.

The loader validates **global-first** and does **not** fail-fast per folder, because a per-folder failure can mask the real root cause. (Canonical example: a dev copies `web/ports/` → `web/ports_v2/` and forgets to regenerate the UUID — producing a duplicate UUID *and* an incidental name mismatch. Fail-fast on the name mismatch would hide the duplicate UUID.) Errors are **accumulated** and reported together at startup — with ~133 components, several folders may be wrong at once and one-error-per-restart is painful.

```python
def discover_components(
    root: Path,
    component_type: Literal["check", "agent", "advisor", "gate"],
) -> list[BaseComponent]:
    """
    Four passes. Parse everything, validate global-first, then import survivors.
    Accumulate errors across passes 2–3; raise once with the full list.

    Pass 1 — parse & collect (no fail-fast on identity):
      Walk {root} recursively for folders containing contract.yaml.
      Parse each; collect (path, id, name, config). Fail only on unparseable YAML.

    Pass 2 — global identity (canonical invariants, accumulate):
        • UUID present & well-formed on every contract
        • UUID globally unique          ← primary collision check; names both paths
        • name globally unique          ← runtime selects by name (check_resolver)

    Pass 3 — per-component validation (hygiene, accumulate):
        • folder_name == contract.name
        • other required fields present
        • skip (don't load) if config.enabled is false
      → raise here if any error accumulated in passes 2–3.

    Pass 4 — load the survivors:
        • Import contract.entry file, resolve the declared class
          (fail loud on a broken entry reference)
        • Instantiate via BaseComponent.from_config() with merged config (§5.1)
      Return a suite-grouped, stable-sorted list (deterministic discovery output;
      runtime execution order is decided later by check_launcher.py over the
      conditions/produces DAG — the loader does not order by any authored phase).
    """
```

- **Global-first, no per-folder fail-fast.** UUID/name uniqueness (Pass 2) are the canonical invariants and run over the full collected set before any per-folder hygiene check (Pass 3) can abort. This keeps a copy-paste duplicate-UUID from being misreported as a name mismatch.
- **Two uniqueness invariants.** UUID is the deep identity; **name is also enforced globally unique in-tree** because the runtime selects checks by name (`check_resolver` filters on `check_names` / `suites`), so a duplicate name makes selection ambiguous. (In the future multi-root module world this relaxes: names may collide across roots, disambiguated by UUID.)
- **Validation before import.** Passes 1–3 are cheap and side-effect-free; importing the entry module (Pass 4) is the expensive, side-effect-prone step and runs only for components that pass validation *and* are enabled. A misnamed, malformed, duplicate, or disabled component never gets imported.
- **`from_config()` is a `BaseComponent`-level contract.** `BaseComponent` is the thin common ancestor of all four types, holding only what the loader touches uniformly — identity (`id`/`name`/`type`) and the `from_config()` construction contract. It does **not** exist yet: today's `BaseCheck.__init__(self)` takes no args and agents/advisors share no base. **56.1 introduces a *minimal* `BaseComponent`** (identity + `from_config()` only — the actual present requirement), with `BaseCheck` as its first subclass. The rich per-type bases (`BaseAgent`/`BaseAdvisor`/`BaseGate`) attach to it as their phases land (56.10–56.12), so the abstraction grows from real implementations rather than being guessed up front. `from_config()` instantiates the component, then applies the **load-time baseline** (layers 1–5) produced by the `ConfigResolver` (§5.1). Per-scan overrides (layer 6) are applied later in the scan path — not here.
  - **Construction is no-arg.** `from_config()` builds the instance via `cls()` — exactly how `get_real_checks()` instantiates all ~133 checks today — then applies the config baseline by attribute assignment. So **an auto-discovered component must be no-arg constructible** (no required positional `__init__` params beyond `self`). `verify_contracts()` (§8.6) AST-asserts this on every `entry` class so a non-conforming constructor fails at validation, not at runtime. Only **two** parameterized constructors exist in the tree, and neither breaks the rule:
    - `PortScanCheck.__init__(self, ports=None, profile=None)` — both optional, so `cls()` already works (and is what production uses; the args appear only in `test_port_profiles.py`). The args are a *programmatic override* for tests/callers; the loader never sets them. Per-scan port selection flows through `context` (`port_profile`) at runtime — the scan-time layer-6 path (§5.1) — never the constructor.
    - `SimulatedCheck.__init__(self, config: SimulationConfig)` — *required* arg, so **not no-arg constructible.** It is **deliberately excluded from auto-discovery**: it carries no `contract.yaml`, never appears in `check_resolver`, and is built only by the simulation factory (`app/checks/simulator/simulated_check.py`) from a `SimulationConfig`. The loader's contract-walk skips it naturally; **the `app/checks/simulator/` tree must never be given a `contract.yaml`** (state this so nobody "fixes" it into the loader). (Ties into C9 — the loader discovers by `contract.yaml` presence, so `simulator/` and non-check `frameworks/` are out by construction.)
- **No authored execution phase.** The loader does *not* sort by a static `phase` int — none exists on any check today. Execution order is decided at runtime by `check_launcher.py`, which repeatedly runs whichever pending checks have their `conditions` met (a topological walk over the `depends_on`/`produces` DAG). The loader returns checks grouped by `suite` (a stable sort for deterministic discovery output); ordering is the launcher's job. The UI progress bar's "phase" is a separate, display-only concept derived from `suite` (`scan.html` `determineCurrentPhase`, 3 phases) — never a per-check authored field.
- **Discovery scope, custom checks, and exclusions.** The loader walks each type's root (`app/checks/` for `check`, etc.) recursively for `contract.yaml`. Two consequences:
  - **Supersedes the custom-check registry.** Today `app/checks/custom/` is discovered via a hand-maintained `CUSTOM_CHECK_REGISTRY` tuple list (`_get_custom_checks()`, `check_resolver.py`) that the chainsmith agent string-edits. Under auto-discovery, `custom/` is just a discovered suite: a custom check is a component folder with a `contract.yaml`, found like any core check — **no registry, no string-editing**. `CUSTOM_CHECK_REGISTRY`, `_get_custom_checks()`, and the agent's `_register_custom_check` are deleted; `_validate_custom_check_health` is **superseded by `verify_contracts()`** (§8.6 — same job: instantiate, `issubclass(BaseCheck)`, well-formed metadata). The registry is empty today, so there is no data to migrate. The "community-upstream never touches `custom/`" property is a directory convention, preserved independently of the discovery mechanism. **Scope note:** in Phase 56 the `custom/` convention is **checks-only** — agents/advisors/gates remain core-only. The loader *mechanically* supports a `custom/` subdir under any type root (same recursive walk), but custom agents/advisors/gates are deliberately **future work** tied to the external `modules/` root (§2); a custom *gate* especially is deferred because it would put user-authored logic on the Guardian allow/block chokepoint.
  - **Non-check dirs are skipped by construction.** `app/checks/simulator/` (a real `BaseCheck`, but a required-arg constructor and factory-built — C7/§6 `from_config`) and `app/checks/frameworks/` (not checks — fingerprint definitions/base, no `BaseCheck` subclass) carry **no `contract.yaml`**, so the walk never picks them up. This is intentional: **neither directory may be given a `contract.yaml`.**
- **Caching (deferred):** `.chainsmith/component-index.json` keyed by contract path + mtime, per module-system-design §8.1. Not needed day one; add if startup gets slow.

---

## 7. Rollout phases

| # | Sub-phase | Scope | Risk |
|---|-----------|-------|------|
| 56.1 | **Foundation.** Loader, `contract.yaml` + `config.yaml` Pydantic schemas, minimal `BaseComponent` (identity + `from_config()`) with `BaseCheck` as first subclass, load-time `ConfigResolver` (layers 1–4, env included), folder-name / contract-name lint, migration tooling (`chainsmith dev new-check` + `migrate-check` + `migrate-suite` — detail in §8). Validate end-to-end on a single pilot check — **`robots_txt`** (simple, standard-shaped, has tests; deliberately *not* `ports.py`, the legacy outlier from §8.5). | Low |
| 56.2 | **Web suite** (23 checks). First full-suite migration. Exercises loader edge cases at real scale. | Medium |
| 56.3 | **Network suite** (13 checks). | Medium |
| 56.4 | **AI suite** (28 components). **Heaviest lift** — by far the largest suite (incl. `endpoints.py` splitting into 2: `llm_endpoint_discovery` + `embedding_endpoint_discovery`, §8.7). Budget accordingly; do *not* treat as equal-weight to network. | **Medium-High** |
| 56.5 | **MCP suite** (18 checks). | Medium |
| 56.6 | **Agent-check suite** (17 checks). Named to avoid confusion with the agent *component type* in 56.10. | Medium |
| 56.7 | **RAG suite** (17 checks). | Medium |
| 56.8 | **CAG suite** (17 checks). | Medium |
| 56.9 ✅ | **Check-resolver cleanup. DONE.** Retired the dead hand-maintained import list from `get_real_checks()` (now a single `discover_components()` call); `check_resolver.py` 570 → 195 lines. `infer_suite()` was **kept, not deleted** — collapsed to a pure prefix split in 56.7 (§14; registry/diff tooling still needs the lookup). **Custom-check registry path deleted** — `CUSTOM_CHECK_REGISTRY` + `_get_custom_checks()` (C9, §6) removed in 56.10d once the chainsmith agent's scaffolder was reworked to emit folder-shape `custom_<name>/` components; `custom/` is now an auto-discovered suite. (Per-component `__init__` re-exports stay — §12 Q1.) Gates green: pytest 2130p/5s/0f, collect 2135, verify-contracts OK, diff-registry CLEAN (123). | Low |
| 56.10 | **Agents component type.** Port `app/agents/*` (coach, adjudicator, triage, etc.) to the folder shape. **Rework the chainsmith agent's custom-check functions** (C9): `_scaffold_custom_check` → delegate to `chainsmith dev new-check --suite custom` (emits a component folder, not a flat `.py` + "edit the registry"); `_register_custom_check` deleted (folder presence = registration); `_validate_custom_check_health` → call `verify_contracts()`. Must land no later than the registry deletion so scaffolding and discovery never disagree (registry is empty today, so no gap meanwhile). **Migrate the `adjudicator`/`triage`/`coach`/`researcher` sub-configs out of `ChainsmithConfig` into each agent's `config.yaml`** (C10, §5.3); keep LLM model routing in `litellm`; add a back-compat shim for the affected `CHAINSMITH_*` env vars. | Medium |
| 56.11 ✅ | **Advisors component type. DONE.** Ported all 3 advisors (`scan_analysis`, `scan_planner`, `check_proof`) to folder shape (`advisor.py` + `contract.yaml` + `config.yaml` + `__init__.py` + co-located `tests/`). Added a thin `AdvisorContract` + `BaseAdvisor` marker + `AdvisorRegistry`/`discover_advisor_specs` — a **config/discovery accessor, NOT a factory**: advisors are deterministic and **caller-constructed** (the scan path / route builds them with per-call data), so `verify_contracts` exempts them from the no-arg rule (`_CALLER_CONSTRUCTED`) and there is no `.create()`/DI. Migrated the `scan_analysis_advisor`/`check_proof_advisor` sub-configs out of `ChainsmithConfig` into each advisor's `config.yaml` (typed config dataclasses kept, hydrated via `from_component_config`); `scan_planner` is `enabled:true` metadata-only (no new gating). Gates green: pytest 2147p/5s/0f (collect 2152), verify-contracts OK (checks+agents+advisors), diff-registry CLEAN (123). | Low |
| 56.12 ✅ | **Gates component type. DONE.** Ported the Guardian (scope + scan-window + forbidden-technique enforcement) to folder shape (`app/gates/guardian/` = `gate.py` + `contract.yaml` + `config.yaml` + `__init__.py` + co-located `tests/`). Operator decision: **one `guardian` gate, not three** — Guardian is *the* single chokepoint ([[project_guardian_gating]]), so splitting scope/window/technique into separate gates would fragment it; the class logic is byte-identical, only construction now resolves identity/`config.yaml` via the registry. Added a thin `GateContract` (with an `enforces` metadata list) + `BaseGate` marker + `GateRegistry`/`discover_gate_specs` — a **config/discovery accessor, NOT a factory**, exactly like advisors: gates are deterministic and **caller-constructed** (the scan route/scanner/launcher build a `Guardian` per scan via `from_scope(...)`), so `verify_contracts` exempts them from the no-arg rule (`_CALLER_CONSTRUCTED += "gate"`) and there is no `.create()`/DI. No `ChainsmithConfig`/env config existed for Guardian, so nothing was migrated out (config.yaml is `enabled` + informational knobs). The flat `app/guardian.py` was **deleted** and the ~5 `from app.guardian import Guardian` sites repointed to `from app.gates.guardian import Guardian`. The two Guardian enforcement test classes relocated from `tests/scanning/test_proof_of_scope_ops.py` to the co-located `tests/`. Gates green: pytest 2155p/5s/0f, verify-contracts OK (checks+agents+advisors+gates), diff-registry CLEAN (123). | Medium |
| 56.13 ✅ | **Phase-17 Wave 2: externalize payload data. DONE.** Moved hardcoded enumeration/discovery *data* out of 7 check implementations into `app/data/{wordlists,endpoints,payloads}/` (NOT top-level `data/`, which is the runtime DATA_DIR). New `app/lib/datafiles.py` with two **fallback-first** loaders — `load_wordlist(relpath, fallback)` (text, one per line, skips blanks/`#`) and `load_data(relpath, fallback)` (YAML list/dict). Each check keeps its prior inline list as the fallback (`_FALLBACK_*`/`_INLINE_*`), so a missing/unparseable file degrades to exactly the prior behavior; the shipped files contain the same entries, so default behavior is byte-identical. Externalized: `network_dns_enumeration` wordlist (33) → `wordlists/subdomains.txt`; `ai_llm_endpoint_discovery`/`ai_embedding_endpoint_discovery`/`ai_model_info_check` path lists → `endpoints/*.yaml`; `ai_input_format_injection`/`mcp_template_injection`/`agent_goal_injection` payloads → `payloads/*.yaml` (data files generated from the live constants + round-trip-verified). **Scope deliberately bounded to the phase17 Wave-2 named set** (operator decision): regex/signature *detection* patterns and the wider ~15 web/agent/rag/cag/mcp path lists were left inline (logic, or a possible follow-up). Config-override (`parameters.wordlist_file`) deferred to Wave 1/3. Hatch ships `app/data/**` already (no packaging change). Gates green: pytest 2165p/5s/0f (+10 loader tests), ruff clean (637), verify-contracts OK, diff-registry CLEAN (123); the 8 loaded constants verified == inline fallbacks. | Low |
| 56.14 ✅ | **Phase-17 Wave 3: scan presets. DONE.** A preset is a named, scan-time bundle (§5.1 **layer 6a**), orthogonal to the preference/profile system (`app/preferences.py` = behavior; preset = *what runs* + *per-check knobs*). Operator decisions: presets control **selection + params** (not selection-only / params-only); definitions are **externalized YAML** (`app/data/presets.yaml`, loaded via the 56.13 `datafiles.load_data` fallback-first loader with a byte-equivalent `_FALLBACK_PRESETS`); and they are a **new orthogonal concept**, not built on preferences. Each preset carries a *selection* half (`suites` / `checks` name-allowlist / `intrusive:false` → drop active-probing checks, the "passive" lens / `port_profile`) and a *defaults* half (the four standard knobs + `on_critical`) applied onto resolved check instances. New `app/scan_presets.py`: Pydantic `Preset` (validates suite names / port_profile / on_critical), `get_preset`/`list_presets`/`preset_names`, `resolve_selection` (explicit CLI/API selection **beats** the preset — §5.1 6b > 6a, resolved per-field) and `apply_runtime` (intrusive filter + knob overrides). Wired through `run_scan(preset=…)`, `ScanStartInput.preset`, the route (400 on unknown name) + new `GET /api/v1/scan/presets`, `cli_client.start_scan(preset=…)`, and a `--preset` CLI flag (validated against the local file). The 4 shipped presets: quick (network+web, web ports), thorough (all suites, lab ports, +retry), passive (non-intrusive only, lower rate), ai-focused (ai/agent/rag/cag/mcp). Gates green: pytest 2189p/5s/0f (+24 preset tests), ruff clean (640), verify-contracts OK, diff-registry CLEAN (123 — checks unaffected). | Low |
| 56.15 ✅ | **Phase-17 Wave 4: per-check on_critical + enabled end-to-end. DONE.** **on_critical** is now enforced **per-check** by the CheckLauncher: it resolves each check's `check.on_critical` (the ConfigResolver value from config.yaml — §5.3) and falls back to the legacy suite-level `app/preferences.py` value **only when the check is at the default `annotate`** (so existing `checks.on_critical_overrides` keep working). `stop` halts the scan; `skip_downstream` now skips the **true transitive DAG dependents** of the critical-emitting check (computed from `produces`/`conditions`, the same graph ChainOrchestrator builds) instead of the old coarse cross-suite blanket-skip; `annotate` is unchanged. **enabled** gets a disabled-visible introspection surface: `ComponentConfig` gains an optional `reason`; new `component_loader.discover_component_metadata` lists ALL components incl. disabled (import-free: name/suite/enabled/reason/on_critical/description), exposed via `GET /api/v1/checks?include_disabled=true` (disabled entries marked `enabled:false` + `reason`) so 56.17's WebUI can offer a re-enable toggle (resolves §17 D7/D8). Disabled checks still never run (loader skip unchanged). **Operator decisions:** per-check wins (prefs fallback at default); skip_downstream = true DAG dependents; **swarm path does NOT enforce on_critical** (documented gap, tracked follow-up — launcher-only this phase); add the disabled-visible surface now. Gates green: pytest 2203p/5s/0f (+14 tests), ruff clean (641), verify-contracts OK, diff-registry CLEAN (123). | Low |
| 56.16 ✅ | **Phase-17 Wave 5: startup config validation + end-to-end env/override surfacing. DONE.** Two halves. **(1) Validation folded into the shared `verify_contracts()` gate** (loader + CI + `dev verify-contracts` all enforce it identically): a new pass validates each component's `config.yaml` + each suite's `suite.yaml` against their Pydantic schemas, accumulating `config-schema`/`config-yaml-parse`/`suite-schema`/`suite-yaml-parse` violations instead of throwing a raw pydantic error mid-build (`_verify_tunable_config`). **Strict env (check root only):** `config_resolver.detect_env_problems()` enumerates the `CHAINSMITH__*` namespace and flags any var that names no known (check, knob) pair (`env-unknown` — a typo or a var aimed at a type that doesn't read these knobs) or carries an uncoercible value (`env-uncoercible`); these become hard `verify_contracts` violations, so a typo'd deployment override fails at load instead of silently doing nothing. `verify_contracts` gained an optional `env=` (defaults to `os.environ`; CI sets no such vars → clean no-op). **(2) End-to-end surfacing with full per-value layer attribution:** `ConfigResolver.resolve` now returns `ResolvedConfig.provenance` (each knob + on_critical → `class_default`/`suite`/`config`/`env`/`default`); `BaseCheck.from_config` stamps it as `check.config_provenance`. Surfaced three ways (operator decision): the resolved knobs + provenance appear under a new `config` block on every `/api/v1/checks` entry (`get_check_info`; disabled entries carry the block with null knobs for shape parity); `discover_components` logs a one-line startup summary of active env overrides (checks-only, the lone consumer); and a new offline `dev show-config [--check NAME]` prints each check's resolved layering + the active overrides. **Operator decisions:** fold into verify_contracts + strict env; surface via /api/v1/checks + startup log + dev CLI (no new endpoint); full per-value provenance. Gates green: pytest 2227p/5s/0f (+24 tests: 12 provenance/env-helper, 12 validation/route), ruff clean (643), verify-contracts OK (checks/agents/advisors/gates), diff-registry CLEAN (123 — no check logic changed). Deferred: `parameters.wordlist_file` config override (Wave 1/3); extending strict env to a future `CHAINSMITH__<AGENT>__<PARAM>` scheme. | Low |
| 56.17 ✅ | **Phase-17 Wave 6: WebUI check-detail modals + per-check parameter editing. DONE.** The final wave — lands the layer-6b runtime scalpel end to end. **Backend:** new `CheckOverride` model (5 optional fields: the 4 knobs + `on_critical`, validated — `gt:0`/`ge:0`, on_critical enum) on `ScanStartInput.check_overrides: dict[name → CheckOverride]`; new `app/scan_overrides.py:apply_check_overrides` assigns the set fields onto resolved instances in `run_scan` **after** `apply_runtime` (6b > 6a, ephemeral), threaded through the route. **Save-as-default (layer 3):** `PUT /api/v1/checks/{name}/config` writes the set fields into the check's `config.yaml` (`on_critical` top-level, knobs under `defaults:`, other keys preserved, merged doc schema-validated before write; PyYAML so header comments are not preserved — surfaced in the response `note`); `component_loader.find_component_dir` locates the folder; `scanner.rebuild_available_checks()` refreshes the display cache live (get_real_checks is uncached, so scans pick the new default up next run). **Frontend (vanilla JS, no build):** the shared `getCheckModalContent` (api.js) gained a Configuration section showing each knob's resolved value + provenance `[layer]`; read-only on scan.html, editable on the index.html launcher via a `window.CheckOverrideEditor` (per-scan overrides map + "Use for this scan" / "Save as default" / "Clear"). The launcher also got a **preset selector** (GET /api/v1/scan/presets → `ScanStartInput.preset`) and an **include_disabled toggle** (GET /api/v1/checks?include_disabled — disabled checks shown greyed/unselectable), and a per-check ⓘ opens the detail modal; `proceedWithScan` builds `{preset, check_overrides}` for `startScan`. **Operator decisions:** 5-tunable scalpel; **both** ephemeral (6b) AND save-as-default (layer-3 config.yaml write); surface **both** the preset selector and disabled toggle. Gates green: pytest **2248p/5s/0f** (= 56.16's 2227 + 21 new: `test_scan_overrides` 14, `test_check_config_save` 7), ruff clean (646), verify-contracts OK (all 4 roots), diff-registry CLEAN (123 — no check logic changed); JS syntax-checked (api.js + index.html inline). **Phase 56 COMPLETE.** | Medium |

**Each sub-phase lands as a separate PR — operator-driven** (all git is manual; see header). Suites in 56.2–56.8 are independent; one stuck PR doesn't block the others. Component-type phases (56.10–56.12) can run in parallel with the phase-17 waves (56.13–56.17) — different files.

> **Execution note (2026-06-01).** The structural suite migrations were executed slightly differently from the table above: the three AI-attack suites (**agent / rag / cag**, 17 checks each) were migrated together in a single pass labelled **56.6**, so the table's separate 56.7 (RAG) and 56.8 (CAG) rows were folded into it. All seven suites are now in folder shape. The freed **56.7** label is reused for a follow-on **convention sweep — uniform suite-prefixed names** — specified in §14. (The original §8.7 decision to *keep* the existing prefix hybrid is **superseded** by §14; see the note there.)

### 7.1 Execution tier by sub-phase

Maps the §8.2–8.4 work-split (deterministic / local agent / interactive assistant) onto the rollout. The local tier owns the repetitive middle; the interactive tier owns the ends.

| Tier | Sub-phases | Why |
|---|---|---|
| **Local agent + deterministic tooling** (mechanical bulk) | **56.2–56.8** — the 7 suite migrations (~133 components, AI heaviest) | High-volume, repetitive, recipe-driven by §8.2/§8.3. The `migrate-suite` → `--infer` → review → test loop (§8.4) does the work; the interactive assistant is pulled in only on escalation (§8.4 step 5). ~90% of the per-check volume. |
| **Interactive assistant** (novel code / judgment / sensitive) | **56.1** (loader, Pydantic schemas, `ConfigResolver`, `BaseComponent`, tooling); **56.10–56.12** (component-type ports — new base classes; 56.12 touches the Guardian chokepoint); **56.13–56.17** (phase-17 waves: data externalization, presets, flag wiring, env validation, WebUI) | New abstractions, design decisions, or sensitive code. Not repetitive; a local code agent isn't suited. |
| **Boundary** | **56.9** (resolver cleanup) | Mechanical deletions, but it removes the old safety net — run interactive-supervised, gated on a clean snapshot diff + fakobanko. |

### 7.2 56.1 ordering gate — the safety net must prove itself before any check moves

**No suite migration (56.2+) begins until the foundation is proven on one pilot check.** The whole "zero regressions" guarantee (§11) rests on a working test/verification net; migrating checks before that net is *proven live* means flying blind. The trap is specifically that an uncollected test fails **silently** (§10 risk 2) — so "the suite is green" is *not* proof the net works; green is also what an empty, never-run net looks like. The pilot must produce a **positive** signal that collection actually happens.

Run 56.1 in this order; each step gates the next:

1. **Consolidate pytest config + enable `--strict-markers`** (§10 risk 2). Run the *existing* suite on the **unchanged** tree to establish a known-green baseline; fix any strict-marker fallout here, before anything moves. This is the "fix the tests first" step — and it is a prerequisite, not part of the migration.
2. **Build the loader + tooling** — `component_loader.py`, `verify_contracts()`, `diff-registry` (§6, §8).
3. **Capture the `diff-registry` baseline** of the current registry *while the old loader is still live* (§8.1) — the pre-migration regression anchor.
4. **Migrate the pilot (`robots_txt`)** and **prove the net is live**, not merely green:
   - **Positive proof of collection** — `pytest --collect-only` shows the count rising by exactly the moved test(s), **or** deliberately break the moved test once and confirm it goes red, then fix it. A break that changes nothing means the test isn't being collected — the false-green (§10 risk 2).
   - The pilot's co-located test then passes for real.
5. **Confirm both behavior anchors** — `diff-registry --compare` clean **and** fakobanko observations identical (§9). These two are independent of the test-collection fix (a CLI tool and an end-to-end scan), so they hold even if per-check unit tests are sparse; they are the load-bearing "did the port preserve behavior" check.

Only after this end-to-end proof on a single check do 56.2–56.8 start. A net that turns out not to collect is then caught on **one** check, not discovered after 133 were "tested" by a net that never ran.

---

## 8. Migration tooling (sub-phase 56.1 detail)

Sub-phase 56.1 ships the CLI surface that makes 56.2–56.8 mostly mechanical. The goal is to minimize the per-check reasoning cost — both human and AI — by deriving every derivable field and leaving clearly-marked TODOs for the rest.

**Where the `dev` commands live (C11).** `app/cli.py` is a ~2,275-line **thin HTTP client** — operator commands (scan/observations/reports/prefs) delegate to a running server via `ChainsmithClient`. The `dev` commands are a **different category: local source-tree authoring tools** (filesystem + AST + codemod). They run **serverless** — no `ChainsmithClient`, no HTTP. Routing them through the server would be *wrong*: a remote/Docker server can't refactor the developer's local source. This doesn't break the CLI's shape — `cli.py` already hosts local, non-HTTP commands (`serve` boots uvicorn; `swarm agent` runs a local process), so `dev` extends an existing local-command category rather than violating a thin-client invariant. **Implementation lives in a new `app/dev/` package** (scaffolding, AST migration/codemod, registry-diff); `cli.py`'s `dev` group is thin Click wrappers importing `app/dev/` directly (mirroring how operator commands wrap `cli_client` and `serve` wraps `uvicorn`). `verify_contracts()` stays with the loader (§8.6) and is *called* by `dev verify-contracts`. The `dev` group is **registered with `hidden=True`** — out of top-level `--help` to keep the operator surface clean, still runnable in any checkout (and in CI for `verify-contracts`); in a deployed install with no editable source tree, commands that need one exit with a clear message. Scaffold templates live at **`app/dev/templates/component/`** (co-located with the dev logic — resolves §12 Q5).

### 8.1 Commands

- **`chainsmith dev new-check --name <name> --suite <suite>`** — scaffolds a fresh component folder with `check.py`, `contract.yaml` (UUID stubbed), `config.yaml`, `tests/test_<name>.py`. Used for all post-56.1 new work.
- **`chainsmith dev migrate-check <path>`** — takes a flat check file (e.g. `app/checks/web/robots.py`), creates the folder (with an `__init__.py` re-exporting the entry class, §3.1), moves files, derives the YAMLs, updates the suite's `__init__.py` re-export, removes the entry from `check_resolver.get_real_checks()`, and **codemods broken module-imports** (§10 risk 3): any `from app.checks.<suite>.<oldfile> import X` whose path changed (folder name ≠ old filename — 98 of 133 checks, e.g. `app.checks.mcp.discovery` → `app.checks.mcp.mcp_discovery`) is AST-rewritten to the new folder-package path across `app/` and `tests/`. The 35 same-name checks need no rewrite (their package transparently replaces the module). Supports `--dry-run`. **Folder name comes from the `name` *class attribute*, not the filename** (§8.7) — filenames are abbreviated (`robots.py` → name `robots_txt`; `ports.py` → name `port_scan`), and the runtime selects by `name`. **One source file may emit *N* folders:** the tool walks *every* `BaseCheck`/`ServiceIteratingCheck` subclass in the file and creates one folder per class, named from that class's `name` (e.g. `ai/endpoints.py` → `ai/llm_endpoint_discovery/` + `ai/embedding_endpoint_discovery/`). See §8.7.
- **`chainsmith dev migrate-suite <suite>`** — driver that runs `migrate-check` for every flat check in a suite, then `pytest tests/<suite>/`. Fails fast with a per-check status report.
- **`chainsmith dev diff-registry`** — confirms every pre-existing check still loads with the same `(name, suite, conditions, produces)` identity; catches silent drops or reorderings across a suite migration. Accepts **`--rename-map <file>`** (`old_name: new_name`) so a deliberate Category-A cleanup rename (§8.7) is treated as *expected*: "zero regressions" means *identical set after applying the rename map*, not a bit-identical set. Hybrid by design:
  - **Snapshot core (the migration safety check):** `--save-baseline <file>` dumps the live registry to JSON; `--compare <file>` diffs the current registry against it. Because the baseline is captured *while the old loader is live*, this works across the structural migration — where the pre-migration tree has no `contract.yaml` to read at all.
  - **Optional `--from-rev <sha>`:** for the same-loader case (e.g. comparing two post-migration revisions), reads that revision via a throwaway read-only worktree and dumps its registry. Read-only git only — no staging/commit/branch (header rule).

### 8.2 Deterministic field derivation

The tool generates these fields without any LLM call — all parseable from the source file:

| Field | How |
|---|---|
| `contract.id` | `uuid4()` |
| `contract.name` | the **`name` class attribute, verbatim** (Category-A cleanup renames applied via §8.7 map); the folder is named *from* this, never from the filename |
| `contract.type` | CLI arg (`check` / `agent` / `advisor` / `gate`) |
| `contract.entry` | `check.py:<ClassName>` — class name via AST walk over **every** `BaseCheck`/`ServiceIteratingCheck` subclass in the file (one folder per class; *not* "first subclass" — that would silently drop the 2nd check in a multi-class file like `endpoints.py`) |
| `contract.suite` | folder path (`app/checks/web/...` → `web`) |
| `contract.depends_on` | read the existing `conditions` class attribute (the declared dependency wiring). Fall back to an AST/grep of `context.get(<key>)` usage only when `conditions` is empty/absent — note `context`, not a `state` singleton (none exists). |
| `contract.produces` | read the existing `produces` class attribute directly (already declared on every check — see `app/checks/base.py`). No grep, no TODO. |
| `contract.intrusive` | existing `intrusive` class attribute |
| `contract.service_types` | existing `service_types` class attribute |
| `contract.parallel_safe` | existing `sequential` class attribute, **inverted** (`sequential=True` → `parallel_safe=false`) |
| `contract.techniques` / `references` / `reason` | existing class attributes of the same name |
| `contract.side_effects` | imports (`requests`/`httpx` → `network`, `sqlite3`/`sqlalchemy` → `db`, `open`/`pathlib` → `filesystem`) |
| `contract.description` | first line of the class docstring |
| `config.enabled` | `true` |
| `config.defaults.*` | the full tunable knob set: `timeout_seconds`, `retry_count`, `requests_per_second`, `delay_between_targets` |

Almost every field is now a direct class-attribute read; only `description`, `side_effects`, and (when `conditions` is absent) `depends_on` may fall back to inference — see §8.3 for those. The authoritative attribute→file mapping is §8.5.

Fields the tool can't confidently derive get written as `TODO:` so a grep (`rg 'TODO:' app/checks/`) surfaces everything needing review:

```yaml
description: "TODO: short description"
produces:
  - TODO
```

### 8.3 Optional: local code-agent assist (harness/model-agnostic)

Some `TODO:` fields resist regex/AST — non-standard dependency patterns, terse docstrings needing cleanup, unusual import-to-side-effect mappings. These can be filled by a **local code agent**: any code-capable model running on-machine via any harness. The design depends on the *role*, not the tool — the Ollama/Qwen setup below is one reference implementation, freely swappable for any local runtime (llama.cpp, LM Studio, vLLM, a local CLI agent, etc.).

**Tasks owned by the local code agent — and *only* these:**
- `description` — rewrite a terse or multi-line docstring into one clean sentence.
- `depends_on` — when the `conditions` attribute can't be read mechanically (§8.2), infer dependency keys from `context.get(...)` usage.
- `produces` — only if the `produces` class attribute is absent and keys must be inferred from code.
- `side_effects` — when imports don't map cleanly to `[network, filesystem, db, none]`.

Every one of these is a *TODO-filling* task on a field the deterministic pass (§8.2) could not confidently derive. The agent never originates a field the deterministic pass already produced.

**Never delegate to any agent:** `id`, `name`, `type`, `entry`, `suite`. These are deterministic and load-bearing — a wrong value silently breaks the loader.

**Contract for whatever agent is plugged in:**
- *Local only* — the migration touches ~133 checks; source must not leave the machine and there is no per-call API cost.
- *One field per call* — easier to validate, cheaper to retry.
- *Structured output* — returns JSON matching the field's schema.
- *Validation gate* — every agent-produced field passes JSON-schema validation before it's written. On validation failure or agent unavailability, leave the `TODO:` in place and log; never merge malformed output.

**Per-field prompting strategy:**
- `description`: source docstring + `"Return one sentence, present tense, under 80 chars."`
- `depends_on` / `produces`: check source + schema excerpt + `"Return a JSON list of strings; empty list if unclear."`
- `side_effects`: import list + `"Return a JSON subset of [network, filesystem, db, none]."`

**Reference setup (one option — Ollama + Qwen):**
- [Ollama](https://ollama.com) installed (single install, no API keys, runs as a background service).
- `ollama pull qwen2.5-coder:14b` — code-trained, Apache 2.0, strong at structured output (`:7b` on modest hardware, `:32b` on capable GPUs).
- The tool talks to the OpenAI-compatible endpoint at `http://localhost:11434/v1`.

**Invocation:**
```
chainsmith dev migrate-check <path>                    # deterministic only; TODOs stay as TODOs
chainsmith dev migrate-check <path> --infer=<agent>    # fill TODOs via the configured local agent
```
`--infer` takes an agent reference (e.g. `ollama:qwen2.5-coder:14b`); the tool resolves it through a thin adapter so the harness/model is a config choice, not baked into the migration logic.

**Why local matters here:** the migration touches ~133 checks. Batch-calling a hosted API for that many contract-inference calls is both costly and leaks source to a third party. Local inference is free after setup, private, and batch-friendly (run overnight, review the TODOs that remain in the morning).

### 8.4 Token-saving workflow

The intended cadence for 56.2–56.8:

1. Run `migrate-suite <suite>` locally (deterministic pass).
2. Run again with `--infer` to fill TODOs via the local code agent (§8.3).
3. Review remaining `TODO:` markers by hand — typically 2–5 per suite.
4. Run the suite tests. If green, the operator commits.
5. Only escalate to the interactive assistant for failing tests or ambiguous TODOs the local agent couldn't resolve.

This compresses the per-suite interactive-assistant conversation from "walk me through 20 migrations" to "here are 3 TODOs and 1 failing test — help?"

### 8.5 Attribute → destination map (authoritative)

Every existing `BaseCheck` attribute maps to exactly one destination. The migration tool follows this map; §8.2 covers *how* each is derived.

| `BaseCheck` attribute | Destination | Notes |
|---|---|---|
| `description` | `contract.yaml` | identity |
| `conditions` | `contract.yaml` → `depends_on` | declared dependency wiring |
| `produces` | `contract.yaml` | I/O |
| `service_types` | `contract.yaml` | applicability — *not* operator-tunable; an `http` check must never be retargeted at a non-web port |
| `intrusive` | `contract.yaml` | safety property; load-bearing for gating |
| `sequential` | `contract.yaml` → `parallel_safe` (**inverted**, default `false`) | execution-graph property; renamed to name the capability, not the restriction |
| `techniques` | `contract.yaml` | identity + drives the resolver's technique filter |
| `references` | `contract.yaml` | educational metadata |
| `reason` | `contract.yaml` | educational metadata |
| `timeout_seconds` | `config.yaml` → `defaults` | tunable |
| `retry_count` | `config.yaml` → `defaults` | tunable |
| `requests_per_second` | `config.yaml` → `defaults` | politeness tunable |
| `delay_between_targets` | `config.yaml` → `defaults` | politeness tunable |
| `status`, `result`, `_last_request_time`, `_scope_validator` | stays in code | per-run state, not config |

Rule of thumb: **what the check fundamentally is or does → `contract.yaml`; knobs an operator may safely retune → `config.yaml`; per-run state → code.**

**Migration invariant (mirror, don't strip).** The tool externalizes *only* the fields in this map. Every other class attribute — internal constants, regexes, helper data, and any non-standard metadata — **stays on the class in `check.py` and is never dropped.** When the tool encounters an attribute it can't place, it **flags it for review** (warns; never rewrites check code). This catches legacy outliers without the map having to be exhaustive. Example: `ports.py` carries `why` and `learning_objectives` (lab-era artifacts) instead of the canonical `reason` — 1 of ~133 checks. The flag surfaces it; the fix is a one-off manual cleanup (`why` → `reason`; fold any live intent from `learning_objectives` into `reason`, drop the stale lab text), not a tool behavior.

### 8.6 Contract integrity enforcement

The naming/identity rules — no `__` in component or param names (§5.1); `folder_name == contract.name`; UUID present, well-formed, and globally unique; name globally unique (§6); the `entry` class is **no-arg constructible** (no required positional `__init__` params beyond `self`, so `from_config()`'s `cls()` works — §6); every `test_*.py` under a component root lives in a `<component>/tests/` dir (§10 risk 2) — are **project-specific structural rules over folders + YAML**. Off-the-shelf linters can't express them: ruff lints Python AST/style and has no custom-plugin mechanism (it's Rust, unlike flake8); mypy checks types. Neither can assert anything about folder names. **Do not try to add these to the ruff config.**

Instead: **one validator, called from every gate.** Factor the loader's Pass 1–3 checks (§6) into a standalone `verify_contracts(root) -> list[Violation]` that does *not* import entry modules, then invoke it from:

1. **The loader**, at startup (already — §6).
2. **A pytest test** — `tests/test_contract_integrity.py` asserts `verify_contracts()` returns no violations. This is the primary CI gate: it runs inside the existing `pytest tests/` step in `ci.yml`, which already blocks PRs to `main`/`develop`. **Zero new workflow.**
3. **A `chainsmith dev verify-contracts` CLI** — same function, for local runs and pre-commit.

Optional hardening:
- **Named CI status check.** Add a `verify-contracts` step to `lint.yml` and require it via **branch protection** (the actual enforcement — a job blocks merge only if branch protection requires its status check). Clearer PR signal than "a test failed." `lint.yml`'s `paths-ignore: docs/**` is fine; components live under `app/`.
- **pre-commit hook.** A `.pre-commit-config.yaml` `local` hook running `chainsmith dev verify-contracts` catches violations at commit time, before push. The repo has none today, so it's additive; git stays operator-driven — the hook only runs on your `git commit`.

DRY is the point: loader, test, and CLI all call the same `verify_contracts()`, so "what CI enforces" can never drift from "what the loader enforces." (Generalizes the `chainsmith verify contracts` idea floated in §12 Q2.)

### 8.7 Component naming — folder from `name`, not filename (load-bearing)

Filenames are abbreviated (or, in the prefixed suites, *un*prefixed); the `name` class attribute is canonical and the runtime selects on it (`check_resolver` filters `check_names`/`suites`). Some diverge by abbreviation — `web/robots.py`→`robots_txt`, `web/cors.py`→`cors_check`, `web/headers.py`→`header_analysis`, `network/ports.py`→`port_scan`, `ai/cache_detect.py`→`response_caching` — and the entire `mcp_`/`agent_`/`rag_`/`cag_` set diverges by prefix (`mcp/discovery.py`→`mcp_discovery`). In total **98 of 133** components are named differently from their file (see §10 risk 3 for the import-path consequences). So:

1. **Folder = `name` attribute, verbatim.** `migrate-check` reads the `name` attribute via AST and names the folder from it. §6's `folder_name == contract.name` invariant then holds by construction. The filename is never the source of the folder name.
2. **Multi-class files split into N folders.** One source file may declare several checks (today only `ai/endpoints.py`: `LLMEndpointCheck`/`llm_endpoint_discovery` + `EmbeddingEndpointCheck`/`embedding_endpoint_discovery`). Each class becomes its own folder named from its own `name`. This is conceptually correct, not just mechanical — embedding/vector endpoints are a distinct attack surface from LLM chat/completion (a vector store can exist with no LLM). Shared helpers move to a sibling module imported by both `check.py` files.

**Category-A cleanup renames (the only `name` changes this phase makes).** Trailing generic role-suffixes (`_check`, `_scan`) carry no information the `type`/`suite` doesn't already convey and are dropped. Substance suffixes (`_discovery`, `_detection`, `_injection`, `_analysis`, `_enumeration`, `_fingerprint`, …) describe what the check *does* and are **kept**. Suite prefixes (`mcp_`/`agent_`/`rag_`/`cag_`, ~69 checks) are **deliberately kept** — they are load-bearing for §6's global-name-uniqueness invariant: dropping them collides `discovery` 4 ways (mcp/agent/rag/cag) and `cache_poisoning`/`auth_bypass` 2 ways each. Stripping suite prefixes is deferred to a separate redesign that first moves runtime selection to a `(suite, name)`-scoped key.

> **⚠ Superseded by §14 (sub-phase 56.7, 2026-06-01).** This paragraph reflects the *structural-migration* decision: keep the existing hybrid (some suites bare, some prefixed). It went two ways in execution — 56.5 actually *stripped* `mcp_`, leaving four bare suites (web/network/AI/MCP) and three prefixed (agent/rag/cag). The operator subsequently chose the opposite of "deferred": rather than *removing* prefixes (impossible without a `(suite, name)` key, exactly as warned), make them **uniform** — every check `<suite>_<name>`. That satisfies global-name-uniqueness *by construction* and turns `infer_suite()` into a pure prefix split. The Category-A *suffix*-drop renames in the map below stand; §14 *adds/restores* the suite prefix on top of them (`cors` → `web_cors`, and the 56.5 `mcp_` strip is reverted).

The full Category-A map (the `--rename-map` input for `diff-registry`, §8.1):

```yaml
# rename-map.yaml — applied atomically across name attr, folder, expected_findings, presets, CLI
cors_check: cors
sri_check: sri
webdav_check: webdav
mcp_auth_check: mcp_auth
context_window_check: context_window
content_filter_check: content_filter
model_info_check: model_info
rate_limit_check: rate_limit
port_scan: ports
```

**Each rename propagates atomically** to: the `name` attribute, the folder name, `scenarios/fakobanko/scenario.json` `expected_findings` keys (136 entries keyed `{name}-{host}-…`; all nine renamed stems appear there), any preset bundles, CLI `--check-names` defaults, and persisted scan rows. The migration applies the map and the §8.6 name-stability audit (post-set == pre-set *after* the map) confirms nothing else moved.

**Out of scope — simulation YAMLs.** The ~175 `scenarios/**/*.yaml` sim files are **not** in the regression path and need no updates: `scenario.json`'s `simulations: []` is empty (real checks run), and the sims' `check_name`/`emulates` values are already drifted from live names (`agent_callback` vs `agent_callback_injection`, `agent_loop` vs `agent_loop_detection`, …). They reference nothing the loader selects. The sole regression anchor is `expected_findings`.

---

## 9. Per-check acceptance checklist

**The flow is derive → load → verify, not hand-write.** `migrate-check` (§8.1) reads the *existing* check source and *generates* `contract.yaml` + `config.yaml` from it (§8.2 deterministic, §8.3 local agent for TODO fields); the loader (§6) then loads that YAML and instantiates the check. This checklist is the **acceptance gate** on the result — its job is to confirm **nothing was dropped** (every attribute mapped per §8.5 or deliberately left in `check.py`) and **nothing changed** (identical behavior). It is *not* a "write the YAML by hand" procedure.

*Before a suite:* `diff-registry --save-baseline <file>` — snapshot the pre-migration registry (§8.1).

*Per check (most of this is done by `migrate-check`; verify it holds):*

- [ ] Folder `app/checks/<suite>/<check_name>/` exists; check code moved to `check.py`.
- [ ] `contract.yaml` written per the §8.5 map (identity, wiring, safety/applicability, metadata); fresh `id` if none existed; `name` matches the folder.
- [ ] `config.yaml` holds **only** tunables — `enabled`, `on_critical`, and the `defaults` knobs (§8.5). *Not* identity/metadata — those are `contract.yaml`.
- [ ] **No-drop check:** any class attribute the tool couldn't map is *flagged and reviewed*, not dropped (Model B, §8.5) — it stays in `check.py` unless deliberately relocated.
- [ ] Tests at `tests/test_<check_name>.py`; original deleted (no duplicate); test is actually **collected** (§10 risk 2) and green.
- [ ] Component folder has an `__init__.py` re-exporting the entry class (pure `from .check import X`, identity-preserving — §3.1); suite `__init__.py` re-exports from the new folder path; any moved module-import paths codemodded to the new package (§10 risk 3).
- [ ] `verify_contracts()` passes for the check (§8.6).

*After all checks in a suite are migrated:*

- [ ] Suite removed from `check_resolver.get_real_checks()`.
- [ ] `diff-registry --compare <baseline> [--rename-map <file>]` clean — identical `(name, suite, conditions, produces)` set as the pre-migration snapshot *after* applying any Category-A renames (§8.7).
- [ ] Scan produces identical observations on the reference scenario (fakobanko) — `expected_findings` keys updated for renamed checks per the §8.7 map.

---

## 10. Risks

1. **Wide refactor.** Touching every check is inherently risky. Mitigated by per-suite PRs + full test run after each. Reference-scenario comparison (fakobanko) catches silent behavior drift.
2. **Test discovery — and a false-green trap.** Co-located tests under `app/checks/<suite>/<check>/tests/` are **not** collected by the current `testpaths = tests`. Uncollected tests don't fail — they silently don't run, a false-green that would quietly hollow out the "zero regressions" guarantee (§11). Fix lands in 56.1 with the pilot:
   - **Consolidate pytest config first (the gotcha).** Two configs exist today — `pytest.ini` *and* `pyproject.toml [tool.pytest.ini_options]` — and pytest reads only the first it finds: **`pytest.ini` wins and the pyproject block is silently dead.** So `--strict-markers`, `-ra`, `minversion`, `python_files`, and `python_functions` (pyproject-only) are currently *inert*, and any `testpaths`/`addopts` edit made to the pyproject block would no-op. **Delete `pytest.ini`, fold the union into `pyproject.toml`** (decision: single source = pyproject), then apply the changes below there. Turning on `--strict-markers` as the first commit may surface pre-existing typo'd/undeclared markers in the *current* suite — run `pytest tests/` once on the unchanged tree, fix what it flags, and only then start moving checks, so the baseline is clean. Verbosity stays `-v` (matches CI `pytest tests/ -v`; lets you confirm co-located tests actually ran — the whole point of this risk item).
   - **`testpaths = ["tests", "app/checks"]`** — add `app/agents` / `app/advisors` / `app/gates` as those phases land (explicit per-type sanctioning, not a blanket `app`, which would let pytest wander into non-component code).
   - **`--import-mode=importlib`** in `addopts` — the idiomatic mode for co-located / namespaced tests; avoids path-derived module-name collisions and the `__init__.py`-per-`tests/`-dir requirement. (The §6 name-uniqueness invariant already keeps `test_<folder>.py` names unique; importlib is belt-and-suspenders.)
   - **Placement guard** (in `verify_contracts()`, §8.6): every `test_*.py` under a component root must live in a `<component>/tests/` dir whose parent has a `contract.yaml`; a misplaced test fails CI. *This* — not `testpaths` scope — is what permanently prevents test files drifting to unexpected paths.
   - **Prove collection, don't assume it.** Because the failure is silent, "green" after the config fix does not prove tests run. The 56.1 pilot must produce a *positive* signal — `pytest --collect-only` count rising by the moved tests, or break-a-moved-test-once-and-watch-it-go-red — before any suite migrates. This is the §7.2 ordering gate.
   - **Avoid double-collection:** delete the original flat test file as you migrate; don't leave it behind.
3. **Import-path changes — 98 of 133 modules move, and class *identity* must survive.** There are ~389 direct module-imports (`from app.checks.<suite>.<file> import X`): ~133 are the suite `__init__.py` re-exports (auto-updated), ~6 other `app/` callers, and **247 in `tests/`**. Two facts shape the fix:
   - **Identity, not just resolvability.** `app/engine/scanner.py:176` does `isinstance(check, DnsEnumerationCheck)` to inject scenario known-hosts into the live check. The imported class and the loader-built instance must be the **same object**, so every shim/re-export is a pure `from … import X` — never a redefinition or subclass. (`dns_enumeration` is a same-name check, so its package `__init__.py` re-export keeps `scanner.py`'s import path *and* identity intact with **zero edits**.)
   - **35 same-name vs 98 renamed.** Where the component folder equals the old filename (35 checks — most of `network`, plus Category-A collapses `cors`/`ports`/`webdav`), the new package transparently replaces the old module: imports resolve unchanged. Where it differs (**98 checks** — all suite-prefixed `mcp_`/`agent_`/`rag_`/`cag_` modules whose files are *un*prefixed, e.g. `mcp/discovery.py` → `mcp/mcp_discovery/`; plus AI's abbreviated filenames), the old path vanishes. `migrate-check` **codemods** those ~257 import sites to the new folder-package path (§8.1). No leftover shim files; clean end state.
4. **UUID authorship burden.** One-time cost per component. The `chainsmith dev new-check` scaffold from 56.1 generates UUID + folder + skeleton files so contributors never hand-write one.
5. **Contract drift from code.** If `contract.yaml` declares `produces: open_ports` but the code never sets it, the loader can't catch that at parse time. Add a test-suite rule that runs each check against a mock target and validates declared outputs match actual. Defer to 56.9 if it slows the migration.
6. **Gate migration touching Guardian.** 56.12 reshapes the scan chokepoint. Carry extra test coverage; validate engagement-window enforcement and scope gating behave identically before/after.

---

## 11. Success criteria

- `pytest tests/` passes with zero regressions across 56.1–56.12.
- `check_resolver.py` shrinks to ~195 lines (from 570 today) — **met (56.9)**. (The original "below 100" figure assumed `infer_suite()` would be *deleted*; it is instead retained as a one-line prefix split — see next bullet and §14 — and `resolve_checks`/`apply_scenario`/the suite & technique filters/`get_check_by_name` legitimately stay in this module. 195 is the honest floor once the hand-list and the C9 custom-check registry path are gone.)
- `infer_suite()` reduced to a **pure prefix split** (`name.split('_', 1)[0]` validated against the suite set) after 56.7 makes every check name `<suite>_<name>`; the 56.5 `_MCP_CHECK_NAMES` exact-name special-case is deleted. (The original "delete `infer_suite()`" goal is relaxed: a one-line prefix derivation is simpler than maintaining a name→suite table, and registry/diff tooling still needs the lookup.)
- **Uniform naming:** every check name is `<suite>_<name>` (56.7); global-name-uniqueness holds by construction, not by collision-checking a flat namespace.
- Every in-tree component lives in a folder matching §3.
- Every component folder contains the role-based filenames from §3.3 (`check.py`/`agent.py`/`advisor.py`/`gate.py` + `contract.yaml` + `config.yaml`) and its `contract.name` matches the folder name.
- Adding a new check: run `chainsmith dev new-check --name foo --suite web` → edit the generated `foo.py` → done. No `check_resolver.py` edit.
- Operators can disable a check via `{check}.config.yaml: enabled: false` (effective next restart).
- Fakobanko scenario produces bit-identical observation counts pre- and post-migration (or documented diffs for explained behavior changes).

---

## 12. Open questions

1. **`__init__.py` re-export shims: keep permanent or remove in 56.9?** ~~Keeping means `from app.checks.web.robots import RobotsTxtCheck` works forever.~~ **Resolved (C8, §10 risk 3):** there is no per-module shim *file* to keep or remove — each component folder's `__init__.py` re-exports its entry class (part of the standard shape, §3.1), and the 98 moved import paths are codemodded to the new folder package, not shimmed. The "keep 98 stub `.py` files forever" option was rejected as cruft. The only permanent re-export surfaces are the per-component `__init__.py` (slug = package) and the suite `__init__.py` (suite package = stable public import API, matching how `check_resolver` already imports). 56.9 removes nothing import-related.
2. **Contract validation depth.** ~~Should the loader validate that `produces:` outputs are actually set by the check at runtime, or is that purely a test-suite concern?~~ **Resolved (§8.6):** static integrity (names, UUIDs, `__` rule, field presence) is the shared `verify_contracts()` validator. The deeper *runtime* check — does the code actually set what `produces:` declares — stays a test-suite concern, tracked as §10 risk 5 and deferred to 56.9.
3. **When to add the UUID override mechanism?** Not needed for in-tree work. Defer until the external `modules/` root phase. UUIDs in contracts now are forward-compat — the override wire is the future bit.
4. **Suite-level `suite.yaml`?** ~~Phase 43 proposed it for shared defaults. No concrete need yet.~~ **Resolved (§5.2):** adopted — co-located `suite.yaml` per suite folder, precedence layer 2, and the parent for `on_critical: inherit`.
5. **Template / scaffold location.** ~~`chainsmith dev new-check` needs a template folder. `app/dev/templates/component/` or `tools/templates/`?~~ **Resolved (C11, §8):** `app/dev/templates/component/` — co-located with the `app/dev/` package that the `dev` commands' logic lives in. `tools/` is ruled out because the single packaged entry point (`chainsmith = app.cli:main`) needs `cli.py` to import the logic, which a non-package top-level dir wouldn't allow cleanly.

---

## 13. Pre-implementation decisions (must resolve before 56.1)

This phase touches every component, so a wrong contract shape is replicated ~133 times and unwound ~133 times. These items must be settled and folded into the sections above before 56.1 ships. Worked one at a time; each decision is written back into the relevant section and checked off here.

Legend: `[x]` done · `[~]` proposed, pending confirmation · `[ ]` open.

- [x] **Config precedence + resolution** — reordered general→specific, per-invocation wins over ambient env var; two-stage resolution (load-time layers 1–5 via a `ConfigResolver` over Pydantic models; scan-time layer 6 in the scan path); 56.1 wires layers 1–4 incl. env. §5.1, §6.
- [x] **Git ownership** — all git is operator-driven. Header + §7.
- [x] **Local code-agent abstraction** — tasks defined by role; harness/model swappable. §8.3.
- [x] **Suite-level preferences** — co-located `suite.yaml` per suite folder; fields `name` / `enabled` / `on_critical` / `defaults`; precedence layer 2. §5.2.
- [x] **Attribute → destination map** — every `BaseCheck` attribute mapped to contract.yaml / config.yaml / code; `service_types` and `intrusive` → contract; `sequential` → `parallel_safe` (inverted, default false). §8.5.
- [x] **§8.2 derivation heuristics corrected** — `depends_on` from the `conditions` attribute (not the nonexistent `state.get`); `produces` read from the existing `produces` attribute; `config.defaults` covers the full knob set. §8.2.
- [x] **`on_critical` parent** — `inherit` → suite `on_critical` → global default. §5.2.
- [x] **Loader step order + UUID-collision pass** — four-pass, global-first: parse all → global UUID + name uniqueness (canonical, accumulated) → per-folder hygiene → import survivors. No per-folder fail-fast (would mask duplicate-UUID). §6.
- [x] **`from_config()` on `BaseComponent`** — base-class contract across all four types; 56.1 introduces it (doesn't exist today). §6.
- [x] **`chainsmith dev` location + shape (C11)** — `cli.py` is a thin HTTP client, but already hosts local commands (`serve`, `swarm agent`), so `dev` extends that category, not a violation. `dev` runs **serverless** (no `ChainsmithClient`); logic in a new **`app/dev/`** package, `cli.py` `dev` group is thin wrappers; `verify_contracts()` stays with the loader. Group registered **`hidden=True`** (operator pick: ship-but-hidden) — out of `--help`, runnable in any checkout/CI, inert with a clear message in a sourceless deploy. Templates at `app/dev/templates/component/` (resolves §12 Q5). §8.
- [x] **Two config systems, ownership boundary (C10)** — `ChainsmithConfig` (dataclass, 41 single-`_` env vars, cross-cutting/infra) and per-component `config.yaml`+`ConfigResolver` (Pydantic, double-`__` construct-by-key env) stay **separate**; no merge. Rule: per-component knob → `config.yaml`, cross-cutting → `ChainsmithConfig`. Env collision impossible (verified: 0 existing `CHAINSMITH__` vars; construct-by-key never broad-scans; `__` lint). Checks fully disjoint (only `ports` reads `get_config()`, for `scope`). Agent/advisor overlap resolved by **migrating** their sub-configs into `config.yaml` in 56.10–56.12 (operator pick) with a back-compat env shim; **LLM model routing stays centralized in `litellm`** (operator pick) as cross-cutting infra. `pydantic-settings` not adopted (borrow `__` convention only). §5.3, §7.
- [x] **Custom-check discovery superseded (C9)** — `custom/` becomes an auto-discovered suite; `CUSTOM_CHECK_REGISTRY` + `_get_custom_checks()` deleted (56.9), chainsmith agent's `_scaffold/_register/_validate_custom_check` rewired to `new-check` + `verify_contracts()` (56.10). Registry empty today → no data migration. `simulator/` + `frameworks/` excluded by construction (no `contract.yaml`; must never get one). **Custom scope = checks-only this phase**; multi-type custom (agents/advisors/gates) is required-later work under the `modules/` root (§2). §6, §2, §7, §8.6.
- [x] **Import shim + class identity (C8)** — verified ~389 module-imports (133 suite `__init__` re-exports, 6 other `app/`, 247 `tests/`); `check_resolver` uses none. Class *identity* matters: `app/engine/scanner.py:176 isinstance(check, DnsEnumerationCheck)` requires the imported class == loader-built object, so all re-exports are pure `from … import X` (no redefinition). Each component folder gets an `__init__.py` re-exporting its entry class (§3.1). 35 same-name checks resolve unchanged (package replaces module — incl. `dns_enumeration`, so `scanner.py` needs no edit); **98 renamed checks** (suite-prefixed + abbreviated AI files) have their ~257 import sites **codemodded** to the new folder path by `migrate-check` — no leftover stub files. §12 Q1 resolved (no per-module shims to keep/remove). §3.1, §8.1, §10 risk 3.
- [x] **No-arg construction + entry exceptions (C7)** — `from_config()` builds via no-arg `cls()` (matches all 132 production instantiations) then applies the config baseline; `verify_contracts()` AST-asserts every `entry` class is no-arg constructible. Two parameterized ctors handled: `PortScanCheck(ports=None, profile=None)` — optional, loader ignores the args (test-only; runtime port selection flows via `context`/layer-6); `SimulatedCheck(config)` — required arg, **excluded from discovery** (no `contract.yaml`, built by the simulation factory only; `simulator/` must never get a contract). The `entry`-AST half (walk *all* `BaseCheck`/`ServiceIteratingCheck` subclasses, not "first") landed with C2 (§8.2). §6, §8.6.
- [x] **Env-var namespacing** — `__` delimiter, resolve-by-construction, `__`-forbidden lint; hard-ceiling clamp confirmed out of the precedence chain. §5.1. Enforcement via the shared `verify_contracts()` validator (loader + pytest + CLI). §8.6.
- [x] **No authored `phase` (C1)** — verified: no `phase` attribute on any check or `base.py`; execution order is a runtime topo-sort over `conditions`/`produces` (`check_launcher.py`); UI progress phase is `suite`-derived/display-only (`scan.html` `determineCurrentPhase`, 3 phases). Dropped `phase` from the contract model, illustrative YAML, §4.1 table, §8.2 derivation, §8.3 never-delegate list, and the §6 loader ordering. `diff-registry` baselines `(name, suite, conditions, produces)`. §4, §6, §8.2.
- [x] **Suite counts rebaselined (C5)** — live component counts (by `name`): web 23, network 13, **AI 28** (was 18; incl. `endpoints.py`→2), MCP 18, **agent 17** (was 16), RAG 17, CAG 17 = **~133 total** (was "120+/131"). AI flagged heaviest lift (Medium-High), no longer equal-weight to network. §7, §7.1.
- [x] **Resolver baseline corrected (C6)** — `check_resolver.py` is **570 lines** today (`infer_suite` at 489), not ~300. §11 success criterion now "below 100 from 570." §1, §11.
- [x] **Pytest config consolidation (C12)** — two configs exist (`pytest.ini` + `pyproject.toml [tool.pytest.ini_options]`); pytest reads only `pytest.ini`, so the pyproject block — and its `--strict-markers`/`-ra`/`minversion`/`python_files`/`python_functions` — is currently dead, and the §10 risk-2 `testpaths`/`--import-mode` fix would no-op if applied there. **Resolved:** delete `pytest.ini`, fold the union into `pyproject.toml` (operator pick: single source = pyproject); keep `-v` (CI-aligned, confirms co-located tests run), drop the contradictory `-q`; turn on `--strict-markers` as the first 56.1 commit and run the unchanged suite once to clear any pre-existing marker violations before checks move. §10 risk 2.
- [x] **Component naming + cleanup (C2)** — folder name derives from the `name` *class attribute*, not the filename; multi-class files split one-folder-per-class (`endpoints.py` → llm + embedding, walk *all* subclasses); Category-A trailing-suffix cleanup only (`*_check`/`port_scan` → 9 renames via `--rename-map`), substance suffixes kept, suite prefixes kept (load-bearing for global-name-uniqueness — dropping collides `discovery`/`cache_poisoning`/`auth_bypass`); sims out of regression scope (dormant + drifted); `expected_findings` is the sole anchor and is propagated through the rename map. §8.7, §8.1, §8.2.
- [x] **Uniform suite-prefixed names (56.7, operator 2026-06-01)** — **reverses** the C2 "keep the hybrid" stance once execution had left four bare suites (web/network/AI) plus a stripped MCP and three prefixed (agent/rag/cag). Adopt `<suite>_<name>` for *every* check: add `web_`/`network_`/`ai_`, **restore** the 56.5-stripped `mcp_`. Rationale: collision-proof by construction, makes `infer_suite()` a pure prefix split, self-documenting in observations/logs. Gated suite-by-suite (own PRs); `infer_suite` simplified + `_MCP_CHECK_NAMES` deleted only at the very end (mid-sweep it must stay prefix-aware-with-fallback so unmigrated bare names still route). Full spec in §14.

---

## 14. Sub-phase 56.7 — Uniform suite-prefixed names (convention sweep)

**Status:** in progress (network piloted first). **Supersedes** the §8.7 "keep the hybrid / defer prefix changes" note. **Not a new migration** — all seven suites are already in folder shape (§13 execution note); this only *renames* already-migrated checks.

### 14.1 Goal & rationale

Every check name becomes `<suite>_<name>`. This is the long-term-viable convention because it is:
- **Collision-proof by construction.** §6's global-name-uniqueness invariant (one flat `by_name` map across the whole tree, `component_loader.py` Pass 2) is satisfied automatically — two suites can never both own a check whose name resolves to `discovery`. (The path does *not* save you: identity is the `name`, and §6's folder-name-mismatch rule forces the leaf folder to equal it. Suite-in-the-path ≠ clean registration; suite-in-the-name is what's required.)
- **`infer_suite()`-trivial.** Suite derivation collapses to `name.split('_', 1)[0]` validated against the suite set, killing the 56.5 `_MCP_CHECK_NAMES` exact-name special-case.
- **Self-documenting** in observations, logs, the API, and `expected_findings` keys.

### 14.2 Scope (4 suites; agent/rag/cag already correct)

Today's state is a hybrid: agent/rag/cag carry their prefix (56.6); web/network/AI are bare; MCP was *stripped* in 56.5. 56.7 makes it uniform:

| Suite | Count | Action | Example |
|---|---|---|---|
| web | 22 | add `web_` | `cors` → `web_cors`, `robots_txt` → `web_robots_txt` |
| network | 13 | add `network_` | `port_scan` → `network_port_scan` |
| AI | 28 | add `ai_` (2 existing `ai_*` already fine) | `jailbreak_testing` → `ai_jailbreak_testing` |
| MCP | 18 | **restore** `mcp_` (revert the 56.5 strip) | `auth_check` → `mcp_auth_check` |
| agent / rag / cag | 17×3 | none — already `<suite>_<name>` | — |

⚠ This **reverses committed work** (the 56.5 MCP strip and re-opens those shipped names). Confirmed by the operator 2026-06-01. Runs as its own reviewable phase, **gated suite-by-suite** — git is operator-only.

### 14.3 Tooling — `chainsmith dev rename-suite` / `rename-check`

The `migrate-*` tools are flat-file → folder and **do not apply** here. 56.7 adds `app/dev/rename.py` (+ thin CLI wrappers, `hidden=True` like the rest of `dev`). Per check, `rename-check <suite> <old> <new>` does:

**Auto (safe, mechanical):**
1. Rename the folder `app/checks/<suite>/<old>/` → `.../<new>/`.
2. Rewrite `contract.yaml` `name:` and the `check.py` `name = "<old>"` class attribute.
3. **Module-path codemod** — replace the dotted package `app.checks.<suite>.<old>` → `…<new>` across `app/` + `tests/` (word-boundary safe; this fixes the suite `__init__.py` re-export, the moved folder's own `__init__.py`, and every `from …import`/patch path). *Distinct from `migrate`'s codemod*: a folder→folder rename is a plain prefix swap with **no `.check` insertion** (refs already point at `.check`).

**Surgical (allowlisted, exact-quoted) name-string sweep:**
4. Replace exact-quoted (`"<old>"`, `'<old>'`) and finding-key (`"<old>-…"`) occurrences of the *name* — only in an explicit allowlist: `app/engine/chains.py` (`check_name`), `app/advisors/scan_analysis_advisor.py` (`trigger_check`/`suggest`), `scenarios/*/scenario.json` (`expected_findings` keys), `tests/**` (`.name ==` assertions; module patches handled by step 3), `static/scan.html` (phase-grouping arrays). **Never** touched: simulation YAMLs (`scenarios/**/simulations/**`, `app/checks/simulator/simulations/**` — out of regression scope, don't-touch), data keys (`mcp_servers`, `*_results`), and look-alike module names (`app/tools/port_scan.py`).

`rename-suite <suite> --prefix <suite>_` runs `rename-check` for every check in the suite and appends the `old: new` pairs to `.phase56/rename-map.yaml`.

### 14.4 `infer_suite()` during vs. after the sweep

`registry_diff._check_identity` derives suite from `infer_suite(check.name)`, so it must stay correct at every intermediate state (some suites prefixed, some not). Strategy:
- **During the sweep:** make `infer_suite` **prefix-aware first** — if `name.split('_',1)[0]` is a known suite, return it — then **fall through to the existing substring/`_MCP_CHECK_NAMES` logic** for not-yet-renamed bare names. Safe because the suite words only ever appear as deliberate prefixes (verified: no bare check's first `_`-token is a suite word). This makes both `web_cors` (prefixed) and `robots_txt` (bare, mid-suite) route correctly.
- **After all 4 suites:** collapse to the pure prefix split and **delete** `_MCP_CHECK_NAMES` + the substring `suite_patterns` table.

### 14.5 rename-map direction

Append `old: new` (e.g. `cors: web_cors`, `port_scan: network_port_scan`) per suite as it lands, so `diff-registry --rename-map` applies them to the pre-56.7 registry baseline → stays CLEAN. For MCP, the current `.phase56/rename-map.yaml` already has 56.5 strip entries (`mcp_auth_check: auth_check`); restoring the prefix means those net out — the registry baseline still carries the original `mcp_*`, so the cleanest path is to **drop** the 18 MCP strip lines (re-deriving identity from the baseline) rather than chaining a reverse rename.

### 14.6 Per-suite gates

Same as the structural migrations: `dev verify-contracts` OK · `dev diff-registry --compare .phase56/registry-baseline.json --rename-map …` **CLEAN** · full `pytest` green (collect parity) · `ruff check` + `ruff format --check` clean. Then the live fakobanko smoke after a container restart (§ smoke command; the renamed checks emit prefixed observation names, so update the `--ignore-check` set accordingly).

**Order:** network (piloted) → web → AI → **MCP last** (it also removes `_MCP_CHECK_NAMES` and the resolver special-case), then the final `infer_suite` simplification.

---

## Summary

One folder shape across all in-tree components. Generic role-based filenames inside named folders, Next.js App Router style: `check.py`/`agent.py`/`advisor.py`/`gate.py` + `contract.yaml` + `config.yaml`. The folder path carries identity; files fill well-known roles. `contract.yaml` is identity + I/O (machine-parseable); `config.yaml` is tunables; code and tests live next to them. Auto-discovery loader replaces hand-maintained registries. Phase-17's configurability, phase-43's restructure, and the module-system component shape all land in one coherent pass, scoped per suite so the blast radius stays bounded.

The external `modules/` root, routes/DB/UI extension points, and licensing remain future work, tracked in `module-system-design.md`. When that phase lands, in-tree components are already in the right shape — a folder move is all it takes to promote one to a module.
