# Module System Design

> **STATUS: PARTIALLY SUPERSEDED by [`phase56-component-modularization.md`](phase56-component-modularization.md).**
>
> The **component folder shape** and **per-component `contract.yaml` + `config.yaml`** from §3, §5, §6 have been absorbed into phase 56, which modularizes all in-tree components (checks, agents, advisors, gates) using the shape described there. Phase 56 adopts folder-name-prefixed filenames (e.g. `ports.contract.yaml`) rather than the generic names originally proposed here, to eliminate conversational and IDE ambiguity.
>
> **Still future work (not in phase 56):**
> - External `modules/` discovery root (§4.2, §4.3)
> - UUID-based override resolution between roots (§4.1)
> - Multi-component extension points: routes, DB models + migrations, UI slots, CLI groups, enrichers (§7, §9.1, §9.2)
> - Manifest + lifecycle + cached index (§5, §8)
> - Licensing and paid-tier validation (§9.3, §11 phases 2, 5)
> - Engagements port as reference implementation (§10)
>
> Phase 56's in-tree restructure is the foundation for this broader system — when this module system lands, in-tree components are already in the right shape, so promoting one to an external module is a folder move.

**Status:** Partially superseded (see banner above). Remaining scope is future work.
**Purpose:** Define how Chainsmith gains capabilities — core components and community/paid add-ins alike — via fine-grained, drop-in directories that are fully self-contained (code + config + tests + contract).

---

## 1. Goals and non-goals

### Goals

- **Single codebase.** Core OSS is the only codebase. Paid/private add-ins live under `modules/`, never forks.
- **Fine-grained, self-contained modules.** One component per folder: code, YAML config, YAML contract, and tests travel together. A community member can author a single check or a single agent as a complete, shareable package without touching anything else.
- **Low drag for contributors (human or AI).** Every module has the same shape. Nothing to wire up elsewhere; discovery is mechanical.
- **Full-stack contribution.** A module can add checks, agents, advisors, gates, API routes, DB tables, CLI commands, reports, and web-UI surfaces.
- **Core doesn't import modules by name.** Modules register with core via declared extension points. Core knows the contract, not the names.
- **Community and commercial tiers coexist.** A module declares a tier; paid modules validate license at load time. Some features (engagements being the first) are *intentionally* paid-only and will never ship in the OSS distribution.
- **Graceful degradation.** If a module fails to load, core keeps running; only that module's features are disabled.
- **No namespace collisions.** Modules are identified by UUID internally; human-readable names are display-only.

### Non-goals

- **Hot reload.** Modules load at startup; changes require a restart.
- **Sandboxing.** Modules run with full core privileges. Installing a module is a trust decision, same as installing any Python package.
- **Cross-module dependencies.** A module may assume core APIs, but not other modules. (If two modules need to talk, they talk through core.)
- **Runtime marketplace.** The registry/distribution story is out of scope for this doc; we define the *loading contract*, not the delivery mechanism.

---

## 2. Core insight

The split that matters is **"what does core know by name"** vs. **"what does core discover at runtime"**.

- Core knows, by name: `scope`, `scan`, `scan_history`, `observations`, `checks`, `chains`, `reports`, `scenarios`. These are the OSS product surfaces.
- Core discovers, at runtime: every module in `modules/` and every component under the in-tree core component directories (`app/checks/`, `app/agents/`, `app/advisors/`, `app/gates/`). Core knows *the shape of a module* (the contract), not any specific module.

Both paths use the same module shape. Core components are "modules that happen to live in-tree" — they carry the same manifest + contract + tests layout. This keeps the shape universal: a community contributor learns one format, and a component's promotion from `modules/` to core is a folder move, not a rewrite.

---

## 3. Module anatomy

A **module** is a directory containing one or more **components**. A component is the smallest useful unit — one check, one agent, one advisor, one gate, one route bundle. A module may be a single component (most community modules) or a bundle of related components (feature packs like engagements).

### 3.1 Single-component module (most common)

```
modules/<human-name>/
├── manifest.yaml           # module-level metadata (required)
├── module.py               # optional — only if the module needs a register() hook
│                           #   beyond what component contracts declare
├── <component-type>/       # one of: checks, agents, advisors, gates, routes, reports
│   └── <component-name>/
│       ├── contract.yaml   # ground-truth I/O contract (required)
│       ├── config.yaml     # runtime tunables (optional)
│       ├── <code>.py       # the implementation (required)
│       ├── prompts/        # for agents: system/user prompt templates (optional)
│       └── tests/          # component-scoped unit tests (required)
```

Example — a single community check:

```
modules/http-header-audit/
├── manifest.yaml
└── checks/
    └── http_header_audit/
        ├── contract.yaml
        ├── config.yaml
        ├── check.py
        └── tests/
            └── test_check.py
```

### 3.2 Multi-component module (feature bundles)

```
modules/engagements/
├── manifest.yaml
├── module.py               # bundle-level register() for routes, DB, UI slots
├── db/
│   ├── models.py
│   └── migrations/
├── routes.py
├── cli.py
├── templates/              # UI slot fragments
├── reports/
└── agents/
    └── engagement_coach/
        ├── contract.yaml
        ├── config.yaml
        ├── agent.py
        └── tests/
```

**Why a fixed layout:** discovery is mechanical, not configurable. Review, audit, and AI-assisted authoring are easier when every module looks the same.

**Core components use the same shape, in place.** `app/checks/<name>/`, `app/agents/<name>/`, etc. each carry `manifest.yaml` (or a lighter component-local marker), `contract.yaml`, code, and tests. Core is not relocated to `modules/`; it is modularized where it lives.

---

## 4. Identity, naming, and precedence

### 4.1 UUID identity

Every module and every component has:

- **`id`**: a UUIDv4 assigned once by the author. This is what core uses internally for registration, override, telemetry, and wire references. UUIDs never collide.
- **`name`**: a human-readable slug (e.g., `adjudicator`, `industry_adjudicator_finance`). For display and CLI ergonomics only. Duplicates across modules are legal.

Two community modules can both call their agent `adjudicator`. Core distinguishes them by UUID; the UI disambiguates by showing the module name alongside.

### 4.2 Discovery paths and precedence

Core scans two roots:

1. **In-tree core components** (`app/checks/`, `app/agents/`, `app/advisors/`, `app/gates/`).
2. **`modules/`** — community and paid add-ins.

Both contribute to the same registry, keyed by UUID. **A component from `modules/` takes precedence over a core component only when it explicitly declares `overrides: <uuid-of-core-component>` in its manifest.** Otherwise, components coexist — a module that adds a new adjudicator does not displace the core one; both are available and the operator picks.

Explicit-override semantics keep the intent visible: replacing a core behavior is a decision an operator can audit by grepping for `overrides:`.

### 4.3 Promotion path

A community module proven in `modules/` can be promoted into core by moving its folder to the appropriate in-tree location (`app/checks/<name>/`, `app/agents/<name>/`, etc.). The manifest, contract, config, code, and tests move unchanged. No rewrites, no flattening — the module shape is the same in both places.

---

## 5. Manifest

`manifest.yaml` is the only file core parses before deciding whether to load the module. It describes *load-time* facts.

```yaml
module:
  id: 3a1c4b8e-2f9d-4a17-8c11-7e9a5b2d4f01
  name: engagements
  version: 0.1.0
  description: Group related scans into engagements with trend analysis
  tier: pro                  # community | pro | enterprise
  chainsmith_min_version: 1.2.0
  chainsmith_max_version: 2.0.0

license:
  # Present only for non-community tiers. Core calls this validator at load
  # time and skips the module if it returns False.
  validator: module.license:check
  offline_grace_days: 7

dependencies:
  # Extra Python deps. Aggregated and resolved together across all modules.
  python:
    - httpx>=0.27
    - croniter>=2.0

contributes:
  # Declarative inventory of what this module ships. Lets core validate the
  # manifest matches the code and lets operators audit without reading source.
  routers: [engagements]
  cli_groups: [engagements]
  db_models: [Engagement]
  ui_slots: [nav.primary, scan.sidebar, dashboard.cards]
  components:
    - type: agent
      id: b7f2...
      name: engagement_coach
      path: agents/engagement_coach
    - type: check
      id: c91e...
      name: engagement_drift_check
      path: checks/engagement_drift

overrides: []                # optional list of component UUIDs this module replaces
```

The manifest is the **module-level contract surface**. Per-component detail lives in each component's `contract.yaml`.

---

## 6. Component contract (`contract.yaml`)

Every component ships a `contract.yaml` that declares what the component **consumes**, **does**, and **produces**. This is ground truth for the loader, the registry, and any AI agent reasoning about composition.

### 6.1 Check contract

```yaml
id: 7b3e2a94-1c6f-4d82-9a37-5e8b1f3c0d22
name: http_header_audit
type: check
description: Audit HTTP response headers for common misconfigurations.

inputs:
  target: Target              # core type; see chainsmith.contracts
  config: ref(config.yaml)

work:
  summary: Issues one HEAD per URL, evaluates headers against policy.
  side_effects: [network]     # network | filesystem | db | none

outputs:
  observations: [Observation]

tests:
  path: tests/
```

### 6.2 Agent contract

Agents are **LLM-powered**. They do not declare a model tier — the LLM provider and model are chosen at chainsmith startup (see `chainsmith.sh`) and injected at runtime.

```yaml
id: a21d4b50-8e09-4f71-9d3a-c4e2f1b8a055
name: industry_adjudicator_finance
type: agent
role: adjudicator            # adjudicator | coach | planner | custom
description: Adjudicates observations using finance-sector compliance norms.

triggers:
  - observation.created
  - chat.message

inputs:
  observation: Observation
  scan_context: ScanContext

outputs:
  adjudication: Adjudication

tools:
  - db.read
  - llm.call

prompts:
  system: prompts/system.md
  user: prompts/user.md

overrides: <uuid-of-core-adjudicator>   # optional; makes replacement explicit
```

### 6.3 Advisor contract

Advisors are **deterministic**. They analyze data and return recommendations without calling an LLM.

```yaml
id: ...
name: scan_planner_advisor
type: advisor
description: Proposes scan plans from scope + history. Pure function of inputs.

inputs:
  scope: Scope
  history: [ScanSummary]

outputs:
  plan: ScanPlan
```

### 6.4 Gate contract

Gates are **deterministic policy enforcement points** (guardian-style). They return allow/block, never "recommend."

```yaml
id: ...
name: engagement_window_gate
type: gate
description: Blocks scans outside the configured scan window.

inputs:
  scan_request: ScanRequest
  policy: ref(config.yaml)

outputs:
  decision: GateDecision      # allow | block(reason)
```

### 6.5 Component-type summary

| Type | LLM? | Determinism | Typical output |
|---|---|---|---|
| **check** | optional | usually deterministic | observations |
| **agent** | **yes** | non-deterministic | adjudications, coaching, plans (LLM-produced) |
| **advisor** | **no** | deterministic | recommendations, analyses |
| **gate** | **no** | deterministic | allow/block decisions |

`role` on an agent is a *sub*-classification (adjudicator, coach, planner). Guardian-style policy enforcement is a **gate**, not an agent.

---

## 7. Extension points

These are the hooks core publishes. A multi-component module's `module.py` exports `register(core)` where `core` exposes typed APIs for each extension point. **Single-component modules usually don't need `module.py`** — the component's `contract.yaml` plus its code file is sufficient; the loader registers it based on contract type.

```python
# modules/engagements/module.py  (only for multi-component bundles)
from chainsmith.module_api import Module, Core
from . import routes, cli, db

class EngagementsModule(Module):
    def register(self, core: Core) -> None:
        core.routes.mount(routes.router, prefix="/api/v1")
        core.cli.add_group(cli.engagements_group)
        core.db.register_models(db.models.Base)
        core.db.register_migrations(__package__, "db/migrations")
        core.ui.contribute("nav.primary", label="Engagements", href="/engagements")
        core.ui.contribute("scan.sidebar", template="templates/scan_sidebar.html")
        core.reports.register_section("engagement", render=self.render_engagement_section)
        core.scan.on_create(self.link_scan_to_engagement)
```

**Extension point categories:**

| Category | API surface | Notes |
|---|---|---|
| **Checks** | auto-registered from `contract.yaml` (type=check) | Directory-scan discovery across both roots; UUID-keyed. |
| **Agents** | auto-registered from `contract.yaml` (type=agent) | Role-indexed; LLM provider injected at runtime. |
| **Advisors** | auto-registered from `contract.yaml` (type=advisor) | Deterministic; called by core or other components. |
| **Gates** | auto-registered from `contract.yaml` (type=gate) | Deterministic allow/block; Guardian composes gates. |
| **Routes** | `core.routes.mount(router, prefix)` | Standard FastAPI router. Core namespace-checks prefixes. |
| **CLI** | `core.cli.add_group(group)` / `core.cli.extend_group(name, subcommand)` | Click groups; modules can add new top-level groups *and* extend existing core groups. |
| **DB models** | `core.db.register_models(base)` | Module owns its tables. Names prefixed `mod_<module-name>_*`. |
| **DB migrations** | `core.db.register_migrations(pkg, path)` | Each module has its own migration lineage. |
| **Reports** | `core.reports.register_section(name, render)` | Named section renderers; templates opt in via `{% section "engagement" %}`. |
| **UI slots** | `core.ui.contribute(slot, ...)` | See §9 for the slot model. |
| **Scan hooks** | `core.scan.on_create/on_complete(...)` | Take `scan_id`; concurrent-aware per `concurrent-scans-design.md`. Fired in registration order; exceptions isolated. |
| **Enrichers** | `core.scan.register_enricher(fn)` | Batch enrichment for list views. Avoids N+1. Generalizes beyond scans to observations, checks, chains. |

**Contract philosophy:** extension points are **additive, not subtractive**. A module can add a nav item; it cannot remove one. A module can register a new adjudicator alongside the core one; replacing a core component requires an explicit `overrides:` declaration. This keeps modules composable.

---

## 8. Lifecycle

### 8.1 Cached manifest index + lazy import

With fine-grained components, a deployment may carry hundreds of modules. A naive scan-then-import-everything startup would be slow. Core uses:

1. **Cached manifest index** at `.chainsmith/module-index.json`. Keyed by file path + mtime of every manifest/contract. Full scan only when mtimes change.
2. **Lazy code import.** Manifests and contracts are parsed at startup (cheap YAML). Component `.py` files are imported on first invocation, not at boot.

This keeps startup fast regardless of module count; import cost is paid only for components actually used in a given run.

### 8.2 Startup flow

```
startup
  ├─ load .chainsmith/module-index.json if fresh; else rescan both roots
  ├─ for each module entry in index:
  │    ├─ check chainsmith_min/max_version
  │    ├─ check python dependencies resolvable (aggregated across all modules)
  │    ├─ for non-community tier: call license validator
  │    ├─ parse component contracts and build registries (checks/agents/advisors/gates)
  │    ├─ if module has module.py: import and call register(core)  ← try/except per module
  │    └─ on failure: mark module status=failed, continue
  ├─ resolve overrides: later-loaded `overrides: <uuid>` replaces earlier entry in registry
  ├─ run DB migrations (core + each successfully loaded module, in dependency order)
  ├─ mount routers, assemble CLI, render UI manifest
  └─ start server (component .py imports deferred to first invocation)

shutdown
  └─ for each loaded module (reverse order): call module.teardown(core) if defined
```

**Load order is deterministic** (alphabetical by module name, with core root first) so failures and overrides are reproducible.

**Dependency resolution.** The loader aggregates `dependencies.python` entries from every manifest and resolves them together against the core venv. Two modules requiring `httpx>=0.27` and `httpx>=0.26` resolve to one install satisfying both. Conflicting constraints fail loudly at load time with both module names in the error.

**Failure isolation:** a module that raises during load is disabled for the process. Core logs the failure, marks the module `status=failed` in the operator-visible `/api/v1/modules` endpoint, and continues. This is the difference between "my engagements module is broken" and "my Chainsmith instance won't boot."

---

## 9. Hard problems

### 9.1 Frontend integration (hardest)

The current frontend is static HTML + vanilla JS (no build step). Modules need to contribute UI without forking `static/index.html`.

**Proposed approach: server-side slot rendering.** Core's HTML templates define named slots:

```html
<nav>
  <a href="/">Scans</a>
  <a href="/scan-history">History</a>
  {{ ui_slot("nav.primary") }}
</nav>
```

`ui_slot(name)` expands to the concatenated contributions from all loaded modules, each a small HTML fragment shipped in `templates/`. For richer UI (a full Engagements tab), a module registers a page:

```python
core.ui.register_page("/engagements", template="templates/engagements.html")
```

and ships JS/CSS under `modules/<name>/static/`, mounted at `/modules/<name>/static/`.

**What this doesn't solve:** deep cross-cutting UI (e.g. "every scan-history row shows an engagement badge"). Handled via the **Enricher** extension point — batch enrichment, one bulk query per list render. Module data lives in `mod_<name>_*` join tables, not columns on core tables.

**Alternative for v2:** introduce a build step (Vite/esbuild) with a proper plugin mechanism. Bigger change, but unlocks real component composition.

### 9.2 Database migrations

Each module owns its tables and migration lineage. Core runs migrations in two passes:

1. Core migrations (existing lineage).
2. Each loaded module's migrations, in load order.

**Uninstall semantics:** deleting a module's folder leaves its tables behind — dropping tables on removal is a footgun. Provide `chainsmith modules uninstall <name> --drop-data` as an explicit, scary command.

**Table name collisions:** enforce a `mod_<module_name>_` prefix in the migration runner. Reject migrations that create tables outside the module's namespace.

Depends on `schema-migration-tooling.md` landing first.

### 9.3 Licensing for paid modules

- License key in env var or `~/.chainsmith/license`.
- `license.validator` function gets the key + module version, returns `bool`.
- Short-lived signed tokens (JWT, ~30-day expiry), refreshed against a license server.
- Offline grace period (configurable per module).

**Intentionally not solving:** DRM/obfuscation. If someone wants to run a paid module without paying, they can. Paid-tier value is support, updates, and license-server reachability — not anti-tamper.

### 9.4 Coupling to core changes

Modules pin a core version range in the manifest. Core publishes a stable **Module API** (`chainsmith.module_api`) with a semver guarantee. Everything else — internal repositories, route signatures, DB schema of core tables — is **not** a stable API.

### 9.5 Testing

- Core ships `chainsmith.module_testing` helper that spins up a core instance with only the module-under-test loaded.
- Each component has `tests/` run via `pytest modules/<name>/<type>/<component>/tests`.
- CI runs: core tests, then each module's tests, then integration with all community modules loaded.

---

## 10. Engagements as the reference implementation

Engagements is the motivating case and the reference multi-component module. It's **paid-only** — validating the module API and the tier/licensing model in one shot. It exercises every extension point:

- Routes (`/api/v1/engagements/*`)
- CLI (`chainsmith engagements ...`)
- DB models + migrations (`mod_engagements_*`)
- Report sections (compliance/exec/trend render an engagement block)
- UI slots (nav item, scan-sidebar panel)
- Scan hooks (on scan create, optionally link)
- An agent component (e.g., `engagement_coach`) exercising the agent contract
- The enricher extension point for scan-list badges

**Resolved:** `Scan.engagement_id` becomes a join table `mod_engagements_scan_links` owned by the module, not a column on the core `scans` table.

---

## 11. Phased rollout

**Prerequisite:** `concurrent-scans-design.md` Phases A–C must land before Phase 1. Module API contracts are concurrent-aware (take `scan_id`) regardless. UI Phase D of concurrent-scans can run in parallel with module system Phase 1.

**POC coverage gap.** The three community POC modules (`terminal-dashboard`, `scan-reporter`, `scope-wizard`) are all CLI-only. They exercise manifest, lifecycle, CLI extension, dependency-dedup paths — but **not** routers, DB models/migrations, UI slots, scan hooks, enrichers, or the agent/gate/advisor contracts. Declaring Module API v1.0 stable requires additional modules exercising DB + UI + enricher + agent contracts (engagements, when it ports, covers much of this).

1. **Phase 1 — Foundation.** Build `chainsmith.module_api`, loader, manifest+contract parsers, cached index, lazy import, failure isolation, `/api/v1/modules` endpoint. Core refactored so existing checks/agents/advisors/gates carry manifest+contract files in place (dogfooding). No external modules yet.
2. **Phase 2 — Engagements port.** Engagements becomes `modules/engagements/`, shipped as a **pro-tier module** (not in OSS distribution). Remove engagement references from core. Requires license-validator hook to exist at least minimally (placeholder accepting any non-empty key, harden later).
3. **Phase 3 — UI slot system.** Minimal slot model (nav, dashboard cards, sidebar). Extend as modules need.
4. **Phase 4 — Migration tooling.** Per-module migrations (depends on separate migration-tooling work).
5. **Phase 5 — Licensing.** License validator hook, offline grace, license-server reference implementation.
6. **Phase 6 — Second real module.** Ideally a *community* module meaningfully different from engagements (e.g., compliance-framework, SIEM-export). Only after two real modules exist is the Module API declared stable (v1.0).

---

## 12. Open questions

1. **Templating engine.** Is Jinja already in the dep tree (reports), or does the UI slot system add it?
2. ~~**`Scan.engagement_id` location.**~~ **Resolved:** join table owned by the module. Badges via Enricher extension point.
3. ~~**Check discovery: scan vs explicit register.**~~ **Resolved:** directory scan across both roots (`app/checks/` and `modules/*/checks/`), registration driven by `contract.yaml`.
4. **Entry points vs folder-only?** Should modules also be installable as pip packages via `setuptools` entry points (`pip install chainsmith-engagements-pro`), or is `modules/<name>/` the only supported shape?
5. ~~**Chat and advisor hooks.**~~ **Resolved:** no `core.chat.on_message` / `core.advisor.register_rule` extension points in v1. Design later against real requirements.
6. **Module config.** Per-component `config.yaml` is defined. Still open: a per-instance overlay for operator-level overrides (API keys, thresholds) — shared `.env` namespace, `~/.chainsmith/modules/<name>.yaml`, or admin UI?
7. ~~**Naming collisions.**~~ **Resolved:** UUID identity; human names are display-only; explicit `overrides: <uuid>` for replacement.
8. ~~**Config format.**~~ **Resolved:** YAML everywhere (manifest, contract, config).
9. ~~**Agent model/provider selection.**~~ **Resolved:** chosen at chainsmith startup (`chainsmith.sh`), injected at runtime. Agents do not declare model tier.
10. ~~**Promotion path.**~~ **Resolved:** proven community modules move from `modules/<name>/` to the appropriate `app/<type>/<name>/` location. Folder move, no rewrite — shape is identical in both roots.

---

## Summary

The module system is a contract between core and an ecosystem of drop-in, self-contained component directories. Every module — core or community, one check or a whole feature pack — has the same shape: `manifest.yaml` + per-component `contract.yaml` + code + tests. Core and `modules/` are two discovery roots into one registry, keyed by UUID, with explicit `overrides:` the only way a module replaces core behavior.

Engagements is both the motivating case and the reference multi-component module. Until it ports cleanly and a second community module lands, the Module API isn't validated.
