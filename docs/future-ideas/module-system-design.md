# Module System Design

**Status:** Draft / request-for-comment
**Purpose:** Define how Chainsmith gains optional capabilities — including OSS community modules and paid/private modules — via drop-in directories, without forking the core codebase.

---

## 1. Goals and non-goals

### Goals

- **Single codebase.** Core OSS is the only codebase. Paid/private modules are additions, never forks.
- **Drop-in directory.** A module is one folder. Delete the folder → the feature is gone. Add the folder → the feature is present on next start.
- **Full-stack contribution.** A module can add checks, API routes, DB tables, CLI commands, reports, and web-UI surfaces.
- **Core doesn't import modules.** Modules register with core. Core has no knowledge of any specific module's name.
- **Community and commercial tiers coexist.** A module declares a tier; paid modules can require license validation at load time. Some features (engagements being the first) are *intentionally* paid-only and will never ship in the OSS distribution.
- **Graceful degradation.** If a module fails to load, the core keeps running; only that module's features are disabled.

### Non-goals

- **Hot reload.** Modules load at startup; changes require a restart.
- **Sandboxing.** Modules run with full core privileges. Installing a module is a trust decision, same as installing any Python package.
- **Cross-module dependencies.** A module may assume core APIs, but not other modules. (If two modules need to talk, they talk through core.)
- **Runtime marketplace.** The registry/distribution story is out of scope for this doc; we define the *loading contract*, not the delivery mechanism.

---

## 2. Core insight

The split that matters is **"what does core know by name"** vs. **"what does core discover at runtime"**.

- Core knows, by name: `scope`, `scan`, `scan_history`, `observations`, `checks`, `chains`, `reports`, `scenarios`. These are the OSS product.
- Core discovers, at runtime: every module in `modules/`. It knows *the shape of a module* (the contract), not any specific module.

Today, `engagements` lives in the first category — it's hardcoded into routes, reports, the scan pipeline, chat, and the advisor. That's why removing it touched 70 files. The module system exists to make that kind of feature live in the second category instead.

---

## 3. Module anatomy

A module is a directory under `modules/<name>/` with a fixed layout:

```
modules/engagements/
├── manifest.toml           # declarative metadata (required)
├── module.py               # entry point — defines register() (required)
├── api_models.py           # Pydantic models (optional)
├── routes.py               # FastAPI routers (optional)
├── cli.py                  # Click command groups (optional)
├── db/
│   ├── models.py           # SQLAlchemy models (optional)
│   ├── repositories.py     # data access (optional)
│   └── migrations/         # schema migrations (optional, one file per version)
├── checks/                 # additional check implementations (optional)
├── reports/                # report templates/builders (optional)
├── static/                 # web UI assets — css/js/html fragments (optional)
├── templates/              # server-rendered fragments for UI slots (optional)
└── tests/                  # module-scoped tests (optional)
```

**Why a fixed layout:** discovery is mechanical, not configurable. Review and audit are easier when every module looks the same.

---

## 4. Manifest

`manifest.toml` is the only file core parses before deciding whether to load the module:

```toml
[module]
name = "engagements"
version = "0.1.0"
description = "Group related scans into engagements with trend analysis"
tier = "pro"                # community | pro | enterprise
chainsmith_min_version = "1.2.0"
chainsmith_max_version = "2.0.0"

[license]
# Optional; present only for non-community tiers.
# Core calls this validator at load time and skips the module if it returns False.
validator = "module.license:check"
offline_grace_days = 7

[dependencies]
# Additional Python deps the module requires. Core checks these at load time
# and surfaces a clear error if any are missing, rather than failing deep in
# an import.
python = ["httpx>=0.27", "croniter>=2.0"]

[contributes]
# Declarative list of extension points the module uses. Lets core validate
# the manifest matches the code and lets operators audit what a module does
# without reading its source.
routers = ["engagements"]
cli_groups = ["engagements"]
db_models = ["Engagement"]
checks = []
ui_slots = ["nav.primary", "scan.sidebar", "dashboard.cards"]
```

The manifest is the **contract surface**. Everything else is the module's private business.

---

## 5. Extension points

These are the hooks core publishes. A module's `module.py` exports `register(core)` where `core` exposes typed APIs for each extension point it uses.

```python
# modules/engagements/module.py
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
| **Routes** | `core.routes.mount(router, prefix)` | Standard FastAPI router. Core namespace-checks prefixes. |
| **CLI** | `core.cli.add_group(group)` / `core.cli.extend_group(name, subcommand)` | Click groups; core guarantees no name collision with built-in groups. Modules can both register new top-level groups *and* extend existing core groups (e.g., `report`, `scope`) with new subcommands — this is required for `scan-reporter` and `scope-wizard` per phases 2/3. |
| **DB models** | `core.db.register_models(base)` | Module owns its tables. Table names must be prefixed (e.g. `mod_engagements_*`) to avoid collisions. |
| **DB migrations** | `core.db.register_migrations(pkg, path)` | Each module has its own migration lineage, run by core's migration runner. |
| **Checks** | `core.checks.register(check_cls)` | Same `BaseCheck` contract as core checks. |
| **Reports** | `core.reports.register_section(name, render)` | Named section renderers; report templates opt into them via `{% section "engagement" %}`. |
| **UI slots** | `core.ui.contribute(slot, ...)` | See §7 for the slot model. |
| **Scan hooks** | `core.scan.on_create/on_complete(...)` | Lifecycle callbacks. Fired in registration order; exceptions are isolated per module. |

**Contract philosophy:** extension points are **additive, not subtractive**. A module can add a nav item, but cannot remove one. A module can add a column to a report, but cannot rewrite the core report. This keeps modules composable — two modules adding nav items works; two modules each "taking over" the nav doesn't.

---

## 6. Lifecycle

```
startup
  ├─ scan modules/ for subdirectories
  ├─ for each module:
  │    ├─ read manifest.toml
  │    ├─ check chainsmith_min/max_version
  │    ├─ check python dependencies resolvable
  │    ├─ for non-community tier: call license validator
  │    ├─ import module.py
  │    ├─ instantiate Module class
  │    └─ call module.register(core)  ← within try/except; failure disables the module, logs clearly, but doesn't abort startup
  ├─ run DB migrations (core + each successfully loaded module, in dependency order)
  ├─ mount routers, assemble CLI, render UI manifest
  └─ start server

shutdown
  └─ for each loaded module (reverse order): call module.teardown(core) if defined
```

**Load order is deterministic** (alphabetical by module name) so that failures are reproducible.

**Failure isolation:** a module that raises during `register()` is disabled for the process. Core logs the failure, marks the module `status=failed` in the operator-visible `/api/v1/modules` endpoint, and continues. This is the difference between "my engagements module is broken" and "my Chainsmith instance won't boot."

---

## 7. Hard problems

### 7.1 Frontend integration (hardest)

The current frontend is static HTML + vanilla JS (no build step). Modules need to contribute UI without forking `static/index.html`.

**Proposed approach: server-side slot rendering.**

Core's HTML templates define named slots:

```html
<!-- static/index.html -->
<nav>
  <a href="/">Scans</a>
  <a href="/scan-history">History</a>
  {{ ui_slot("nav.primary") }}
</nav>
```

Core serves templates through a tiny template step (Jinja is already likely in deps for reports — confirm). `ui_slot(name)` expands to the concatenated contributions from all loaded modules, each a small HTML fragment the module ships in `templates/`.

For richer UI (a full Engagements tab with its own routes), a module registers a page:

```python
core.ui.register_page("/engagements", template="templates/engagements.html")
```

and ships its own JS/CSS under `modules/<name>/static/`, which core mounts at `/modules/<name>/static/`.

**What this doesn't solve:** deep cross-cutting UI (e.g. "every scan-history row should show an engagement badge"). For these, the slot model needs per-row context — feasible but adds template complexity. Start with coarse slots (nav, dashboard cards, sidebar panels) and extend only when needed.

**Alternative to consider:** introduce a build step (Vite/esbuild) with a proper plugin mechanism. Bigger change, but unlocks real component composition. Probably the right answer for v2 of the module system, not v1.

### 7.2 Database migrations

Each module owns its tables and its migration lineage. Core runs migrations in two passes:

1. Core migrations (existing lineage).
2. Each loaded module's migrations, in load order.

**Uninstall semantics:** deleting a module's folder leaves its tables behind. This is intentional — dropping tables on removal is a footgun. Provide `chainsmith modules uninstall <name> --drop-data` as an explicit, scary command.

**Table name collisions:** enforce a `mod_<module_name>_` prefix in the migration runner. Reject migrations that create tables outside the module's namespace.

Depends on the `schema-migration-tooling.md` work already in `docs/future-ideas/` — the module system assumes that lands first.

### 7.3 Licensing for paid modules

Paid module loads require a valid license. Mechanism:

- License key in env var or `~/.chainsmith/license` file.
- Module's `license.validator` function gets the key + module version, returns `bool`.
- Short-lived signed tokens (e.g. JWT with 30-day expiry), refreshed by contacting a license server.
- Offline grace period (configurable per module) so a temporarily-offline instance keeps working.

**Intentionally not solving:** DRM/obfuscation. If someone wants to run a paid module without paying, they can. The value of the paid tier is support, updates, and keeping the license server reachable — not anti-tamper.

### 7.4 Coupling to core changes

Modules pin a core version range in the manifest. Core publishes a stable **Module API** (`chainsmith.module_api`) with a semver guarantee: breaking changes bump the major version; modules pin a range and are refused if they don't match.

Everything else — internal repositories, route signatures, DB schema of core tables — is **not** a stable API. Modules that reach into internals risk breaking on any core release.

### 7.5 Testing

- Core ships a `chainsmith.module_testing` helper that spins up a core instance with only the module-under-test loaded.
- Each module has `modules/<name>/tests/` run by a dedicated pytest command: `pytest modules/<name>/tests`.
- CI runs: core tests, then each module's tests, then an integration job with all community modules loaded.

---

## 8. Engagements as the reference implementation

Engagements is the perfect first module because it's already the feature that motivated this design, and because **engagements is paid-only** — it's one of the primary value props of the pro tier, not an OSS feature. Porting it both validates the module API and validates the tier/licensing model in one shot. Porting it exercises every extension point:

- Routes (`/api/v1/engagements/*`)
- CLI (`chainsmith engagements ...`)
- DB models + migrations (`engagements` table, `mod_engagements_*` after rename)
- Report sections (compliance/exec/trend all render an engagement block)
- UI slots (nav item, scan-sidebar panel showing linked engagement)
- Scan hooks (on scan create, optionally link to engagement by param)

**One friction point to resolve during port:** today `Scan.engagement_id` lives on the core `scans` table. In the module model, that column belongs to the engagements module — the cleanest answer is a join table (`mod_engagements_scan_links`) owned by the module, not a column on the core `scans` table. Worth a design decision before port starts; it affects the frontend story too (badges on scan rows).

---

## 9. Phased rollout

1. **Phase 1 — Foundation.** Build the module API (`chainsmith.module_api`), loader, manifest parser, failure-isolation, `/api/v1/modules` introspection endpoint. No real module yet. Core refactored so existing route/CLI registration goes through the same APIs modules will use (dogfooding).
2. **Phase 2 — Engagements port.** Engagements becomes `modules/engagements/`, shipped as a **pro-tier module** (not part of the OSS distribution). Remove all engagement references from core. Because engagements is paid-only, phase 2 also requires the license-validator hook to exist in at least a minimal form — either pull licensing forward from phase 5 or ship a placeholder validator that accepts any non-empty key, then harden later.
3. **Phase 3 — UI slot system.** Minimal slot model (nav, dashboard cards, sidebar). Extend as real modules need more.
4. **Phase 4 — Migration tooling.** Integrated per-module migrations (depends on the separate migration-tooling work).
5. **Phase 5 — Licensing.** License validator hook, offline grace, license-server reference implementation.
6. **Phase 6 — Second real module.** Pick something meaningfully different from engagements to stress the design (e.g. a compliance-framework module, or a SIEM-export module). Ideally this one is a *community* module so the design is proven across both tiers. Only after two real modules exist should the Module API be declared stable (v1.0).

---

## 10. Open questions

1. **Jinja or lighter?** Is Jinja already in the dependency tree (reports), or would the UI slot system add it? Template choice affects frontend design.
2. **Where does `Scan.engagement_id` go?** Column on core table vs join table in module. Cleanest is join table, but existing scan-list queries would need a hook point to include module-provided badges.
3. **Check discovery today uses directory scanning under `app/checks/`.** Do module-contributed checks go through the same scanner, or register explicitly? Directory scanning is more ergonomic; explicit registration is more auditable.
4. **Entry points vs folder-only?** Should modules also be installable as pip packages via `setuptools` entry points, or is `modules/<name>/` the only supported shape? Entry points help with `pip install chainsmith-engagements-pro` ergonomics; folder-only is simpler.
5. **Chat and advisor hooks.** Today both have hardcoded engagement references. The design above covers scan-lifecycle hooks; do we need analogous `core.chat.on_message` and `core.advisor.register_rule` hooks, or can engagements live without them in v1?
6. **Module config.** Modules often need per-instance config (API keys, thresholds). Shared `.env` namespace? Per-module config file? Admin UI?

---

## Summary

The module system is a contract between core and an ecosystem of drop-in directories. Core publishes extension points; modules register against them. The design keeps OSS and commercial tiers in one codebase by making the *product surface* (what ships) depend on *what's in `modules/`*, not on which git branch was built.

Engagements is both the motivating case and the reference implementation. Until it's successfully ported, the Module API isn't validated.
