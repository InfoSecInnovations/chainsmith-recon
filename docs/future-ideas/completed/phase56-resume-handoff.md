> **Archived 2026-10-11** from `.phase56/RESUME-HERE.md`. Phase 56 is complete. The baselines it mentions
> are still in `.phase56/`.

# Phase 56 — Resume Handoff (🎉 PHASE 56 COMPLETE — 56.17 WebUI/param-editing DONE ✅; all phase-17 waves + all component-type ports landed)

## 56.17 — Phase-17 Wave 6 (FINAL): WebUI check-detail modals + per-check param editing DONE ✅ (this session)

**The last wave.** Lands the §5.1 **layer-6b runtime scalpel** end to end + the save-as-default
(layer 3) write path + surfaces presets (56.14) and disabled checks (56.15) in the launcher UI.
**Phase 56 is now COMPLETE.**

**Operator decisions (AskUserQuestion ×3):**
1. Overridable per-check fields = **5 tunables** (the 4 knobs + `on_critical`).
2. Persistence = **BOTH** ephemeral per-scan (6b) **and** "save as default" (writes config.yaml, layer 3).
3. Surfacing = **BOTH** the preset selector (56.14) and the include_disabled toggle (56.15).

**Backend (fully tested):**
- `app/api_models.py`: `CheckOverride` (5 optional fields, validated — `timeout_seconds`/`requests_per_second`
  `gt:0`, `retry_count`/`delay_between_targets` `ge:0`, `on_critical` enum incl. `inherit`; `extra=forbid`);
  `ScanStartInput.check_overrides: dict[name → CheckOverride]`.
- `app/scan_overrides.py` (NEW): `apply_check_overrides(checks, overrides)` — assigns set fields onto resolved
  instances; `inherit` ignored at scan time; unknown/deselected names skipped. Called in `run_scan` **after**
  `apply_runtime` (6b > 6a). `run_scan(..., check_overrides=None)`; route threads `body.check_overrides`.
- `app/routes/checks.py`: `PUT /api/v1/checks/{name}/config` (save-as-default) — `on_critical` top-level,
  knobs under `defaults:`, other keys (`enabled`/`reason`/`parameters`) preserved, merged doc
  `ComponentConfig`-validated BEFORE write; 404 unknown / 400 empty body. **PyYAML → config.yaml header
  comments NOT preserved** (surfaced in response `note`). `_CHECKS_ROOT` + `find_component_dir`.
- `app/component_loader.py`: `find_component_dir(root, name, type)` — import-free folder locator by contract name.
- `app/engine/scanner.py`: `AVAILABLE_CHECKS` build refactored into `rebuild_available_checks()` (called at
  import + by the save endpoint to refresh the display cache live; `get_real_checks` is uncached so scans
  pick up a saved default on the next run with no restart).

**Frontend (vanilla JS, FastAPI StaticFiles, no build step):**
- `static/js/api.js`: `startScan(body)` now POSTs an optional JSON body; `getChecks(includeDisabled)`;
  new `getScanPresets()` + `saveCheckConfig(name, override)`. Shared `getCheckModalContent` gained a
  **Configuration** section (`getCheckConfigSection`): each knob's resolved value + provenance `[layer]`,
  **read-only** unless a launcher installs `window.CheckOverrideEditor` (so scan.html stays informational —
  and during a live scan its instances reflect the applied 6b override, so it shows effective config).
- `static/index.html` (the launcher): full check objects cached in `CHECK_BY_NAME`; a dedicated
  `check-modal-overlay` (the existing `modal-overlay` there is the scan-window warning, NOT reusable);
  `window.CheckOverrideEditor` (pending-overrides map + `applyForScan`/`saveDefault`/`clearPending`); a
  **preset `<select>`** (from `getScanPresets`) + **"Show disabled checks"** toggle (re-fetches with
  `include_disabled`, preserves selection across re-render); per-check **ⓘ** opens the modal; an override
  dot marks rows with a pending 6b override; `proceedWithScan` builds `{preset, check_overrides}` for
  `startScan`.
- CSS: `.cfg-*` (modal config) → common.css; `.suites-controls`/`.check-info-btn`/`.override-dot`/
  `.check-config-disabled` → index.css.

**Tests:** `tests/scanning/test_scan_overrides.py` (14 — apply, set-fields-only, missing-name skip, inherit
ignored, empty no-op, plain-dict, ScanStartInput parse, CheckOverride validation) +
`tests/checks/test_check_config_save.py` (7 — find_component_dir, write knobs/on_critical, merge into
existing defaults, create-when-absent, 404, 400, post-save verify_contracts clean). Frontend JS
syntax-checked (`node --check` on api.js + the index.html inline block).

**GATES ALL GREEN:** pytest **2248 passed / 5 skipped / 0 failed** (170s) = 56.16's 2227 + 21 new; ruff
check + format clean (646 files); verify-contracts OK (checks/agents/advisors/gates); diff-registry CLEAN
(123 — **no check logic changed**). **Committable (operator's call — git is operator-only).** Plan §7 56.17
row → ✅ DONE; **§7 Phase 56 COMPLETE**. Full write-up in auto-memory `phase56_17_webui_param_editing`.

**FRONTEND NEEDS A LIVE SMOKE (operator):** the JS is syntax-valid but not browser-exercised here. Suggest:
launch the server, open the launcher, click a check ⓘ → edit a knob → "Use for this scan" (dot appears) →
start scan and confirm the scan runs with the override (and "Save as default" writes config.yaml). I can
drive this via the `run`/`verify` skill if you want.

**Deferred (post-Phase-56 backlog):** swarm `on_critical` parity; `parameters.wordlist_file` config override
(phase-17 Wave 1/3); extend strict env to a future `CHAINSMITH__<AGENT>__<PARAM>` scheme; `verifier` agent;
advisor YAML/env back-compat shim; comment-preserving config.yaml writes (ruamel) if save-as-default churn
on comments becomes a pain; re-enable-a-disabled-check from the WebUI (the toggle is display-only by design).

---


## 56.16 — Phase-17 Wave 5: startup config validation + env/override surfacing DONE ✅ (this session)

**Two halves.** (1) config/suite/env **validation folded into the shared `verify_contracts()` gate**;
(2) **end-to-end surfacing** of the resolved config with **full per-value layer attribution**.
**ONE phase left after this (56.17 = WebUI).**

**Operator decisions (AskUserQuestion ×3):**
1. **Validation:** fold `config.yaml`/`suite.yaml` schema validation into `verify_contracts` (one gate:
   loader + CI + `dev verify-contracts`), AND **strict env** — an unknown/uncoercible `CHAINSMITH__`
   override is a hard startup error (not the old silent drop/warn).
2. **Surfacing channels:** extend `/api/v1/checks` entries **+** startup log summary **+** `dev` CLI
   command (NOT a new endpoint).
3. **Provenance:** **full per-value layer attribution** (ConfigResolver records the winning layer per knob).

**What landed:**
- `app/components/config_models.py`: `ResolvedConfig.provenance: dict[str,str]` (defaulted — only
  config_resolver constructs ResolvedConfig, so safe).
- `app/components/config_resolver.py`: `resolve()` now tracks provenance through each layer
  (`class_default`/`suite`/`config`/`env`; on_critical → `config`/`suite`/`default` via new
  `_on_critical_source`). `_apply_defaults` takes `(provenance, label)`. NEW module fns:
  `detect_env_problems(names, env)` → `(key, code, msg)` for `env-unknown`/`env-uncoercible` over the
  `CHAINSMITH__*` namespace (the ONE place env is enumerated — resolution still constructs-by-key);
  `active_env_overrides(names, env)` → sorted `(check, param, value)` for valid live overrides;
  `ENV_OVERRIDE_PREFIX = "CHAINSMITH__"` (double-underscore — excludes legacy single-underscore vars).
- `app/component_loader.py`: `verify_contracts(root, type, env=None)` (env defaults os.environ).
  NEW Pass 4 `_verify_tunable_config` (config.yaml + suite.yaml schemas → accumulated violations);
  NEW Pass 5 env validation **gated `component_type == "check"`** (checks are the lone knob consumer —
  agents/advisors/gates have own registries, no ConfigResolver). `discover_components` logs a one-line
  active-env-override summary (check root).
- `app/checks/base.py`: `from_config` stamps `inst.config_provenance`; class attr default `= {}`.
- `app/engine/scanner.py` `get_check_info`: NEW `config` block (4 knobs + on_critical + provenance).
- `app/routes/checks.py` `_disabled_check_entry`: `config` block for shape parity (null knobs — disabled
  checks are never imported; on_critical from import-free metadata).
- `app/cli.py`: NEW `dev show-config [--check NAME] [--root]` — offline; prints active env overrides +
  each check's resolved knobs with `[layer]` tags.

**WHY check-root-only env validation:** confirmed only `discover_components` (checks) uses
`ConfigResolver`/`_KNOBS` env. agents/advisors/gates parse config.yaml via the SAME `ComponentConfig`
model (so the new config-schema pass covers them too — they use only `enabled`+`parameters`, both valid),
but have NO env-knob layer. suite.yaml validation no-ops on their flat (non-suited) roots.

**Tests:** NEW `tests/core/test_config_provenance.py` (12 — layer attribution per knob, on_critical
source, env helpers incl. legacy single-underscore exclusion) + `tests/checks/test_config_validation.py`
(12 — config/suite schema violations on synthetic trees, strict-env unknown/uncoercible, non-check root
skips env, real tree clean, /api/v1/checks `config` block shape). Synthetic checks write a stub
`check.py` so the entry-constructible pass passes.

**GATES ALL GREEN:** pytest **2227 passed / 5 skipped / 0 failed** (142s) = 56.15's 2203 + 24 new; ruff
check + format clean (643 files); verify-contracts OK (checks/agents/advisors/gates); diff-registry CLEAN
(123 — **no check logic changed**, only the resolver/loader/route/CLI). **Committable (operator's call —
git is operator-only).** Plan §7 56.16 row → ✅ DONE. Full write-up in auto-memory `phase56_16_config_validation`.

**NEXT — 56.17 (Wave 6, FINAL):** WebUI check-detail modals + per-check parameter editing — consumes
this phase's `/api/v1/checks` `config` block + provenance + the 56.15 `include_disabled` surface + 56.14
presets (the layer-6b runtime scalpel). **1 phase to the finish.** Deferred: swarm on_critical parity;
`parameters.wordlist_file` config override; extending strict env to a future `CHAINSMITH__<AGENT>__<PARAM>`
scheme; `verifier` agent; advisor YAML/env back-compat shim.

---


## 56.15 — Phase-17 Wave 4: per-check on_critical + enabled end-to-end DONE ✅ (this session)

**Two halves.** (1) `on_critical` is now enforced **per-check** by the CheckLauncher; (2) a
**disabled-visible** introspection surface for `enabled`. 2 phases left after this (56.16, 56.17).

**KEY discovery:** the launcher ALREADY enforced on_critical, but resolved it at the **suite**
level via the separate `app/preferences.py` (`resolve_on_critical(prefs, suite)`), and NEVER read
the per-check `check.on_critical` that Phase-56's ConfigResolver sets from config.yaml. 56.15 wires
the per-check value in.

**Operator decisions (AskUserQuestion ×4):**
1. **Per-check config wins** — launcher reads `check.on_critical`; falls back to the legacy
   preferences suite-level value ONLY when a check is at default `annotate` (back-compat:
   existing `checks.on_critical_overrides` keep working).
2. **skip_downstream = true transitive DAG dependents** of the critical-emitting check (built from
   `produces`/`conditions`) — NOT the old coarse cross-suite blanket-skip. **The same-suite
   exemption is GONE** (dependency-based, not suite-based).
3. **Launcher only** — the swarm path does NOT enforce on_critical (documented gap in
   `app/swarm/runner.py` docstring; follow-up = coordinator post-completion hook).
4. **Add disabled-visible introspection** now (backend half for 56.17's WebUI toggle).

**What landed:**
- `app/check_launcher.py`: new `_resolve_check_on_critical(check_name, suite)` (per-check wins,
  prefs fallback at default); `_record_critical` acts on it (`stop`→`scan_stopped`;
  `skip_downstream`→add transitive dependents to `self.skip_downstream_targets: dict[name→source]`);
  `_should_skip_for_critical` reads that dict; new `_build_dependents_map` (output→consumers from
  conditions, built once in __init__) + `_transitive_dependents`. Old suite-blanket logic removed.
  `_resolve_on_critical(suite)` (prefs) kept as the fallback. Module docstring + base.py comment updated.
- `app/components/config_models.py`: `ComponentConfig.reason: str = ""` (optional note; D8 → consumed).
- `app/component_loader.py`: `ComponentMeta` + `discover_component_metadata(root, type)` — lists ALL
  components incl. disabled, **import-free** (contract.yaml+config.yaml+suite.yaml; effective
  enabled = component AND suite; on_critical resolved via `ConfigResolver._resolve_on_critical`).
- `app/check_resolver.py`: `get_all_check_metadata()` over the checks tree.
- `app/routes/checks.py`: `GET /api/v1/checks?include_disabled=true` appends disabled entries
  (`enabled:false` + `reason`); copies live dicts (no mutation of shared `AVAILABLE_CHECKS`).

**Tests:** `tests/core/test_on_critical.py` — the existing `FakeCheck` has NO `on_critical` attr →
it falls through to the prefs path, so all legacy preference/annotate/stop tests PASS unchanged;
only `test_same_suite_not_skipped` was reworked → `test_non_dependent_not_skipped` (same-suite
exemption gone — only DAG dependents skip). +`TestPerCheckOnCritical` (4) +`TestDependentsGraph` (1).
NEW `tests/checks/test_component_metadata.py` (9) — synthetic enabled/disabled/suite-disabled/
inherit/malformed-skipped + real-tree (enabled set == loader, disabled non-empty) + the
`include_disabled` route.

**GATES ALL GREEN:** pytest **2203 passed / 5 skipped / 0 failed** (169s) = 56.14's 2189 + 14 new;
ruff check + format clean (641 files); verify-contracts OK; diff-registry CLEAN (123 — **no check
logic changed**, only the launcher engine + loader/route). **Committable (operator's call — git is
operator-only).** Plan §7 56.15 row → ✅ DONE. Full write-up in auto-memory
`phase56_15_on_critical_enabled`.

**NEXT — 56.16 (Wave 5):** startup config validation + end-to-end env/override surfacing (the env
layer `CHAINSMITH__<C>__<P>` construct-by-key was wired in 56.1; this wave is validation +
surfacing). Then 56.17 (Wave 6: WebUI check-detail modals + per-check param editing — consumes
this phase's `include_disabled` surface + the 56.14 presets). **2 phases to the finish.** Deferred:
swarm on_critical parity; `parameters.wordlist_file` config override; `verifier` agent; advisor
YAML/env back-compat shim.

---

## 56.14 — Phase-17 Wave 3: scan presets DONE ✅ (prior session)

**A preset is a named, scan-time bundle** layered on the per-component config baseline
(§5.1 **layer 6a**), **orthogonal** to the preference/profile system (`app/preferences.py`
tunes *behavior* — rate/LLM/network; a preset says *what runs* + *which per-check knobs*;
both can be active at once). Operator decisions (AskUserQuestion ×3):
1. Presets control **selection + params** (not selection-only / params-only).
2. Definitions are **externalized YAML** (`app/data/presets.yaml`), loaded via the 56.13
   `app.lib.datafiles.load_data` fallback-first loader; an in-code `_FALLBACK_PRESETS` is
   byte-equivalent so a missing/unparseable file degrades to exactly the same 4 presets.
3. A **new orthogonal concept**, NOT built on the preferences subsystem.

**New `app/scan_presets.py`:** Pydantic `Preset` = a *selection* half (`suites` / `checks`
name-allowlist / `intrusive:false` → drop active-probing checks, the "passive" lens /
`port_profile`) + a *defaults* half (the 4 standard knobs `timeout_seconds`/
`requests_per_second`/`retry_count`/`delay_between_targets` + `on_critical`). Validators
reject unknown suite / port_profile / on_critical (`inherit` excluded — meaningless at scan
time). Public fns: `get_preset` / `list_presets` / `preset_names`;
`resolve_selection(preset, *, suites, checks, port_profile)` — explicit CLI/API selection
**beats** the preset per-field (§5.1 **6b > 6a**: `--preset quick --suite ai` runs AI but
keeps quick's port_profile); `apply_runtime(preset, checks)` — intrusive filter + knob/
on_critical overrides assigned onto the resolved instances (same attrs `BaseCheck.from_config`
sets). No-op when preset is None.

**Wiring (one insertion point + thin pass-through):**
- `app/engine/scanner.py` `run_scan(..., preset=None)`: `get_preset(preset)` →
  `resolve_selection(...)` BEFORE `resolve_checks` (selection) → `apply_runtime(...)` AFTER
  (filter + knobs). `eff_port_profile` replaces the old `port_profile` in the context seed.
  Unknown preset name → logged warning, ignored (route already 400s it).
- `app/api_models.py` `ScanStartInput.preset: str | None`.
- `app/routes/scan.py`: validates the name up front (**400** "Unknown preset … Available: …"),
  passes `preset=body.preset or None` to `run_scan`; new **`GET /api/v1/scan/presets`** →
  `{"presets":[{name,description}…]}`.
- `app/cli_client.py` `start_scan(preset=…)` + `get_scan_presets()`.
- `app/cli.py` `scan --preset` flag: validated against the **local** presets file (no server
  needed, mirrors `--profile`); echoes `Preset: <name>` in the header.
- `app/dev/rename.py` `_NAME_REF_GLOBS` += `app/data/presets.yaml` (a preset `checks:` list
  may name a check, so a future rename-suite sweep must touch it).

**The 4 shipped presets** (`app/data/presets.yaml`): quick (network+web, web ports, retry 1),
thorough (all suites, lab ports, retry 2), passive (`intrusive:false`, rps 5.0),
ai-focused (ai/agent/rag/cag/mcp).

**GATES ALL GREEN:** pytest **2189 passed / 5 skipped / 0 failed** (139s) = 56.13's 2165 + 24
new (`tests/scanning/test_scan_presets.py` — loader fallback, Preset validation, selection
precedence, intrusive filter, knob overrides, shipped==fallback); ruff check + format clean
(640 files); verify-contracts OK; diff-registry CLEAN (123, identical — checks unaffected).
**Committable (operator's call — git is operator-only). No check logic changed** (presets only
select + layer scan-time overrides). Plan doc §7 56.14 row → ✅ DONE. Full write-up in
auto-memory `phase56_14_presets`.

**NEXT — 56.15 (Wave 4):** per-component `enabled` flag wired end-to-end + per-check
`on_critical` override (note: `BaseCheck.on_critical`/`enabled` exist + presets already set
`on_critical` at scan time; 56.15 is the *full* enable/on_critical pipeline, see base.py
comment "wired end-to-end in 56.15"). Then 56.16 (Wave 5: startup config validation + env
surfacing), 56.17 (Wave 6: WebUI check-detail modals + per-check param editing — the layer-6b
runtime scalpel). **3 phases left to the finish.** Deferred: `parameters.wordlist_file` config
override (Wave 1/3); `verifier` agent (sketch-only); advisor YAML/env back-compat shim.

---

## 56.13 — Phase-17 Wave 2: externalize payload data DONE ✅ (prior session)

**Moved hardcoded enumeration/discovery DATA out of 7 check implementations into data files.** This is a
phase-17 wave (data externalization), NOT a component-type port. Operator decisions (AskUserQuestion ×3):
1. **Scope = the phase17 Wave-2 named set only** (~7 checks): the DNS wordlist + 3 AI endpoint path lists +
   the 3 still-inline injection payload sets. Regex/signature *detection* patterns (~60) and framework
   fingerprints (~80) were EXCLUDED (they're logic, not payload data); the wider ~15 web/agent/rag/cag/mcp
   discovery path lists were left inline (possible follow-up). Chose the bounded set over "all path lists" / "2-check pilot".
2. **Location = `app/data/{wordlists,endpoints,payloads}/`** (alongside the existing `injection_payloads.json`
   + `proof_templates/`), NOT top-level `data/` (which holds the runtime `chainsmith.db` / mounted DATA_DIR).
3. **Data-file + hardcoded fallback only** — NO config.yaml override key (`parameters.wordlist_file`) yet;
   that's the Wave 1 (per-check config) / Wave 3 (presets) dependency.

**Mechanism — `app/lib/datafiles.py`** (new), two **fallback-first** loaders:
- `load_wordlist(relpath, fallback)` → text, one entry per line, skips blank + `#` lines; returns `fallback`
  unchanged on missing/empty.
- `load_data(relpath, fallback)` → YAML (list or dict); returns `fallback` on missing/empty/unparseable.
  YAML has no tuples, but a 2-item YAML list unpacks identically to the old tuple literals
  (`for category, payload in ...`), so no check iteration logic changed.
- Paths are relative to `app/data/` (`DATA_ROOT = app/data`). Each loader logs a WARNING on fallback.

**The 7 checks (each keeps its prior inline list as `_FALLBACK_*`/`_INLINE_*`, so missing file == prior behavior):**
- `network_dns_enumeration` `DEFAULT_WORDLIST` (33) → `wordlists/subdomains.txt`. **`DEFAULT_WORDLIST` name kept**
  (test imports it + asserts `check.wordlist == DEFAULT_WORDLIST`); now `= load_wordlist(..., _FALLBACK_WORDLIST)`.
- `ai_llm_endpoint_discovery.CHAT_PATHS` (19) / `ai_embedding_endpoint_discovery.EMBEDDING_PATHS` (13) /
  `ai_model_info_check.MODEL_PATHS` (17) → `endpoints/{chat,embedding,model_info}_paths.yaml`. Inline kept as
  class-attr `_FALLBACK_*` directly above each `X = load_data(...)` (class-body name in scope).
- `ai_input_format_injection.INJECTION_PAYLOADS` (6 `[category,msg]`) → `payloads/input_format_injection.yaml`.
  `PIRATE_INDICATORS` left inline (detection indicators, not payloads).
- `mcp_template_injection.INJECTION_PAYLOADS` (dict→list of `[payload,desc]`) → `payloads/mcp_template_injection.yaml`.
- `agent_goal_injection` `FALLBACK_PAYLOADS` (list[dict]) + `FRAMEWORK_PAYLOADS` (dict) → ONE file
  `payloads/agent_goal_injection.yaml` (keys `fallback`+`framework`); `_GOAL_INJECTION_DATA = load_data(...)`
  then `FALLBACK_PAYLOADS/FRAMEWORK_PAYLOADS = _GOAL_INJECTION_DATA[...]`. `FALLBACK_PAYLOADS` name kept
  (imported by tests + agent_discovery test). `HIJACK_INDICATORS` left inline.

**Byte-identical-ness PROVEN:** payload YAML files were *generated* from the live Python constants (one-shot
`_gen_data.py`, deleted) with round-trip assertion; then a one-shot `_verify_data.py` (deleted) asserted all 8
loaded public constants `==` their inline fallbacks (tuple/list-normalized). diff-registry CLEAN confirms the
registry is unaffected (these aren't registry-bearing). **NO external module imports any of the 8 constants**
(only check.py self-refs + tests); no test asserts tuple-equality on `INJECTION_PAYLOADS` (only `len()`).

**Packaging:** Hatch wheel target `packages = ["app"]` ships all of `app/` incl. `app/data/**` (the existing
`injection_payloads.json`/`proof_templates/*.yaml` already prove non-`.py` data ships) — **no MANIFEST/packaging
change needed**.

**Tests:** +`tests/llm/test_datafiles.py` (10 tests — real shipped files + synthetic missing/empty/unparseable/
blank-skip/pairs-unpack via monkeypatched `DATA_ROOT`). Check tests unchanged (behavior identical).

**GATES ALL GREEN:** ruff check + format clean (637 files); verify-contracts OK; diff-registry CLEAN (123);
pytest **2165 passed / 5 skipped / 0 failed** (165s) = 56.12's 2155 + 10 new loader tests. **Committable
(operator's call — git is operator-only). FAKOBANKO LIVE SMOKE is operator-pending** but expected CLEAN (data
byte-identical to the old inline lists; DNS enumeration/endpoint discovery unchanged). Full write-up in
auto-memory `phase56_13_payload_data`.

**NEXT — 56.14 (Phase-17 Wave 3):** check presets (quick, thorough, passive, ai-focused). Deferred: the wider
~15 discovery path lists (web/agent/rag/cag/mcp) + the `parameters.wordlist_file` config override (Wave 1/3);
`verifier` agent (sketch-only); advisor YAML/env back-compat shim.

---


## 56.12 — Gates component type DONE ✅ (prior session)

**Guardian ported to folder shape.** Operator decision (AskUserQuestion ×2 this session):
1. **ONE `guardian` gate, NOT three.** Guardian is *the* single chokepoint ([[project_guardian_gating]]) —
   splitting its three behaviors (scope / scan_window / technique) into separate gate folders would fragment
   the allow/block boundary. So it stays one component; the class logic is **byte-identical**, only construction
   now resolves identity + `config.yaml` via the registry.
2. **Update call sites + delete the flat file** (not a re-export shim) — matches the 56.11 advisor precedent.

**Core framing:** gates are DETERMINISTIC allow/block authorities — they *decide* (return `(allowed, reason)`),
unlike advisors which *recommend* and agents which *think* (LLM). Like advisors they are **caller-constructed**
(the scan route/scanner/launcher build a `Guardian` per scan via `from_scope(...)` with scope data they hold),
so gates got the **discovery + config + contract-metadata** half of folder-shape and NONE of the agent DI
machinery. Four component shapes now: check (no-arg, loader-built) / advisor (per-call, caller-built) / gate
(per-call, caller-built) / agent (LLM, factory-injected).

**Foundation built:**
- **`GateContract`** in `app/components/contracts.py` (thin like AdvisorContract: id/name/type:"gate"/description/
  entry + `enforces` metadata list + outputs:`{decision:[GateDecision]}`/side_effects/references/reason — NO
  suite/depends_on/produces, NO role/triggers/tools/prompts); registered in `CONTRACT_MODELS` (now the full
  4-type discriminated union). `contract_model_for` KeyError comment de-staled (no type is "premature" now).
- **`app/gates/base.py` `BaseGate(BaseComponent)`** — marker only (component_type+enabled, NO from_spec/DI).
- **`app/gates/registry.py`** — `GateSpec`/`GateRegistry`/`discover_gate_specs`/`get_gate_registry`. A
  **config/discovery accessor, NOT a factory** (`.config`/`.get`/`.entry_cls`/`.param`/`.names`, NO `.create()`).
  **Does NOT skip disabled gates** (mirrors advisors — config stays introspectable).
- **`component_loader._CALLER_CONSTRUCTED={"advisor","gate"}`** — exempts gates from the no-arg rule (still
  entry-exists/class-present). NO `_INJECTED_REQUIRED["gate"]`.
- pytest testpaths += `app/gates`; `test_contract_integrity` += `test_gate_contracts_have_no_violations`.

**The 1 folder** (`app/gates/guardian/` = `gate.py`+`contract.yaml`+`config.yaml`+`__init__.py`+co-located `tests/`):
- contract uuid `676c7628-…`, enabled:true, `enforces:[scope, scan_window, technique]`, side_effects:[filesystem].
- `Guardian(BaseGate)` — class body unchanged (check_url/url_scope_validator/check_scan_window/check_technique/
  from_scope/approve_url/deny_url/create_violation_event all identical).
- **config.yaml is `enabled` + informational knobs only** — Guardian had **NO `ChainsmithConfig` block and no
  env vars**, so (unlike 56.10c agents / 56.11 advisors) **nothing was migrated out and there is no back-compat
  concern**. block_exclusions/log_violations are documented in config.yaml but the live values still come from
  request-time `ProofOfScopeSettings`; flipping config.yaml `enabled:false` is NOT a live kill switch today
  (the scan path always constructs the chokepoint) — reserved for a future opt-out.

**Flat `app/guardian.py` DELETED.** The 5 `from app.guardian import Guardian` sites repointed to
`from app.gates.guardian import Guardian`: `engine/scanner.py`, `routes/scan.py` (window gate + session guardian),
`swarm/agent.py` (inline, local per-task guardian), `check_launcher.py` (TYPE_CHECKING), `scan_session.py`
(TYPE_CHECKING). Lazy `app/gates/__init__.py` re-exports `Guardian` (mirrors `app/advisors/__init__.py`).

**Tests:** the 2 Guardian enforcement classes (`TestGuardianUrlScope` 6 + `TestGuardianScanWindow` 4) MOVED from
`tests/scanning/test_proof_of_scope_ops.py` into co-located `app/gates/guardian/tests/test_guardian.py` (the
proof-of-scope logging/report tests STAY behind; the `ScanWindow` import there is still used by ComplianceReport
tests). +7 NEW `TestDiscoveryAndConfig` tests (discover→config→entry_cls→enforces→param accessor).

**Docs reconciled:** plan §7 56.12 row → ✅ DONE; `docs/pipeline.md` Guardian path → `app/gates/guardian/gate.py`
(+ "engagement window" → "scan-window"); `app/dev/rename.py` `_NAME_REF_GLOBS` += `app/gates/*/tests/*.py`.

**GATES ALL GREEN:** ruff check + format clean (636 files; 1 reformat = test_contract_integrity); verify-contracts
OK for **checks + agents + advisors + gates**; `diff-registry … --rename-map` **CLEAN (123, identical)** (checks
unaffected); pytest **2155 passed / 5 skipped / 0 failed** (139s) = 56.11's 2147 + 7 new discovery tests + 1 gate
integrity test (the 10 relocated Guardian tests net to zero). **Committable (operator's call — git is
operator-only). No gate logic changed** (construction now resolves config.yaml via the registry; behavior
byte-identical).

**NEXT — 56.13 (Phase-17 Wave 2):** externalize payload data (`data/payloads/`, `data/wordlists/`,
`data/endpoints/`). Deferred: `verifier` agent (sketch-only); advisor YAML/env back-compat shim (if operator
wants it). Phase 56's component-type work (check/agent/advisor/gate) is now COMPLETE through 56.12.

---


## 56.11 — Advisors component type DONE ✅ (prior session)

**All 3 advisors ported to folder shape.** Core framing (operator): advisors are DETERMINISTIC, rule-based,
narrowly-scoped — **check lineage, NOT agents**. Agents are LLM-backed and need injected SERVICES (client/
event_callback) → spec+factory. Advisors have no LLM/services; their ctor args are per-call DATA the caller
already holds. So advisors got the **discovery + config + contract-metadata** half of folder-shape and NONE
of the agent DI machinery. Three component shapes now: check (no-arg, loader-built) / advisor (per-call,
caller-built) / agent (LLM, factory-injected).

**Foundation built:**
- **`AdvisorContract`** in `app/components/contracts.py` (thin: id/name/type:"advisor"/description/entry +
  outputs/side_effects/references/reason — NO suite/depends_on/produces, NO role/triggers/tools/prompts);
  registered in `CONTRACT_MODELS`.
- **`app/advisors/base.py` `BaseAdvisor(BaseComponent)`** — marker only (component_type+enabled, NO from_spec/DI).
- **`app/advisors/registry.py`** — `AdvisorSpec`/`AdvisorRegistry`/`discover_advisor_specs`/`get_advisor_registry`.
  A **config/discovery accessor, NOT a factory** (`.config(name)`/`.get`/`.entry_cls`/`.param`, NO `.create()`).
  **Does NOT skip disabled advisors** (unlike agents — introspection routes read disabled config).
- **`component_loader._CALLER_CONSTRUCTED={"advisor"}`** — exempts advisors from the no-arg constructibility
  rule (still does entry-exists/class-present); NO `_INJECTED_REQUIRED["advisor"]`.
- pytest testpaths += `app/advisors`; `test_contract_integrity` += advisor root.

**3 folders** (`advisor.py`+`contract.yaml`+`config.yaml`+`__init__.py`+co-located `tests/`):
- **scan_analysis** (uuid da624a5b…, enabled:false). Typed `ScanAnalysisAdvisorConfig.from_component_config`.
  Call sites: `engine/scanner.py:_run_scan_advisor` + `routes/advisor.py` GET now read config via the registry
  (was `cfg.scan_analysis_advisor`). `build_analysis_advisor_from_launcher` kept.
- **scan_planner** (uuid 77b5eaf0…, enabled:true METADATA-ONLY — route runs unconditionally, no new gating;
  only the import path moved). No typed config (ctor takes no config).
- **check_proof** (uuid 20d332de…, enabled:true, side_effects:[filesystem]). Typed `CheckProofAdvisorConfig`.
  +NEW minimal co-located test (it had ZERO tests — gap closed). Call site `engine/chat.py` still
  `CheckProofAdvisor()` direct (unchanged — construction stays at call site).

Flat `scan_analysis_advisor.py`/`scan_planner_advisor.py`/`check_proof.py` DELETED; lazy `app/advisors/__init__.py`
re-points to the subpackages. **config.py:** `ScanAnalysisAdvisorConfig`+`CheckProofAdvisorConfig` dataclasses +
ChainsmithConfig fields + YAML/env apply blocks all DELETED.

**WATCH:** top-level `scan_analysis_advisor:`/`scan_advisor:`/`check_proof_advisor:` chainsmith.yaml blocks +
`CHAINSMITH_SCAN_*ADVISOR_*` / `CHAINSMITH_CHECK_PROOF_ADVISOR_*` env vars are **NO LONGER read** (no advisor
back-compat shim was requested, unlike agents' 56.10c shim — flag for operator if a YAML/env bridge is wanted).

**Docs reconciled:** plan §7 56.11 row → ✅ DONE; `docs/vocabulary-dev.md` + `docs/pipeline.md` (advisor paths +
config keys → per-advisor config.yaml; the chainsmith.yaml `scan_advisor:` example block annotated as no-longer-parsed);
`app/dev/rename.py` `_NAME_REF_GLOBS` updated to folder paths.

**GATES ALL GREEN:** ruff check+format clean (631); verify-contracts OK for **checks + agents + advisors**;
`diff-registry … --rename-map` **CLEAN (123, identical)** (checks unaffected); pytest **2147 passed / 5 skipped /
0 failed** (140s); collect **2152** (= 56.9-era 2135 + advisor tests net). **Committable (operator's call — git is
operator-only). No advisor rule logic changed** (construction now resolves config.yaml via the registry; behavior
byte-identical for default config). Full design + decisions in auto-memory `phase56_11_advisors`.

**NEXT — 56.12 (Gates component type):** port Guardian's gate logic (engagement/scan window, scope, rate limit)
to folder shape. Touches the scan allow/block CHOKEPOINT (see [[project_guardian_gating]]) — extra care; its own
gated phase. Then 56.13 (payload externalization). Deferred: `verifier` agent (sketch-only); advisor YAML/env
back-compat shim (if operator wants it).

---


## 56.9 — CLOSED ✅ (this session)

**56.9 is formally closed.** Its blocker (C9 — the custom-check registry path) was removed in 56.10d, so
the resolver cleanup is complete end-to-end. No new code this session — 56.9 was already implemented across
56.7 (hand-list-empty + infer_suite collapse), 56.9-partial (dead hand-list literal deleted), and 56.10d
(C9 registry path deleted). This session **verified the closeable state and reconciled the docs.**

- **Code state confirmed:** `app/check_resolver.py` is now **195 lines** (was 570). `get_real_checks()` is a
  docstring + single `discover_components(app/checks, "check")` call — no hand-list, no custom-check registry.
  `infer_suite()` is the collapsed pure prefix split (`_SUITE_NAMES` incl. `"custom"`). Grep confirms **zero
  live references** to `CUSTOM_CHECK_REGISTRY` / `_get_custom_checks` (only descriptive "the path is gone"
  comments + historical docs remain).
- **GATES ALL GREEN (fresh run, conda base env, `python -m`):** pytest **2130 passed / 5 skipped / 0 failed**
  (173s); collect **2135**; ruff check + format clean (625 files); `verify-contracts` OK for **both**
  `app/checks` and `--root app/agents --type agent`; `diff-registry … --rename-map` **CLEAN (123, identical)**.
- **Docs reconciled (plan doc §7 + §11):** the §7 rollout-table 56.9 row was stale ("Delete `infer_suite()`")
  — rewritten to reflect reality (infer_suite KEPT/collapsed; C9 deleted in 56.10d; marked ✅ DONE with gate
  numbers). §11 success criterion "below 100 lines" relaxed to **~195 = met** (operator's call this session):
  the <100 figure assumed deleting infer_suite, which §14 instead retains as a one-line prefix split, and the
  resolve/scenario/filter helpers + `get_check_by_name` legitimately stay. **Committable (operator's call —
  git is operator-only); docs + no code change this session.**
- **NOTE:** the older session notes below (lines ~118/161/231) that say "C9 blocks 56.9 close" are HISTORICAL
  (pre-56.10d) — left intact as the per-session trail. This top section supersedes them.

---


## 56.10d — C9: custom-check registry → auto-discovered `custom` suite (this session)

**The legacy custom-check registry path is GONE.** Custom checks are now folder-shape
components under `app/checks/custom/custom_<name>/` (= `contract.yaml` + `check.py` + `config.yaml`
+ `__init__.py`), discovered by the SAME `discover_components(app/checks, "check")` call as every core
suite. No registry, no string-editing, no separate load path. **This closes C9 and unblocks 56.9 fully.**

**Operator decisions (2, via AskUserQuestion this session):**
1. **Custom check naming = `custom_<name>`, suite = `custom`.** Uniform with 56.7 (`<suite>_<name>`):
   discovery dir == name prefix == `infer_suite`. Added `"custom"` to `_SUITE_NAMES`
   (`check_resolver.py`), so `infer_suite("custom_foo") → "custom"` and `--suite custom` runs them. The
   scaffold's `suite` arg is now **metadata only** (recorded in the generated `reason`/docstring + the DB
   `chainsmith_custom_checks` row); the contract `suite:` field is always `custom`. (Operator did NOT
   choose the alternative "name by functional suite" option — custom checks do NOT join `--suite web` etc.)
2. **`validate()` custom-health re-implemented via `verify_contracts`.** `_validate_custom_check_health`
   now runs `verify_contracts(Path(CUSTOM_DIR), "check")` and folds violations into `ValidationResult`
   as `invalid_custom_check` issues — same canonical gate as the loader / CI / `dev verify-contracts`,
   instead of the old hand-rolled registry walk. (Operator did NOT choose "drop the step entirely".)

**What landed:**
- **`app/check_resolver.py`:** deleted `_get_custom_checks()` + its call in `get_real_checks()` (and the
  now-unused `import importlib`). Added `"custom"` to `_SUITE_NAMES`. `get_real_checks()` is now just the
  single `discover_components(...)` call.
- **`app/checks/custom/__init__.py`:** deleted `CUSTOM_CHECK_REGISTRY`; docstring rewritten to describe the
  folder-shape convention. (Stays a valid package so the `custom/` dir is importable.)
- **`app/agents/chainsmith.py`:** `scaffold_check` now emits a **folder preview** (returns
  `{"path": <folder>, "files": {contract.yaml, check.py, config.yaml, __init__.py}, "check_name",
  "class_name", "registered": False}`). New pure helper `_render_check_folder` (no I/O — backs both
  preview and write; `contract.yaml` is `yaml.safe_dump`-ed from a dict + `uuid.uuid4()` so it always
  re-parses as `CheckContract`). New static `_custom_check_name` normalizer (`custom_<slug>`, collapses
  `__`). `write_and_register_check` → **renamed `write_check`** (creates the folder + writes the 4 files,
  no registry edit). `_register_custom_check` **DELETED**. `_validate_custom_check_health` re-implemented
  (see decision 2). Dropped `import importlib`; added `uuid`, `Path`, `yaml`.
- **`app/engine/chainsmith.py`:** `create_check` now calls `agent.write_check(...)`; DB metadata
  persistence (`save_custom_check`, `result["path"]` = the folder) unchanged. `scaffold_check` wrapper +
  all `app/routes/chainsmith.py` routes unchanged (routes pass the result dict straight through; no
  frontend reads `code`/`files`).

**Tests** (`tests/core/test_chainsmith_agent.py`): the 2 scaffold tests updated to `custom_<name>` + `files`
dict; +4 NEW — name normalization, `contract.yaml` parses as `CheckContract` (suite=custom), `write_check`
drops a folder that passes `verify_contracts` end-to-end (patches `CUSTOM_DIR`→tmp_path), and the
`verify_contracts`-backed health check surfaces a folder-name-mismatch as `invalid_custom_check`.

**GATES ALL GREEN:** ruff check + format clean (whole repo); `dev verify-contracts` OK for **both**
`app/checks` and `--root app/agents --type agent`; `diff-registry … --rename-map` **CLEAN (123, identical)**
(registry byte-identical — the registry was empty of custom checks, so removing the dead path changes
nothing observable); full pytest **2130 passed / 5 skipped / 0 failed** (193s); collect **2135** (= 56.10c's
2131 + 4 new). **Committable (operator's call — git is operator-only). No core check logic changed.**

**NOTE:** the DB `chainsmith_custom_checks` table + `save_custom_check`/`get_custom_checks` are a metadata
LEDGER (what was created, when, functional-suite intent), independent of discovery — LEFT intact. The
`custom/` "community-upstream never touches it" property is a directory convention, preserved.

**NEXT — deferred:** `verifier` agent (sketch-only, unwired). Optional: wire the
`CHAINSMITH__<AGENT>__<PARAM>` construct-by-key env scheme for agents (legacy shim only today). With C9
closed, **56.9 is fully closeable** and Phase 56's check/agent component-type work is complete through
56.10; remaining sub-phases are advisors (56.11) + gates (56.12) + payload externalization (56.13).

---

## 56.10c — agent sub-configs → per-agent config.yaml (prior session)

**The 4 agent configs left `ChainsmithConfig`.** `AdjudicatorConfig`/`TriageConfig`/`CoachConfig`/
`ResearcherConfig` classes, their fields, and their `_apply_yaml`/`_apply_env` blocks are DELETED from
`app/config.py`. Each agent's knobs now live in its own `app/agents/<name>/config.yaml`. **LLM model
routing stays central** (`LiteLLMConfig.model_adjudicator`/`model_triage` untouched).

**Operator decisions (3, via AskUserQuestion this session):**
1. **Single source of truth = config.yaml `enabled`.** Engine pipeline gates changed from
   `cfg.<agent>.enabled` to **registry membership** (`"adjudicator" not in get_agent_registry()` /
   `"triage" not in …`). A disabled agent isn't discovered → not in the registry. (Coach was never
   actually gated historically — `chat._get_coach` still creates it unconditionally; its `memory_cap`
   now flows from config.yaml via `from_spec`. Researcher has no production call site.)
2. **Path knobs migrate to config.yaml.** `context_file` (adjudicator+triage) and `kb_path` (triage)
   are engine-glue (not ctor args) → moved to each `config.yaml`'s `parameters` and read via a new
   **`AgentRegistry.param(name, key, default)`** accessor. Ctor knobs (coach `memory_cap`, researcher
   `offline_mode`) live in `parameters` too and are forwarded by `from_spec`.
3. **Dead knobs DROPPED:** `CoachConfig.context_window`/`max_recent_events` and
   `ResearcherConfig.data_sources` were defined+YAML-parsed but never consumed → deleted entirely.

**Mechanism (what landed):**
- **`ComponentConfig.parameters: dict`** added (`app/components/config_models.py`). Checks ignore it
  (empty); agents carry their knobs there. `extra="forbid"` preserved (parameters is now a known field).
- **`BaseAgent.from_spec`** (`app/agents/base.py`) now forwards the subset of `config.parameters` the
  subclass `__init__` accepts (via `inspect.signature`) — so coach `memory_cap`/researcher `offline_mode`
  flow from config.yaml; engine-glue params (`context_file`/`kb_path`) are skipped (ctor doesn't accept
  them). Explicit caller `**ctor_knobs` still WIN over config (back-compat for `create(..., offline_mode=True)`).
- **Env back-compat shim** in `app/agents/registry.py`: `_LEGACY_AGENT_ENV` maps the old
  `CHAINSMITH_<AGENT>_ENABLED` / `CHAINSMITH_RESEARCHER_OFFLINE` / `CHAINSMITH_COACH_MEMORY_CAP` vars to
  `enabled`/params; `_apply_legacy_env()` applies them at discovery (BEFORE the enabled-skip, reading
  `os.environ`). All legacy agent env vars still work. (The new `CHAINSMITH__<AGENT>__<PARAM>`
  construct-by-key scheme is NOT wired for agents — legacy shim only, per operator ask; easy to add later.)
- **Engine call sites:** `adjudication.py` + `triage.py` read paths via `get_agent_registry().param(...)`
  with module-default fallbacks (`DEFAULT_ADJUDICATOR_CONTEXT_FILE`, `DEFAULT_TRIAGE_CONTEXT_FILE`,
  `DEFAULT_TRIAGE_KB_PATH`). `load_operator_context`/`load_team_context`/`save_team_context` signatures
  changed from `config: ChainsmithConfig` → `context_file: str | None` (explicit arg → registry → default).
  Removed now-unused `get_config`/`ChainsmithConfig` imports from both engine modules.

**Tests:** `tests/core/test_team_context.py` + `test_operator_context.py` updated to the new
`context_file=` signatures (MagicMock-cfg pattern dropped). NEW `tests/core/test_agent_registry_config.py`
(13 tests) locks the env shim (`_apply_legacy_env` unit + end-to-end discovery), the `param()` accessor,
and ctor-knob forwarding.

**GATES ALL GREEN:** ruff check + format clean (625 files); `dev verify-contracts` OK for **both**
`app/checks` and `--root app/agents --type agent`; `diff-registry … --rename-map` **CLEAN (123, identical)**
(checks unaffected); full pytest **2126 passed / 5 skipped / 0 failed** (173s); collect **2131**
(= 56.10b's 2118 + 13 new registry-config tests). **Committable (operator's call — git is operator-only).
No agent runtime logic changed** (knobs now resolved from config.yaml + env shim; behavior byte-identical
for default config).

**NOTE — chainsmith.yaml back-compat:** the top-level `adjudicator:`/`triage:`/`coach:`/`researcher:`
blocks in a user's `chainsmith.yaml` are NO LONGER parsed (those `_apply_yaml` blocks were removed). Agent
config now comes from each `config.yaml` + the legacy env shim. No bridge from chainsmith.yaml → agent
config.yaml was requested. Flag for the operator if a YAML override path is still wanted.

**NEXT — 56.10d / deferred:** ChainsmithAgent custom-check rework + `CUSTOM_CHECK_REGISTRY`/
`_get_custom_checks` deletion (C9, still blocks 56.9 close); `verifier` (sketch-only, unwired). Optional:
wire the `CHAINSMITH__<AGENT>__<PARAM>` construct-by-key env scheme for agents (parity with checks).

---

## 56.10b — coach/triage/researcher → folder shape + factory (prior session)

**All three ported** to `app/agents/<name>/` = `agent.py` + `contract.yaml` + `config.yaml` + `__init__.py`
(re-export) + co-located `tests/`. Each class is now `(BaseAgent)`. Flat `coach.py`/`triage.py`/
`researcher.py` DELETED. Contract UUIDs: coach `eee801d8-…`, triage `760eea70-…`, researcher `2514ba77-…`.

- **`BaseAgent.from_spec` extended with `**ctor_knobs` passthrough** (`app/agents/base.py`): forwards extra
  kwargs to the subclass `__init__`, so the factory can inject coach `memory_cap` / researcher `offline_mode`.
  Defaults preserved; no caller passes them yet → behavior identical. This is the "extend from_spec" option
  the 56.10a handoff flagged (chosen over post-construction settable attrs — cleaner, single code path).
- **Call sites wired through the factory:**
  - `app/engine/chat.py:_get_coach` → `get_agent_registry().create("coach", client=get_llm_client())`.
  - `app/engine/triage.py` → `get_agent_registry().create("triage", client=get_llm_client())`; the KB helpers
    `_match_kb_entries`/`load_remediation_kb` now import from `app.agents.triage.agent` (white-box) — the
    package `__init__` is a clean class-only re-export (adjudicator pattern; white-box symbols from `.agent`).
  - **Researcher has NO production call site** — `chat.py:_handle_researcher` is info-text only (points at an
    aspirational `POST /api/v1/research/{scan_id}` that isn't wired), and the only `ResearcherAgent(...)`
    instantiations were in tests. Migrated anyway (folder + factory-discoverable). `RESEARCHER_TOOLS` tool
    names are listed in contract `tools`.
- **Test split (mirrors adjudicator):** agent-behavior + KB/model/cleanjson tests co-located; the engine-only
  team-context load/save tests moved to `tests/core/test_team_context.py` (parallels adjudicator's
  `load_operator_context` → `tests/core/test_operator_context.py`). Each co-located test gained a
  `TestDiscoveryAndFactory` (proves discover→create→inject; coach/researcher also assert the ctor-knob
  passthrough).
- **GATES ALL GREEN:** ruff check + format clean (624 files); `dev verify-contracts` OK for **both**
  `app/checks` and `--root app/agents --type agent`; `diff-registry … --rename-map` **CLEAN (123, identical)**
  (checks unaffected); full pytest **2113 passed / 5 skipped / 0 failed** (157s); collect **2118**
  (= 56.10a's 2107 + 11 new factory tests: 4 coach + 3 triage + 4 researcher; the moved team-context tests
  reconcile exactly, none lost). **Committable (operator's call — git is operator-only). No agent runtime
  logic changed** (construction now flows through the factory; everything else byte-identical to the flat files).

**NEXT — 56.10c:** migrate the 4 sub-configs (`AdjudicatorConfig`/`TriageConfig`/`CoachConfig`/
`ResearcherConfig`) out of `ChainsmithConfig` into each `config.yaml` (resolve in `from_spec`/ConfigResolver)
+ an env back-compat shim; litellm model routing stays central. Knobs to relocate: adjudicator `context_file`,
triage `context_file`+`kb_path`, coach `memory_cap`, researcher `offline_mode`. **Watch:** the engine still
gates each pipeline on `cfg.<agent>.enabled` (separate from each `config.yaml: enabled`) — reconcile the two
enables in 56.10c. Still DEFERRED (operator didn't select): ChainsmithAgent custom-check rework +
`CUSTOM_CHECK_REGISTRY`/`_get_custom_checks` deletion (C9, blocks 56.9 close); `verifier` (sketch-only).

---

## 56.10a — Agents component type: foundation + adjudicator pilot (prior session)

**Operator-approved design (3 decisions, this session):**
1. **Agent lifecycle = spec registry + factory** (NOT no-arg startup singletons like checks). Agents
   need a runtime `LLMClient` + per-session `event_callback` and are built per request/session, so
   discovery returns *specs* and a factory injects the runtime deps. Checks' loader path is untouched.
2. **Scope = adjudicator, triage, coach, researcher.** ChainsmithAgent rework + `CUSTOM_CHECK_REGISTRY`/
   `_get_custom_checks` deletion (C9) were **DEFERRED** (operator did not select) — they stay live for a
   later sub-phase. `verifier` deferred (sketch-only, unwired).
3. **Pilot-first sequencing:** 56.10a (foundation + adjudicator) → 56.10b (coach/triage/researcher) →
   56.10c (migrate sub-configs into config.yaml + env back-compat shim).

**What landed in 56.10a (foundation, reusable for 56.10b/c):**
- **`AgentContract`** added to `app/components/contracts.py` (id/name/type/description/entry + role/triggers/
  tools/prompts + outputs/side_effects/references/reason) and registered in `CONTRACT_MODELS["agent"]`.
- **`verify_contracts` is now agent-aware:** `_verify_entry_constructible` takes `component_type` and an
  `_INJECTED_REQUIRED = {"agent": {"client"}}` allowlist — agents may *require* the injected `client`
  without tripping the no-arg rule; checks unchanged (empty allowlist). Violation code renamed
  `entry-not-no-arg` → `entry-not-constructible` (0 external refs).
- **`app/agents/base.py` `BaseAgent(BaseComponent)`** — `from_spec(contract, config, *, client,
  event_callback=None)` builds `cls(client=, event_callback=)` then stamps identity + `enabled`.
- **`app/agents/registry.py`** — `AgentSpec` (contract+config+entry_cls, `.create(**deps)`), `AgentRegistry`
  (`.create(name, **deps)`, `.names()`, `__contains__`), `discover_agent_specs(root=AGENTS_ROOT)` (reuses
  the shared `verify_contracts` gate + loader path helpers; returns specs, does NOT instantiate), and a
  cached `get_agent_registry()`.

**Adjudicator pilot (migrated to folder shape):**
- `app/agents/adjudicator/` = `agent.py` (moved; class now `AdjudicatorAgent(BaseAgent)`) + `contract.yaml`
  (uuid `d764d0ab-…`) + `config.yaml` (`enabled: true`) + `__init__.py` (re-export) + `tests/test_adjudicator.py`.
  Flat `app/agents/adjudicator.py` DELETED. `app/agents/__init__.py` lazy `__getattr__` still resolves
  (`from app.agents.adjudicator import AdjudicatorAgent` → package re-export, identity preserved).
- **Call site wired through the factory:** `app/engine/adjudication.py` now does
  `get_agent_registry().create("adjudicator", client=get_llm_client())` (was `AdjudicatorAgent(client=…)`).
- **Tests:** agent-behavior tests co-located + a new `TestDiscoveryAndFactory` (proves discover→create→inject
  end-to-end); the engine-only `load_operator_context` tests split to `tests/core/test_operator_context.py`;
  original `tests/core/test_adjudicator.py` deleted.
- **pytest `testpaths += "app/agents"`** (pyproject); `tests/test_contract_integrity.py` gained
  `test_agent_contracts_have_no_violations` (agents root).

**GATES ALL GREEN:** ruff check + format clean (620 files); `dev verify-contracts` OK for **both**
`app/checks` and `--root app/agents --type agent`; `diff-registry … --rename-map` **CLEAN (123, identical)**
— checks unaffected; full pytest **2102 passed / 5 skipped / 0 failed** (184s); collect **2107** (= prior
2102 + 4 new factory/discovery tests + 1 new agent-integrity test; the ~28 moved adjudicator tests reconcile
exactly, none lost). **Committable (operator's call — git is operator-only). No agent runtime logic changed**
(adjudicator behavior identical; only construction now flows through the factory).

**NEXT — 56.10b:** port coach/triage/researcher to folder shape + wire their call sites
(`app/engine/chat.py` coach is per-session; `triage.py`; researcher integration) through the factory.
Watch: coach takes `memory_cap` ctor arg + per-session callback; researcher has `offline_mode` ctor arg +
declarative `RESEARCHER_TOOLS` (→ contract `tools`); triage has `kb_path`. `from_spec` currently passes only
`client`+`event_callback`; for ctor-arg knobs either make them settable attributes (apply post-construction)
or extend `from_spec`. Then 56.10c migrates the 4 sub-configs (`AdjudicatorConfig`/`TriageConfig`/`CoachConfig`/
`ResearcherConfig`) from `ChainsmithConfig` into each `config.yaml` + env back-compat shim (litellm model
routing stays central).

---

## 56.9 (partial) — dead hand-list retired from get_real_checks() (this session)

The empty `checks = [...]` literal + its 28 dead `# <Suite> Phase N` comments were deleted from
`app/check_resolver.py:get_real_checks()`. All 133 checks already loaded via `discover_components()`
(the hand-list had been empty since the suites finished migrating), so this is pure dead-code removal —
`get_real_checks()` is now a docstring + `discover_components(...)` + the custom-check block. **GATES
GREEN:** ruff check + format clean; `diff-registry … --rename-map` **CLEAN (123, identical set)** — the
registry is byte-identical, confirming behavior preserved; resolver/registration/infer_suite tests
**47 passed**; collect **2102** (parity). No check logic changed. **Committable (operator's call).**
**STILL DEFERRED to 56.10:** the custom-check registry path (`_get_custom_checks` at `check_resolver.py:96` +
`CUSTOM_CHECK_REGISTRY` in `app/checks/custom/__init__.py`) — it's coupled to reworking the chainsmith
agent's `_scaffold_custom_check` /
`_register_custom_check`, so it stays until 56.10 (Agents). 56.9 cannot fully close before then.

---


## 56.7 FULLY COMPLETE & COMMITTED (session 8) — infer_suite collapsed to a pure prefix split, `_MCP_CHECK_NAMES` DELETED

**The last item is DONE and COMMITTED by the operator** (`app/check_resolver.py` + new
`tests/checks/test_infer_suite.py`). `check_resolver.py` `infer_suite()` is now a pure prefix split
(`check_name.lower().split("_", 1)[0]` validated against `_SUITE_NAMES`, else `"other"`); the
pre-56.7 substring map AND the `_MCP_CHECK_NAMES` exact-set hack are deleted (~120 lines → ~5).
Verified dead-code removal: the function already checked the prefix FIRST, so for every prefixed
runtime name it returned before reaching the fallback. Safety traced exhaustively:
- All 9 production callers pass live registry names (prefixed) or use `getattr(check,"suite") or
  infer_suite(...)` — sims carry an explicit `suite`, so they never infer.
- `apply_scenario` (check_resolver.py:199-205) only injects a sim when its `emulates` EXACTLY equals
  a real (prefixed) check name → bare-emulated sims (`jailbreak_testing`, `guardrail_consistency`)
  match nothing, are dropped, never reach `launcher.completed`/the advisor (the one direct-name caller).
- No production viz/report/db code routes persisted historical names through canonical `infer_suite`
  (the `tests/reports/test_viz_*.py` copies are test-local & independent — LEFT alone, flagged as drift).
- `_MCP_CHECK_NAMES` had 0 external refs.
- **NEW test `tests/checks/test_infer_suite.py`** (15 cases) locks the contract: each suite prefix
  routes; unknown/no-underscore/suite-word-not-first → `"other"`; legacy bare names
  (`auth_check`/`discovery`/`jailbreak_testing`/`cors`) now route to `"other"` (intended, not a regression).
- **GATES ALL GREEN:** full pytest **2097 passed / 5 skipped / 0 failed** (195s, = 2082 + 15 new);
  collect **2102** (= 2087 + 15); `verify-contracts` OK; `diff-registry … --rename-map` **CLEAN (123)**
  (the primary signal — registry_diff derives `suite` via infer_suite); ruff check + format clean.
- **COMMITTED (operator, git is operator-only):** `app/check_resolver.py` (infer_suite collapse
  + `_MCP_CHECK_NAMES` deletion) and the new `tests/checks/test_infer_suite.py`. No check logic changed.

**→ Phase 56.7 is COMPLETE end-to-end AND COMMITTED. All 7 suites uniformly `<suite>_<name>`, offline +
LIVE validated, resolver simplified. Nothing on 56.7 is outstanding. The sections below are the per-suite
history (kept for reference). Possible NEXT threads (separate, operator-gated): the §"Known open item"
56.2 simulation-leftover old names; reactivating the 10 dormant AI checks (§56.4 / auto-memory phase56_ai_dormant_checks);
the divergent `tests/reports/test_viz_*.py` infer_suite copies (test-local drift, harmless).**

---

## 56.7 MCP suite DONE (session 8) — OFFLINE GATES ALL GREEN; LIVE SMOKE PASS

**18 MCP checks → `mcp_*`** via `dev rename-suite mcp --prefix mcp_ --rename-map
.phase56/rename-map.yaml`. This RESTORES the 56.5 strip (reverses committed work — operator
re-opens the 56.5 PR). All 18 folders now carry `mcp_` again; `infer_suite`'s prefix-first
split (check_resolver.py:278-280) routes them correctly with NO `_MCP_CHECK_NAMES` involvement.

- **NO data-key collisions** in MCP (`collision_data_keys()` ∩ MCP names = ∅) → all 18 used the
  blanket exact-quoted sweep, even the generic `discovery`/`prompt_injection`/`template_injection`.
  Pre-checked the swept globs: every `"discovery"` hit is a real check-name ref (chains `check_name`,
  advisor `trigger_check`, fakobanko `discovery-mcp...` finding id, MCP test assertion). Generic
  look-alikes (`agent_discovery-`, `mcp_surface_discovery-`, `web_openapi_discovery-`) have `_`
  before `discovery`, not a quote → the `"X-` finding-key pattern can't match them. Confirmed safe.
- **OVER-SWEEP FINDER — 4 lines, ALL BENIGN.** `_find_oversweep.py mcp` flagged
  `result["matrix"][host]["mcp_auth_check"][...]` (×3, test_viz_coverage) and
  `orchestrator.nodes["mcp_discovery"].suite == "mcp"` (test_chain) — these are coverage-matrix /
  orchestrator dicts keyed BY CHECK NAME, correctly rewritten. NOT data-key over-sweeps. **0 reverts.**
- **rename-map (the chain-collapse care):** DELETED the 18 `mcp_*: <bare>` 56.5 strip entries
  (post-restore they're HARMFUL — single-pass apply maps baseline `mcp_*`→bare while live is now
  `mcp_*` → manufactured drift) AND the 18 `dev rename-suite` auto-appended `<bare>: mcp_*` lines
  (harmless no-ops — no baseline carries a bare MCP key). MCP section now nets to identity
  (registry baseline already = `mcp_*`, live = `mcp_*`). Left a comment block explaining why.
- **One mechanical fixup (part of the change):** `ruff format` reformatted 6 test files (longer
  lines from the `mcp_` prefix, incl. `mcp_websocket_transport/tests/test_websocket_transport.py`).
  No hand edits, no over-sweep reverts.
- **OFFLINE GATES (all green):** full pytest **2082 passed / 5 skipped / 0 failed** (194s); collect
  **2087** (parity); `verify-contracts` OK; `diff-registry … --rename-map` **CLEAN (123)**;
  `ruff check` + `ruff format --check` clean (615 files).
- **Committable (operator's call — git is operator-only):** the 18 `mcp/mcp_*` folders + module-path
  codemods + name-string sweep (chains.py, scan_analysis_advisor.py, scenario.json, tests, scan.html),
  the rename-map edits (18 strip lines deleted + 18 appended lines removed + 56.7 comment), and the
  6 ruff-reformatted test files. No check IMPLEMENTATION logic changed.
- **BOTH FOLLOW-UPS NOW DONE** (see the top §"56.7 FULLY COMPLETE" for the infer_suite collapse):
  1. **LIVE SMOKE — DEFINITIVE PASS** (2026-06-01, session 8). Operator started the MCP target via
     `./range/start-range.sh fakobanko --profile mcp` (the `fakobanko-mcp` service is gated behind a
     compose `profile: mcp` — base `up` only starts www/chat/api/docs; it was NOT running, which is why
     a first scan emitted 0 MCP obs). With it up + healthy (172.18.0.x:8089, recon→mcp `/health` http=200),
     `dev scan-baseline --target fakobanko.local --scenario fakobanko --server 127.0.0.1:8100 --suite
     network --suite mcp` returned **49 obs**: **8 MCP checks fired, ALL `mcp_*`** (`mcp_discovery`,
     `mcp_server_fingerprint`, `mcp_transport_security` ×2, `mcp_websocket_transport`,
     `mcp_notification_injection`, `mcp_resource_traversal`, `mcp_sampling_abuse`,
     `mcp_undeclared_capabilities`) — **ZERO stripped bare names** (no `auth_check-`/`discovery-`).
     `infer_suite`'s prefix-first split routed all names, no `_MCP_CHECK_NAMES` hit. Network re-confirmed
     `network_*` on the same scan (DNS discovered `mcp.fakobanko.local` once the container was up). The
     other 10 MCP checks emitting nothing is EXPECTED (they only observe when the weakness is present;
     this server enforces/rejects). **Rename validated end-to-end. Operator clear to commit the MCP suite.**
     NOTE for any re-run: the MCP target needs `--profile mcp` (or `--all`) on the range launcher, else
     DNS finds only api/chat/docs/www and the MCP suite yields 0 obs.
  2. **infer_suite collapse + DELETE `_MCP_CHECK_NAMES` — DONE (session 8).** Collapsed to a pure
     prefix split; `_MCP_CHECK_NAMES` + the substring map deleted; new `tests/checks/test_infer_suite.py`
     locks the contract. Gates green (pytest 2097p/5s/0f, diff-registry CLEAN 123). Full write-up in the
     top §"56.7 FULLY COMPLETE". The "legacy/simulation names → other" worry was traced out: bare sims
     are dropped by `apply_scenario` (don't match any prefixed real check) and never reach infer_suite.

---

## 56.7 AI suite DONE this session (session 7) — OFFLINE + LIVE GATES ALL GREEN

**26 AI checks → `ai_*`** via `dev rename-suite ai --prefix ai_ --rename-map
.phase56/rename-map.yaml`. The tool SKIPPED the 2 already-prefixed checks
(`ai_error_leakage`, `ai_framework_fingerprint`) → idempotent, as predicted. All 28
AI folders now carry `ai_`. **NO data-key collisions** in AI (`collision_data_keys()`
∩ AI names = ∅), so all 26 used the blanket exact-quoted sweep — no anchored handling.

- **OVER-SWEEP FINDER CLEAN.** `_find_oversweep.py ai` printed NOTHING (exit 0) — none
  of the AI internal-output sub-keys / discriminators / URLs collide with the new
  `ai_*` names, unlike web (http_method_enum `webdav`, sitemap discriminator). Despite
  the handoff's "expect more" warning, AI was clean. Full pytest confirmed it (backstop).
- **TWO mechanical ruff fixups (both auto-applied, part of the change):**
  `app/checks/ai/__init__.py` needed import re-sort (`ruff check --fix`, "Organize
  imports" — the 26 renamed `from app.checks.ai.ai_* import …` lines fell out of
  alphabetical order); `tests/cli/test_cli.py` reformatted by `ruff format` (longer
  line from a prefixed name). No hand edits, no over-sweep reverts needed.
- **OFFLINE GATES (all green):** full pytest **2082 passed / 5 skipped / 0 failed**
  (200s); collect **2087** (parity); `verify-contracts` OK; `diff-registry … --rename-map`
  **CLEAN (123)**; `ruff check` + `ruff format --check` clean (615 files).
- **rename-map:** 26 new `old: ai_new` entries appended (e.g. `jailbreak_testing:
  ai_jailbreak_testing`). The registry baseline carries the bare names → diff-registry
  applies them → CLEAN. (The 2 already-`ai_` checks need no entry — baseline already
  has `ai_framework_fingerprint`/`ai_error_leakage`.)
- **Committable (operator's call — git is operator-only):** the 26 `ai/ai_*` folders +
  module-path codemods + name-string sweep, the `ai/__init__.py` import re-sort,
  `tests/cli/test_cli.py` reformat, and the 26 rename-map entries. No check
  IMPLEMENTATION logic changed.
- **LIVE SMOKE — DEFINITIVE PASS** (2026-06-01, after operator restarted chainsmith-recon
  with the renamed AI code): network+web scan-baseline vs the pre-56.2 anchor → **CLEAN
  (66 obs, identical set)**. The AI rename is transparent end-to-end. AI noise-floor ignores
  were POST-rename `ai_*` (`ai_framework_fingerprint`, `ai_llm_endpoint_discovery`,
  `ai_model_enumeration`, `ai_model_info_check`); **`agent_discovery` stayed BARE** — it's
  the AGENT suite (56.6, kept `agent_` prefix), not renamed this phase. network/web ignores
  stay `network_*`/`web_*`. Exact command in §"Live fakobanko smoke" below. **Operator clear
  to commit the AI suite.**
- **NEXT: MCP (18) — the LAST suite.** RESTORE `mcp_` (reverses the 56.5 strip):
  `dev rename-suite mcp --prefix mcp_ --rename-map …`. For the rename-map, DELETE the
  18 `mcp_*: <bare>` strip entries and re-derive (baseline carries `mcp_*` already —
  the strip entries net out). Then gates + `_find_oversweep.py mcp` + live smoke. FINALLY
  collapse `infer_suite` (check_resolver.py) to a pure prefix split + DELETE `_MCP_CHECK_NAMES`
  (uniform prefixes make the exact-name hack dead code) — diff-registry CLEAN is the signal.

---

## 56.7 web suite DONE this session (session 6) — OFFLINE + LIVE GATES ALL GREEN

**23 web checks → `web_*`** via `dev rename-suite web --prefix web_ --rename-map
.phase56/rename-map.yaml`. NO web name is a `collision_data_keys()` member (simpler
than network's 3) → all 23 used the blanket sweep. But TWO NEW over-sweep classes
surfaced that `collision_data_keys()` does NOT catch (it only reads contract
`produces`/`output_name`, never internal output sub-keys or discriminators):

- **rename-map CHAIN COLLAPSE (the gotcha).** `registry_diff._apply_rename` (and
  scan_diff) apply the map **SINGLE-PASS, no chaining**. The registry + scan baselines
  predate 56.2 and carry the ORIGINAL `cors_check`/`sri_check`/`webdav_check` names.
  The tool appended `cors: web_cors` etc., but the existing 56.2 entries said
  `cors_check: cors` — so baseline `cors_check` mapped only to `cors` (one hop),
  never to `web_cors` → diff-registry DRIFT (cors/sri/webdav). FIX: rewrote the 3
  56.2 entries to map the baseline name DIRECTLY to the final name
  (`cors_check: web_cors`, `sri_check: web_sri`, `webdav_check: web_webdav`) and
  DELETED the redundant `cors|sri|webdav: web_*` lines (no baseline carries the bare
  `cors` key). diff-registry CLEAN again. **LESSON for any future re-rename of an
  already-renamed check: collapse the chain to baseline→current, don't stack hops.**
- **Internal-data-key over-sweep:** `webdav` is an internal key of network
  http_method_enum's `http_methods` output (`data["webdav"]`, PROPFIND/MKCOL) AND a
  substring in its observation title. Blanket sweep corrupted 5 lines in
  `network_http_method_enum/tests/test_http_method_enum.py` → reverted to `webdav`
  (impl unchanged; check.py never in sweep globs).
- **Discriminator + sub-resource-URL over-sweep:** sitemap's finding id is
  `{check}-{host}-{discriminator}` with a HARDCODED `discriminator="sitemap-discovered"`
  (NOT `self.name`). The finding-key pattern `"X-` rewrote the test's
  `"sitemap-discovered"` (a discriminator-tail substring match on `f.id`) and the
  sub-sitemap response-map URLs `"sitemap-main.xml"`/`"sitemap-api.xml"` to `web_*`
  → 4 sitemap tests broke. Reverted 5 lines in `web_sitemap/tests/test_sitemap.py`.
  (scenario.json `expected_findings` ids like `web_header_analysis-…-version-disclosure`
  ARE correct — those genuinely start with the check name.)
- **Two ordinary fixups:** `tests/cli/test_cli.py` sorted-list literal reordered to
  `["network_dns_enumeration", "web_header_analysis"]` (the `sorted()` order flipped
  after prefixing); `tests/scanning/test_simulated_check.py` inline YAML fixture
  `emulates: header_analysis` → `web_header_analysis` (bare YAML value the
  quote-sweep missed; assertion was swept). Same shape as the network sim-fixture fix.
- **NEW reusable finder `.phase56/_find_oversweep.py <suite>`** — surfaces new
  `<prefix><name>` strings in non-check-name contexts (data subscripts, `.get()`,
  `"…" in x.title`, URL/filename, discriminator tails). Reports CLEAN for web now.
  **RUN IT after the AI and MCP sweeps** — those suites have richer output dicts and
  more discriminators, so expect more of these. Full pytest is the backstop, but the
  finder localizes the silent ones fast.
- **OFFLINE GATES (all green):** full pytest **2082 passed / 5 skipped / 0 failed**;
  collect **2087**; `verify-contracts` OK; `diff-registry … --rename-map` **CLEAN (123)**;
  `ruff check` clean + `ruff format` reformatted 7 files (longer lines from the prefix)
  → `--check` clean (615 files).
- **Committable (operator's call — git is operator-only):** the 23 `web/web_*` folders +
  module-path codemods + name-string sweep (chains/advisor/scenario.json/tests/scan.html),
  the rename-map edits (3 chain-collapsed 56.2 entries + 20 new web entries, redundant
  3 removed), the 10 over-sweep reverts (5 http_method_enum + 5 sitemap), the 2 fixups
  (test_cli order, test_simulated_check fixture), and `.phase56/_find_oversweep.py`.
  No check IMPLEMENTATION logic changed.
- **LIVE SMOKE — DEFINITIVE PASS** (2026-06-01, after operator restarted chainsmith-recon):
  network+web scan-baseline vs the pre-56.2 anchor → **CLEAN (66 obs, identical set)**. The
  web rename is transparent end-to-end. Web ignores are now POST-rename: `web_mass_assignment`,
  `web_redirect_chain` (the rename-map renames the baseline → web_*, live emits web_*, so the
  ignore must be web_*). AI ignores stay bare until AI is renamed. The exact command run is in
  the §"Live fakobanko smoke" section below. **Operator clear to commit the web suite.**
- **NEXT: AI (28) → MCP (18).** `dev rename-suite ai --prefix ai_ --rename-map …`
  (2 checks already carry `ai_` → tool skips them, idempotent), gates, run
  `_find_oversweep.py ai`, fix, live smoke. Then MCP (restore `mcp_`), and finally
  collapse `infer_suite` to a pure prefix split + delete `_MCP_CHECK_NAMES`.

---

## 56.7 (uniform suite-prefixed names) — network suite DONE (session 5)

**56.7 is the convention sweep** (operator-confirmed): make every check `<suite>_<name>`.
Spec written into the plan doc as a new **§14** (docs/future-ideas/phase56-component-modularization.md):
§7 execution note, §8.7 superseded note, §11/§13 updates. Order: **network (done) → web → AI → MCP last**,
then simplify infer_suite + delete `_MCP_CHECK_NAMES`.

- **NEW tooling `app/dev/rename.py`** (+ CLI `dev rename-check` / `dev rename-suite --prefix`, hidden):
  the `migrate-*` tools are flat→folder and DON'T apply (all suites already foldered). Per check:
  (1) folder rename, (2) contract.yaml `name:` + check.py `name=` attr, (3) **module-path codemod**
  (`app.checks.<suite>.<old>` → `<new>`, plain prefix swap, NO `.check` insertion — refs already point at
  `.check`, unlike migrate's codemod), (4) **surgical name-string sweep** over an allowlist
  (chains.py, scan_analysis_advisor.py, scenario.json `expected_findings`, `tests/**`, co-located
  `app/checks/*/*/tests/`, scan.html). NEVER simulations / check_proof.py / data keys.
- **KEY LESSON — data-key/check-name string collision.** Three network names are ALSO dependency data
  keys: `dns_records`, `wildcard_dns`, `reverse_dns` (produced/consumed; appear as `produces`,
  `output_name`, `outputs[...]`, `run({...})`, `"X" in produces`). A blanket quote-sweep corrupts the
  data-key uses. FIX baked into the tool: `collision_data_keys()` reads all contracts' produces+depends_on;
  a name in that set is swept with **anchored check-name patterns only** (`.name ==`, `.check_name ==`,
  `check_name`/`check`/`name` dict, `emulates`, `trigger_check`/`suggest`, `infer_suite("X")`,
  `"X" in names|check_names|all_check_names`, finding-key `"X-"`), never bare-quoted. Non-collision names
  use the blanket sweep. (Watch this for web/AI/MCP too — recompute per suite; tool does it automatically.)
- **infer_suite (check_resolver.py) made prefix-aware-with-fallback** (§14.4): `name.split('_',1)[0]` in the
  suite set returns it FIRST, else falls through to the legacy substring/`_MCP_CHECK_NAMES` logic. So it's
  correct while the sweep is mid-flight (some suites prefixed, some bare). Collapse to a pure prefix split
  + delete `_MCP_CHECK_NAMES` only AFTER all 4 suites carry prefixes (i.e. after MCP).
- **13 network checks → `network_*`.** rename-map appended `<name>: network_<name>` (registry baseline
  carries bare names → diff-registry CLEAN). Also updated the scan-smoke-only `ports:` line to
  `ports: network_port_scan` (no effect on diff-registry, whose key is `port_scan`).
- **Manual fixups after the sweep (now folded into the tool, but did happen):** reverted 6 `dns_records`
  data-key over-sweeps in top-level tests (the first run used the pre-collision-aware blanket sweep) + 7 in
  co-located tests (a buggy `"X" in` membership pattern, since narrowed to `in names|check_names`); fixed an
  unquoted sim YAML fixture (`emulates: network_dns_enumeration`), a CLI sorted-list order, and an unquoted
  compliance table assertion (`| network_port_scan | network |`).
- **OFFLINE GATES (all green):** full pytest **2082 passed / 5 skipped / 0 failed**; collect **2087**;
  `verify-contracts` OK; `diff-registry --compare … --rename-map` **CLEAN (123)**; `ruff check` + `ruff
  format --check` clean (615 files).
- **Committable (operator's call — git is operator-only):** `app/dev/rename.py` + cli.py `dev rename-*`
  wrappers, `check_resolver.py` infer_suite prefix-guard, the 13 `network/network_*` folders + module-path
  codemods + co-located test name fixes, the swept name-refs (chains/advisor/scenario.json/tests/scan.html),
  `.phase56/rename-map.yaml`, and the §14 doc additions. No check IMPLEMENTATION logic changed.
- **LIVE SMOKE — DEFINITIVE PASS** (2026-06-01, after operator restarted chainsmith-recon):
  network+web scan-baseline vs the pre-56.2 anchor → **CLEAN (66 obs, identical set)**. The network
  rename is transparent end-to-end. **Smoke command note:** `--rename-map` is applied to the BASELINE
  *before* `--ignore-check` filters both sides (scan_diff.compare), so the two network noise-floor ignores
  are now the POST-rename names: `--ignore-check network_traceroute` and `--ignore-check network_reverse_dns`
  (web/AI ignores stay bare: mass_assignment, redirect_chain, agent_discovery, ai_framework_fingerprint,
  llm_endpoint_discovery, model_enumeration, model_info_check). rename-map's `ports: network_port_scan`
  line covers the scan-baseline compare (baseline emits `ports`).
- **PRE-COMMIT GATES RE-CONFIRMED GREEN** (fresh run before operator commit): pytest 2082p/5s/0f,
  collect 2087, verify-contracts OK, diff-registry CLEAN 123, ruff check + format clean 615, live smoke CLEAN.
  Operator is committing the network suite now.
- **NEXT: web (22) → AI (28) → MCP (18, also delete `_MCP_CHECK_NAMES` + simplify infer_suite at the end).**
  Run `dev rename-suite web --prefix web_ --rename-map .phase56/rename-map.yaml`, then gates; repeat. For
  MCP, the strip entries already in rename-map net out — drop the 18 `mcp_*: *` lines and re-derive (baseline
  has `mcp_*`). After MCP: infer_suite → pure prefix split, delete `_MCP_CHECK_NAMES`.

---

_Updated 2026-06-01 (session 5). 56.6 (agent + rag + cag, 17 checks each = 51) is COMPLETE OFFLINE:
all deterministic gates green (pytest 2082p/5s/0f, diff-registry CLEAN 123, verify-contracts OK,
collect 2087, ruff check + format --check clean 614). Operator chose to KEEP the agent_/rag_/cag_
prefixes (registry-neutral, AI-style) — a clean strip is IMPOSSIBLE (discovery collides 4 ways incl.
MCP's live bare `discovery`; cache_poisoning collides rag↔cag; the check NAME is a global key, paths
don't disambiguate). LIVE SMOKE — DEFINITIVE PASS (after operator restarted chainsmith-recon):
network+web scan-baseline vs the pre-56.2 anchor → CLEAN (66 obs, identical set, exit 0); server loads
the 51 migrated folders fine. 56.6 fully validated (offline + live). ALL prior suites (56.1–56.5)
remain green. NEXT = 56.7: standardize on suite-prefixed names (see bottom)._

## 56.6 (agent/rag/cag) — what landed this session

- **51 checks → folders, prefixes KEPT** (`app/checks/agent/agent_discovery/` etc.). Registry-neutral:
  NO rename-map entries added, NO infer_suite/chains.py/scan_analysis_advisor/scenario.json churn (names
  unchanged, so all existing refs + the infer_suite substring match still valid). This is the LIGHT
  (AI-style) path, exactly as the prior handoff predicted for the no-strip option.
- **Operator decision rationale (the prior §"FIRST DECISION"):** stripping is blocked by hard global
  collisions. Verified via collision_check (load registry-baseline + apply rename-map → 123 live names,
  strip each prefix): `discovery` ×4 (agent/rag/cag + MCP's already-live bare `discovery`), `cache_poisoning`
  ×2 (rag/cag). The NAME is the global registry key — `component_loader.py:167-177` (Pass 2 `by_name`,
  `duplicate-name` across the whole tree) + `:183-190` (folder name MUST equal contract name). Unique folder
  PATH saves only Python imports, not identity.
- **Per suite:** 0 dormant (all 17 registered), 0 shared-helper modules (17 check files + __init__ exactly —
  unlike MCP's invocation_safety / network's port_profiles), 0 multi-class, 0 §8.5 why/learning_objectives.
- **Internal-symbol test imports** (`.check` redirect — codemod fixes patch targets but not
  `from <pkg> import <non-Check-symbol>`): agent 2 (`FALLBACK_PAYLOADS` from agent_goal_injection, used by
  test_agent_goal_injection.py + test_agent_discovery.py), rag 1 (`CANARY` from rag_chunk_boundary), cag 0.
- **Cross-cutting registration residuals:** each suite had exactly ONE (agent `TestRegistration`,
  rag `TestCheckResolverRegistration`, cag `TestCAGRegistry`) → hand-cleaned into NEW
  `tests/checks/test_<suite>_registration.py` (dropped dead fixtures ruff can't prune). Like web/network.
- **split-tests collision:** goal_injection in test_agent.py + test_agent_exploitation.py → distinct file
  `test_agent_goal_injection__agent_exploitation.py` (hardened tool behavior).
- **Committable (operator's call — git is operator-only):** 51 folders, deleted flat files, 3 suite
  `__init__` import rewrites, resolver block collapses (agent/rag/cag removed from hand-list), co-located
  tests + 3 new `test_<suite>_registration.py`. No check IMPLEMENTATION logic changed. rename-map UNCHANGED.

---

## 56.5 (MCP suite) — what landed this session

- **18 checks → folders; the `mcp_` prefix was STRIPPED from every registered name** (operator
  decision: clean `app/checks/mcp/auth_check/` etc., NOT `mcp/mcp_auth_check/`). This is the FIRST
  Category-A rename of a whole suite. Verified **0 global name collisions** before executing (notably
  `prompt_injection`/`template_injection` are NOT taken by AI). Note `mcp_tool_rate_limit` →
  `tool_rate_limit` (strips only `mcp_`); `rate_limit.py` → `tool_rate_limit/` is the only file whose
  module PATH changed (codemod rewrote its `__init__` import).
- **`invocation_safety.py` is a SHARED HELPER (not a check) — stays FLAT**, exactly like network's
  `port_profiles.py`. `migrate-suite` auto-skips it (no `BaseCheck` subclass → ValueError → SKIPPED).
  **6** checks import it via ABSOLUTE path (`from app.checks.mcp.invocation_safety import …`), so the
  imports survive the move untouched. This is the 19-files-vs-18-checks discrepancy.
- **KEY NEW LESSON — renaming a suite breaks `infer_suite()` (check_resolver.py).** Suite is derived
  from the check NAME by SUBSTRING; `mcp` only matched because names started with `mcp_`. After the
  strip, names fell through and several COLLIDED with AI/agent substrings (`discovery`→agent_discovery,
  `prompt_injection`→system_prompt_injection, `server_fingerprint`→"fingerprint",
  `tool_rate_limit`→"rate_limit"). FIX: added an EXACT-name set `_MCP_CHECK_NAMES` checked BEFORE the
  substring loop, and KEPT `"mcp": ["mcp"]` as a substring FALLBACK so legacy/simulation observations
  with old `mcp_*` names still route to mcp. Registry suite comes from `infer_suite(check.name)`
  (registry_diff.py:33), so this is what made diff-registry go from 17 drift entries → CLEAN.
- **Stale-ref sweep (check-NAME refs only, never data keys like `mcp_servers`/`mcp_*_results`):**
  `chains.py` 13 `check_name` entries, `scan_analysis_advisor.py` 2 (trigger/suggest), 14 test
  `.name ==` assertions, removed 5 orphaned `# MCP Phase` resolver comments. Chain `"name"` identifiers
  (e.g. `mcp_resource_traversal_chain`) and produces/depends_on data keys left intact.
- **Scenario coverage (test_scenario_coverage.py):** stripped `mcp_` from the **18 check-named**
  `expected_findings` in `fakobanko/scenario.json` so finding IDs start with the new check names
  (coverage convention). LEFT `mcp_invocation_safety` (non-check helper finding) as the suite marker →
  both `*_covers_all_suites` indicator tests (which key on `["mcp_"]`) stay green with NO test edits.
  demo-domain's mcp findings are non-check sim IDs (`mcp_resources_exposed`…) — untouched.
- **Co-location:** 5 test files → 18 co-located `tests/`. NO cross-cutting registration class (like AI;
  unlike web/network) → no shared `test_mcp_registration.py`. The 1 residual was the
  `invocation_safety` helper test → renamed `tests/checks/test_mcp_invocation_safety.py` (parallels
  network's flat-helper `test_port_profiles.py`). NO broken internal-symbol test imports (codemod
  handled patch targets → `.check`); collect parity 2087 throughout.
- **0 dormant** (all 18 registered, unlike AI's 10), **0 §8.5 outliers** (all use `reason`), single-class.
- **rename-map.yaml** got the 18 `mcp_<x>: <x>` entries (old→new); diff-registry applies them to the
  baseline → CLEAN.
- **Committable (operator's call — git is operator-only):** the 18 folders, deleted flat files (NOT
  `invocation_safety.py`), `check_resolver.py` (infer_suite + resolver block collapse), `chains.py`,
  `scan_analysis_advisor.py`, `mcp/__init__.py` (import rewrites), co-located tests + renamed helper
  test, `fakobanko/scenario.json`, `rename-map.yaml`. No check IMPLEMENTATION logic changed.
- **LIVE SMOKE — OPERATOR-PENDING.** The documented network+web smoke is unaffected (MCP not in those
  suites). If validating MCP live: it now emits **stripped** observation names (`auth_check-…` not
  `mcp_auth_check-…`); needs MCP servers in the scenario + a chainsmith-recon restart.

---

## 56.4 (AI suite) — what landed this session

- **All 27 AI flat files → 28 folders.** `endpoints.py` was the FIRST and ONLY multi-class file in the
  whole codebase (2 independent checks) → split into `llm_endpoint_discovery/` + `embedding_endpoint_discovery/`.
- **NEW tooling (reusable for 56.5+):**
  - `migrate_check` now handles N independent classes (`split_multiclass_source`): N folders, each
    `check.py` = shared preamble + one class body; guard-raises if the module has a shared module-level
    helper (function/assignment) or a non-check top-level class (none exist anywhere). Output is shaped
    identically to a single-class folder.
  - `codemod.rewrite_imports_multiclass`: splits a combined `from <mod> import A, B` across the new
    per-class packages. Attribute/patch refs (ambiguous in a split — symbol lands in every folder) are
    left for test co-location to disambiguate per-folder. (Used on `ai/__init__.py` + the endpoints test.)
  - `migrate_suite` captures the live registry once up front (`_currently_registered_names`) and writes
    `config.yaml enabled: false` for any check NOT currently registered — so dormant checks stay dormant
    (registry-neutral). No-op for web/network (all were registered).
- **DORMANT CHECKS (key AI-specific finding):** AI has 28 check CLASSES but only **18 were ever
  registered**; 10 are dormant (flat files re-exported by `ai/__init__.py` but absent from the resolver
  list). Operator decision: migrate all 28, the 10 dormant get `enabled: false`, **REVISIT activation
  after Phase 56** (see auto-memory `phase56_ai_dormant_checks`). The 10: `adversarial_input, auth_bypass,
  response_caching, embedding_extraction, function_calling_abuse, guardrail_consistency,
  conversation_history_leak, model_behavior_fingerprint, streaming_analysis, training_data_extraction`.
- **Test co-location:** 5 AI test files (`test_ai_attacks/endpoints/fingerprint/leakage/leakage_disclosure`)
  split → all classes are check-specific (NO cross-cutting registration class → no shared
  `test_ai_registration.py` needed, unlike web/network). All 5 sources fully consumed & removed. The
  endpoints patches (`...endpoints.AsyncHttpClient` ×15) were fixed per-folder AFTER the split (each
  co-located file is single-folder, so a blanket `endpoints.` → `<folder>.check.` rewrite is unambiguous).
  NOTE: AI tests had ZERO broken internal-symbol imports (cleaner than network's 13) — they only import
  entry classes.
- **OFFLINE GATES (all green, re-confirmed after ruff):** full pytest **2082 passed / 5 skipped / 0 failed**;
  `--collect-only -q` **2087** (parity); `verify-contracts` OK; `diff-registry --compare … --rename-map`
  **CLEAN (123 identical)**; `ruff check app/ tests/` clean; `ruff format app/ tests/ --check` clean (489 files).
- **rename-map:** NO AI entries needed (registered names were already the desired folder names; no
  Category-A renames). No `why`/`learning_objectives` §8.5 outliers in AI either.
- **Committable (operator's call — git is operator-only):** tooling (`app/dev/migrate.py`,
  `app/dev/codemod.py`), the 28 AI folders, resolver edits (AI block removed + collapsed), `ai/__init__.py`
  import split, and the co-located AI tests. No check IMPLEMENTATION logic was changed (Option B: only the
  4 config tunables stripped; dormant get enabled:false).
- **LIVE FAKOBANKO SMOKE — DEFINITIVE PASS (2026-06-01, after operator restart):** the §smoke command below
  returned **CLEAN (66 obs, identical set, exit 0)** — every migrated network+web check matches the pre-56.2
  anchor. Registry-neutral migration confirmed end-to-end; noise floor unchanged (existing ignore set covers
  the AI checks). 56.4 is fully validated (offline + live).

---

## Where things stand (prior phases)

- **56.1, 56.2, 56.3 all COMPLETE.** Web (22 checks) + network (13 checks) are in folder shape
  (`app/checks/<suite>/<check>/` = `check.py` + `contract.yaml` + `config.yaml` + `__init__.py`
  + co-located `tests/`). `port_profiles.py` stays flat (helper, not a check).
- **All gates green (re-confirmed this session):**
  - full pytest **2082 passed / 5 skipped / 0 failed**; `pytest --collect-only -q` **2087**
  - `dev verify-contracts` OK
  - `dev diff-registry --compare .phase56/registry-baseline.json --rename-map .phase56/rename-map.yaml`
    CLEAN (123)
  - `ruff check app/ tests/` clean; `ruff format app/ tests/ --check` clean (455 files)
- **CI fixes landed** (both blockers from the original handoff): `ci.yml` drops the positional
  `tests/` path so pyproject `testpaths` applies (collects 2087, not 1866); `ruff format` was run
  and committed.
- **Test co-location FINISHED** (this session):
  - The one genuine gap — `service_probe`'s 13 stranded unit tests — moved into
    `app/checks/network/service_probe/tests/test_service_probe.py`.
  - All cross-cutting registration/resolver residuals consolidated into two shared files:
    `tests/checks/test_network_registration.py` and `tests/checks/test_web_registration.py`
    (the latter replaces the old `test_web_default_debug.py`, which was 1 class buried under
    ~280 lines of dead orphan fixtures/constants).
  - `tests/checks/` network+web footprint is now just those 2 shared registration files +
    `test_port_profiles.py` (the flat-helper test). Collect parity held at 2087 throughout.
- **`.phase56/` pruned**: 38 `*.txt` scratch files deleted; kept this file + `registry-baseline.json`,
  `fakobanko-netweb-baseline.json`, `rename-map.yaml`.
- `app/dev/split_tests.py` hardened with 3 fixes (decorator-aware segment, drop-leading-module-
  docstring, **distinct-file-on-collision** → `test_<check>__<src>.py`). Reuse for 56.4+.

**Committable (operator's call — git is operator-only):** the test-only relocations above. No check
implementation was touched this session.

---

## Live fakobanko smoke — DEFINITIVE PASS (2026-06-01)

`scan-baseline --compare` against the pre-56.2 anchor returned **CLEAN (66 obs, identical set,
exit 0)** — every migrated network+web check produces observations identical to the anchor.
`cors`/`sri`/`webdav`/`robots_txt`/`port_scan` all match; renames are transparent, no regressions.

Reproduce (after restarting the chainsmith-recon container — on `chainsmith-shared` docker net,
localhost:8100, fakobanko containers up). Scan the **base domain `fakobanko.local`**, NOT
`*.fakobanko.local` (the wildcard makes dns_enumeration emit `www.*.fakobanko.local` → 0 hosts →
all web checks skip):

```
python -m app.cli dev scan-baseline --target fakobanko.local --scenario fakobanko \
  --server 127.0.0.1:8100 --suite network --suite web \
  --compare .phase56/fakobanko-netweb-baseline.json --rename-map .phase56/rename-map.yaml \
  --ignore-check network_traceroute --ignore-check web_mass_assignment \
  --ignore-check web_redirect_chain --ignore-check network_reverse_dns \
  --ignore-check agent_discovery --ignore-check ai_framework_fingerprint \
  --ignore-check ai_llm_endpoint_discovery --ignore-check ai_model_enumeration \
  --ignore-check ai_model_info_check
```
(Network + web + AI noise-floor ignores are POST-rename — `network_*` / `web_*` / `ai_*` —
because the rename-map renames the baseline and the live server (once restarted with the
renamed code) emits the prefixed names. `agent_discovery` STAYS BARE — it's the AGENT suite
(56.6, kept its `agent_` prefix), not touched by the AI rename. NB: this AI smoke is
operator-pending — the chainsmith-recon container must be restarted with the renamed AI
code first, or the live server still emits bare AI names and these `ai_*` ignores won't match.)

**Noise floor + non-obvious gotchas:**
- `rename-map.yaml` MUST include **`ports: port_scan`** (old→new) for the *scan* compare — the scan
  baseline predates the rename and emits `ports`. This is the CORRECT direction; do NOT use the
  reversed `port_scan: ports` (it would rename the live check to `ports` if `migrate` re-ran, and
  manufacture drift). Verified safe: `diff-registry` stays CLEAN because the *registry* baseline
  already uses `port_scan` (no-op there). Only the dev scan-baseline tool reads the rename-map —
  no CI/runtime impact. _(Reverses the prior "web-only rename-map" stance, which was correct only
  while port_scan was unmigrated.)_
- `--ignore-check` names must match the name **as it appears in the baseline being filtered** —
  after the AI rename + rename-map, that's `ai_model_info_check` (the rename-map maps the baseline's
  bare `model_info_check` → `ai_model_info_check`, and the AI check emits 0 this run, so the obs live
  on the baseline side post-rename).
- `reverse_dns` flaps purely from **Docker IP reassignment** across restarts (same IPs ↔ different
  `fakobanko-*` hostnames each boot) — environmental, not a code change.
- The AI/agent checks (agent_discovery, ai_framework_fingerprint, ai_llm_endpoint_discovery,
  ai_model_enumeration, ai_model_info_check) + mass_assignment + redirect_chain + traceroute run
  regardless of the requested suite and flap per-scan — see phase56_1_progress memory
  "NOISE-FLOOR FINDING". The HARD deterministic gates remain diff-registry + full pytest; the
  fakobanko scan is a smoke (scan runs, checks fire), compared with --rename-map + --ignore-check.

---

## 56.7 — standardize on suite-prefixed names (OPERATOR-CONFIRMED convention)

> **STATUS (session 8): all 4 shipped suites RENAMED offline — network ✅ web ✅ AI ✅ MCP ✅.**
> agent/rag/cag were already prefixed (56.6). Every check now carries `<suite>_<name>`. Only two
> items remain (see the top §"56.7 MCP suite DONE" section): (1) the MCP **live smoke** is
> operator-pending, and (2) the final **`infer_suite` collapse + `_MCP_CHECK_NAMES` deletion** is
> not yet done (surfaced for the operator). The text below is the original spec/playbook, kept for
> reference.

**ALL 7 suites are now in folder shape** (web=22, network=13, AI=28, MCP=18, agent=17, rag=17, cag=17).
56.6 finished the structural migration. 56.7 is a CONVENTION sweep, not a new migration.

**The decision (operator, 2026-06-01):** adopt UNIFORM suite-prefixed names: every check name =
`<suite>_<name>`. Rationale (long-term viability): collision-proof by construction, makes `infer_suite`
trivial (`name.split('_',1)[0]` validated against the suite set — kills the `_MCP_CHECK_NAMES` special-case),
and self-documenting in observations/logs/API. Today's state is a HYBRID: web/network/AI/MCP are bare
(MCP was stripped in 56.5; AI has 2 vestigial `ai_`), agent/rag/cag are prefixed (56.6). 56.7 makes it uniform.

**Scope (Category-A renames across the 4 shipped suites — agent/rag/cag are ALREADY correct, no rework):**
- **web (22):** add `web_` (e.g. `cors` → `web_cors`, `robots_txt` → `web_robots_txt`).
- **network (13):** add `network_` (e.g. `port_scan` → `network_port_scan`).
- **AI (28):** add `ai_` (e.g. `jailbreak_testing` → `ai_jailbreak_testing`; the 2 existing `ai_*` already fine).
- **MCP (18):** RESTORE `mcp_` — revert the 56.5 strip AND remove the `_MCP_CHECK_NAMES` exact-name set
  from check_resolver.py (uniform prefixes make infer_suite a clean prefix split, so the hack is dead code).

⚠️ This REVERSES committed work (the 56.5 mcp strip + the web `_check`-drop renames). **CONFIRM scope with
the operator before touching the shipped suites** — git is operator-only and this re-opens shipped PRs.
Its own reviewable phase, gated suite-by-suite. (NB: simplify infer_suite to a pure prefix split at the END,
after all 4 suites carry prefixes — not mid-sweep, or unmigrated-this-phase names misroute.)

**56.7 per-suite playbook (the MCP-rename playbook, run in REVERSE — adding/restoring prefixes):**
- Append `old: new` entries to `rename-map.yaml` (old→new, e.g. `cors: web_cors`) as you do each suite, so
  diff-registry applies them to the baseline → stays CLEAN. (For MCP it's the inverse of the current entries:
  `auth_check: mcp_auth_check` etc. — or just delete the 18 mcp lines and re-derive; the baseline has `mcp_*`.)
- `migrate`/rename tooling rewrites folder + contract name + class `name` attr. Sweep check-NAME refs:
  `chains.py` `check_name`, `scan_analysis_advisor.py` trigger/suggest, `scenario.json` `expected_findings`
  (+ the `*_covers_all_suites` indicators), test `.name ==` assertions, scan.html. (NOT data keys.)
- After all 4: `infer_suite` → pure prefix split; delete `_MCP_CHECK_NAMES`. diff-registry CLEAN is the signal.

---

## (Historical) per-suite BASE migration recipe — proven on web + network + AI + MCP + agent/rag/cag

Kept for reference; all suites are migrated. Re-use if a NEW suite is added.

1. `chainsmith dev migrate-suite <suite> --rename-map .phase56/rename-map.yaml`
   (append any Category-A rename to the map ONLY as you migrate that check; use old→new direction).
2. Grep + fix stale old-names across `app/`, `tests/`, `static/`, `scenario.json`.
3. Per shared test file: `dev split-tests <file>` → `ruff check --fix` → `ruff format` →
   assert `pytest --collect-only` count parity → run moved tests. Keep cross-cutting
   registration tests in a shared `tests/checks/test_<suite>_registration.py` (don't co-locate them).
4. Watch for the §8.5 legacy outliers (`why`/`learning_objectives` instead of `reason`) — manual cleanup.
5. **Expect more internal-symbol test imports than web did** (network needed 13 manual `.check`
   redirects for module constants/private fns like `DEFAULT_WORDLIST`, `_random_subdomain`). PATTERN:
   entry class from the package; internal/white-box symbols from `.check`. TOOLING TODO: teach
   split-tests to auto-redirect non-Check imports to `.check`.
6. Final gates: verify-contracts + diff-registry + full pytest + ruff check + ruff format, all green.
7. Live fakobanko smoke after a container restart (use the command above; extend the ignore set if a
   newly-migrated AI/agent check is in the documented noise floor).

## Known open item (operator decision)
- Pre-existing 56.2 web-rename leftovers still reference old names (`cors_check`/`sri_check`/
  `webdav_check`) in: `scenarios/{demo-domain,fakobanko}/simulations/web/*.yaml`,
  `app/checks/simulator/simulations/web/*.yaml`, `demo-domain/scenario.json:123-124`, and a stale
  docstring path in `app/checks/web/sri/check.py:2`. NOT fixed — simulations are don't-touch, and
  these didn't break the live smoke. Flagged for a decision.

Full running status + lessons: auto-memory `phase56_1_progress.md`.
