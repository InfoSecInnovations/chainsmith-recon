# Module Phase 2 — Markdown Scan Reporter ("Notebook")

**Status:** Design / pending implementation
**Module name:** `scan-reporter`
**Tier:** `community`
**Prerequisite:** Module System (`module-system-design.md`) must land first.

---

## 1. Goals

Produce a researcher- or blogger-friendly **markdown notebook** from a completed scan: one directory per scan, with an `index.md` that narrates the scan results and supporting files for observations and evidence.

- Audience: security researchers, bug bounty hunters, CTF writeup authors, OSS maintainers who want to publish their scan output
- **Post-hoc only** — runs against a completed scan, not live
- **One directory per scan** — portable, self-contained, good for `git` or Jekyll/Hugo/MkDocs drops
- Narrative is a **mix**: deterministic scaffold + optional LLM-generated intros + explicit operator notes
- Template customization: ship a default template, but users can override via their own template files

## 2. Non-goals

- Compete with paid-tier **branded reports**, **executive summaries**, or **comparison/retest reports** — those are client-deliverable formats with different design constraints (branding, legal language, structured exec narrative)
- Rich PDF output (core already does PDF via existing export paths)
- Live/streaming updates as the scan runs
- Publishing/hosting the notebook anywhere — just writes files

**Positioning:** this is a writeup/blog format for humans who will read and edit it further, not a polished deliverable.

---

## 3. Module layout

```
modules/scan-reporter/
├── manifest.toml
├── module.py
├── cli.py                  # `chainsmith report notebook <scan-id>`
├── builder/
│   ├── __init__.py
│   ├── assembler.py        # orchestrates scan → notebook dir
│   ├── sections.py         # deterministic section renderers (header, scope, findings, etc.)
│   ├── narrative.py        # LLM-generated intro/summary (optional, costs tokens)
│   ├── notes.py            # injects operator notes
│   └── media.py            # embeds HTTP req/resp captures, evidence blobs
├── templates/
│   ├── default/            # default template (shipped with module)
│   │   ├── index.md.j2
│   │   ├── observation.md.j2
│   │   └── README.md       # top-level scan description
│   └── _schema.md          # documents the template contract for user overrides
└── tests/
    ├── fixtures/           # canned scan JSON for deterministic golden-file tests
    ├── test_assembler.py
    └── test_narrative.py   # mocks LLM calls
```

### Manifest

```toml
[module]
name = "scan-reporter"
version = "0.1.0"
description = "Generate researcher-friendly markdown notebooks from completed scans"
tier = "community"
chainsmith_min_version = "1.3.0"

[dependencies]
python = ["jinja2>=3.1"]

[contributes]
cli_groups = ["report"]
# Extends the existing 'report' CLI group with a new 'notebook' subcommand.
# The module system needs to allow extending existing groups, not just adding new ones.
```

**Design flag:** the module system's CLI extension point must support **extending an existing group** (not just registering a new one). Otherwise `chainsmith report notebook` has to become `chainsmith notebook` and the UX fragments. Call this out as a module-system-design requirement.

---

## 4. Output shape

```
scans/my-scan-8a7f9c1d/
├── README.md                    # top-of-directory summary (title, date, target)
├── index.md                     # the main narrative notebook
├── scan.json                    # raw scan data (copy from core export)
├── observations/
│   ├── 001-missing-csp.md       # numbered, slug from title, per-observation file
│   ├── 002-weak-tls.md
│   └── ...
├── evidence/
│   ├── http-captures/
│   │   └── missing-csp.http     # raw request/response
│   └── raw/
│       └── port-scan.txt
└── notes.md                     # operator notes (preserved across re-runs)
```

**Numbering:** observations are numbered `001-`, `002-` in rendered order. This gives writeup authors stable anchor links and predictable ordering when committed to git.

---

## 5. Narrative model (the "d" option from brainstorming)

The notebook is assembled from four layers, in this order:

| Layer | Source | When enabled | Owner |
|---|---|---|---|
| **Scaffold** | Deterministic rendering of scan data | Always | Module |
| **Narrative intros** | LLM-generated 2-3 sentence intros per section | `--with-narrative` flag, off by default | Core's LLM provider (user pays tokens) |
| **Operator notes** | `notes.md` in the output dir, preserved across rebuilds | User-created | User |
| **Template overrides** | User's custom Jinja templates | If `--template <path>` or `~/.chainsmith/notebook-templates/<name>/` | User |

### Re-running the reporter

`chainsmith report notebook <scan-id> --output scans/my-scan-8a7f9c1d/` can be re-run safely:
- `index.md`, `observations/*.md` — **regenerated** each run from scan data + narrative + template
- `notes.md` — **preserved** (never overwritten)
- `evidence/` — **preserved** + additive (new evidence appended, existing never touched)

This lets researchers take notes, re-render the narrative (e.g., after a new LLM model is released), and not lose their work.

**Safety rail:** if `index.md` has been hand-edited (module detects by comparing a fingerprint stored in a comment at the top), refuse to overwrite without `--force`. Operator notes should live in `notes.md`, not in `index.md`.

---

## 6. Default template structure

`templates/default/index.md.j2`:

```markdown
<!-- chainsmith-notebook: generated; do not edit directly. Put notes in notes.md. -->
<!-- fingerprint: {{ fingerprint }} -->

# {{ scan.target_domain }} — Scan {{ scan.id[:8] }}

**Date:** {{ scan.started_at }}
**Duration:** {{ scan.duration_human }}
**Profile:** {{ scan.profile_name }}
**Findings:** {{ findings.total }} ({{ findings.by_severity.critical }} critical, {{ findings.by_severity.high }} high, ...)

{% if narrative.intro %}
{{ narrative.intro }}
{% endif %}

## Scope

{% include 'partials/scope.md.j2' %}

## Findings

{% for obs in observations %}
### {{ loop.index }}. {{ obs.title }}  ({{ obs.severity }})

See [observations/{{ obs.slug }}.md](observations/{{ '%03d' % loop.index }}-{{ obs.slug }}.md) for full evidence.

{{ obs.description }}

{% endfor %}

## Operator Notes

{% include '../notes.md' ignore missing %}
```

### Template override protocol

1. User creates `~/.chainsmith/notebook-templates/my-template/` with the same file structure as `default/`.
2. Runs `chainsmith report notebook <scan-id> --template my-template`.
3. Templates only have to override the files they change; missing files fall back to `default/`.
4. `templates/_schema.md` documents the template context (variables available to Jinja) so users can author templates without reading module source.

---

## 7. Embedded media

| Media type | When | How |
|---|---|---|
| HTTP req/resp captures | Always when present on an observation | Written to `evidence/http-captures/<obs-slug>.http` as raw text; linked from the observation page |
| Raw command output | Always when present | Written to `evidence/raw/<check-name>.txt` |
| Screenshots | If any check produces them (none currently do — future-proofing) | `evidence/screenshots/<check-name>-<n>.png`, embedded inline if small |
| Scan JSON | Always | `scan.json` at the root |

Module never tries to re-fetch evidence — it consumes whatever the core scan already stored.

---

## 8. LLM narrative (optional)

When `--with-narrative`:

- Module calls core's configured LLM provider via `core.llm.complete(...)` (Module API addition)
- Generates short (2-3 sentence) intros for: top-of-notebook summary, each severity group, each attack chain
- **Clearly marked** as AI-generated in the rendered output (a subtle "— AI-generated summary" footer under each block)
- Caches by scan fingerprint — re-running with `--with-narrative` doesn't re-generate unless `--refresh-narrative`

**Cost control:** module prints estimated tokens and the configured profile before the LLM call, and refuses to run if `--with-narrative` is used without a configured LLM profile.

**Required module API:** `core.llm.complete(system, user, max_tokens) -> str`. If this doesn't exist in the Module API on day one, gate the narrative feature off and ship the scaffold-only version.

---

## 9. Testing

- **Golden-file tests**: fixture scans in `tests/fixtures/*.json` → expected output in `tests/fixtures/expected/<scan-id>/`. Byte-compare `index.md` and per-observation files.
- **Narrative tests**: mock `core.llm.complete` so tests don't cost tokens and are deterministic.
- **Re-render idempotency test**: render a scan, hand-add `notes.md`, re-render, assert notes preserved.
- **Fingerprint test**: render, edit `index.md`, assert re-render refuses without `--force`.
- **Template override test**: supply a minimal override template, assert mixed default+override works.

---

## 10. Open questions

1. **CLI group extension.** Can the module system extend an existing CLI group (`report`) or only register new top-level groups? If not, the command becomes `chainsmith notebook <scan-id>` and we accept the fragmentation.
2. **Jinja dependency.** Jinja isn't listed in core's direct dependencies (confirm). If core's existing report templates use Jinja, great — share it. If not, this module adds it.
3. **Narrative section boundaries.** How "chatty" should the default narrative be — one paragraph total, or per-section? Start with sparse; let users request more.
4. **Git-friendliness.** Should the module auto-`.gitattributes` the output directory (e.g., mark `scan.json` as `-diff`)? Or leave all git decisions to the user?
5. **Evidence size.** Big raw captures could bloat git repos. Add a `--max-evidence-bytes` flag that truncates with a pointer?

---

## 11. Definition of done

- `chainsmith report notebook <scan-id>` produces a valid notebook directory from any completed scan in core's DB
- Default template renders cleanly; overriding single files works
- Re-render preserves operator notes and evidence, refuses to overwrite hand-edited `index.md`
- `--with-narrative` works when an LLM is configured; gracefully disabled otherwise
- Golden-file tests pass across at least 3 fixture scans (small, medium, large)
- Manifest validates; removing the module folder removes the command
