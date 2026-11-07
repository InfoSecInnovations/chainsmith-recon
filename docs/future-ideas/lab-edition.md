# Lab Edition (SEC536) — Generated Build Target

**Status:** Proposed. Startable now.
**Track:** Lab / distribution
**Depends on:** presets (`app/data/presets.yaml`, `app/scan_presets.py`), which have landed. Optionally the external component roots in [`module-system-design.md`](module-system-design.md).
**Do first:** [`lab-backports.md`](lab-backports.md). These are bugs the current lab snapshot fixed and main still has.
**Size:** M
**Last reviewed:** 2026-10-11

---

## 1. What the lab edition is today

The lab snapshot (kept in the SEC536 course workspace, `post-beta/536-labs-L/1.2`, not in this repo) is an older trimmed
snapshot of main, not a divergent branch:
108 Python files against 559, 25 checks against 133, pre-Phase-30 `Finding` naming, flat `guardian.py`,
pre-Phase-43 flat check files. `scenarios/`, `static/`, and `range/` are strict subsets.

The only files not present in main are `app/agents/scout.py` (superseded by `app/engine/scanner.py`),
`app/checks/student/_example.py`, and the pre-rename `findings.py` pair.

So it is a **fork by neglect**: it drifts every time main changes check semantics, and the drift
silently invalidates the course's instructor solution key and grading rubric (both live in the course
workspace, not this repo).

**Update 2026-10-11.** The drift now runs in both directions. In August 2026 the lab snapshot received
real bug fixes (range session activation, scenario hosts, MCP JSON-RPC enumeration, a semantic cache
service, a skip-and-log student-check loader, vendored d3) that main does not have. Those are listed in
[`lab-backports.md`](lab-backports.md) and should be ported **before** a generated lab build is attempted,
or the first generated build will regress the course.

---

## 2. What it becomes

**A generated build target of main** — a preset plus a component subset — not a hand-pruned copy.

The lab preset:

- **`sampling.iterations: 1`.** A 90-minute lab with 15–20 minute exercises cannot afford 20×. (Only
  meaningful once `phase58-ai-grading.md` §4 lands; harmless before then.)
- **Rule tier grading only.** Fast, offline, no API keys for a room full of students. (Likewise: this is
  the natural state before phase 58, and must stay available after it.)
- **Honest negatives.** A 1-shot "Not Observed" must never render as "Not Vulnerable" — see phase 58
  §9.4. This matters *more* in the lab than in the field, because a student reads a clean report as a
  conclusion.

Instructor materials — solution key, grading rubric — are **regenerated from the lab build**, not
maintained by hand. That is the point of the exercise: the drift stops being possible.

---

## 3. Why it is separable

It was originally bundled with evidence capture and grading because it came up in the same
conversation, not because it depends on them. In fact:

- The preset machinery it needs **already exists** (`app/data/presets.yaml`, `app/scan_presets.py`,
  Phase 56.14).
- Rule-tier-only and 1 iteration are the *current* behaviour of main, so a lab build could be generated
  today and would simply gain the two knobs later.
- The component subset is a selection problem, which presets already solve
  (`suites` / `checks` / `intrusive` / `port_profile`).

Holding it behind a capture-and-grading programme delays a fix to a live course-material problem for no
technical reason.

---

## 4. Open questions

- **L-1** — Does the lab build ship as a generated directory, a Docker image, or both? The classroom
  constraint (no API keys, offline, fast start) may favour an image.
- **L-2** — Which 25 checks? The current subset was chosen by hand at snapshot time. Re-derive it from
  the lab exercises rather than inheriting it.
- **L-3** — Does the build command live in the CLI (`chainsmith build lab`) or as a separate script?
  CLI is more discoverable; a script keeps course tooling out of the product surface.
- **L-4** — How are instructor materials regenerated — a template rendered against the lab build's
  actual output, or a captured golden run? The latter needs `phase57-evidence-and-capture.md`, which is
  the one place a dependency does appear, and only for this sub-question.

---

## 5. Success criteria

1. The lab edition is produced by a **build command from main** and runs inside the lab time budget.
2. A change to a check in main is reflected in the next lab build with no hand-editing.
3. Solution key and grading rubric are regenerated, not maintained.
4. The build runs with no API keys and no network beyond the lab range.
