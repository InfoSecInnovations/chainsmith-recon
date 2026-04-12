# Module Phase 1 — Terminal Live-Scan Dashboard

**Status:** Design / pending implementation
**Module name:** `terminal-dashboard`
**Tier:** `community`
**Prerequisite:** Module System (see `module-system-design.md`) must land first.

---

## 1. Goals

A full-screen terminal UI that attaches to the currently-running scan, shows live progress across checks, streams observations as they appear, and lets the operator **pause, stop, or start** scans from the keyboard.

- CLI-first audience: researchers, hobbyists, students running Chainsmith in a terminal
- Works on Windows (PowerShell/Terminal), macOS, and Linux
- Requires a TTY — headless environments should use the web UI instead
- Single-scan focus (today core runs only one scan at a time; see §4)

## 2. Non-goals

- Multi-scan control panel (out of scope; core is single-scan)
- Browser-rendered TTY (xterm.js) — if you need a browser UI, the web UI already exists
- Replacing the web UI
- Historical scan browsing (that's core's scan-history view / future `scan-reporter` module)

---

## 3. Module layout

```
modules/terminal-dashboard/
├── manifest.toml
├── module.py              # registers CLI command
├── cli.py                 # `chainsmith watch [--scan <id>]` entry point
├── dashboard/
│   ├── app.py             # Textual App subclass
│   ├── widgets/
│   │   ├── header.py      # scan id, target, elapsed, status
│   │   ├── check_table.py # checks + per-check status
│   │   ├── observations.py # streaming observations feed
│   │   └── controls.py    # pause/stop/start keybind help bar
│   └── client.py          # thin async wrapper over core REST + (optional) SSE
└── tests/
    ├── test_client.py     # mocks the REST/SSE layer
    └── test_widgets.py    # Textual's built-in pilot harness
```

### Manifest

```toml
[module]
name = "terminal-dashboard"
version = "0.1.0"
description = "Full-screen terminal UI for watching live Chainsmith scans"
tier = "community"
chainsmith_min_version = "1.3.0"    # bumped for new pause/stop/resume endpoints

[dependencies]
python = ["textual>=0.60", "httpx>=0.27"]

[contributes]
cli_groups = ["watch"]
```

Note: no routers, no DB, no UI slots. This is a pure consumer of core APIs.

---

## 4. Prerequisite core changes

**This module cannot ship without these core additions.** Sequence them as part of Phase 1 before writing the module.

### 4.1 Scan control endpoints

**These endpoints are already assumed to exist by the web UI** — `static/scan.html` has Pause/Resume/Stop buttons wired to `/api/v1/scan/pause`, `/resume`, `/stop` via `static/js/api.js:64-66`. Those buttons 404 silently today. Implementing the routes below fixes a pre-existing bug in the web UI *and* unblocks this module.

Add to `app/routes/scan.py`:

| Endpoint | Behavior |
|---|---|
| `POST /api/v1/scan/pause`    | Set `state.status = "paused"`; runner checks flag between checks and sleeps when paused |
| `POST /api/v1/scan/resume`   | Set `state.status = "running"` |
| `POST /api/v1/scan/cancel`   | Set cancel flag; runner aborts current check, writes `state.status = "cancelled"` |
| `POST /api/v1/scan/start`    | Already exists as `POST /api/v1/scan` — alias for consistency |

The runner (`app/engine/scanner.run_scan`) needs a cooperative pause/cancel check. Propose: a single `asyncio.Event` on `state` (`state.pause_event` — set=run, clear=paused), plus a `state.cancel_requested` bool the runner checks between checks. Nothing inside individual checks needs to change; pause happens at check boundaries.

**Trade-off flagged:** pausing mid-check is much harder (each check would need cooperative yielding). Accepting "pause at check boundaries" keeps this simple; UX is "click pause, current check finishes, then we hold."

### 4.2 Scan-state streaming (optional but recommended)

`GET /api/v1/scan/stream` returning Server-Sent Events. Emits one event per state change: `status_changed`, `check_started`, `check_completed`, `observation_added`. If this lands, the dashboard is reactive and idle. If it doesn't, the dashboard falls back to polling at ~500ms.

**Recommendation:** ship the module with **polling first**, add SSE later. Polling works; SSE is an optimization. Keeps the module-Phase-1 critical path short.

### 4.3 Single-scan assumption

Because `_scan_lock` + `state.status` gate a single scan globally, `chainsmith watch` takes no scan-id argument — it attaches to "the" current scan. If core later adds concurrent scans, the module can be taught `--scan <id>` then.

---

## 5. Library choice: Textual

**Chosen:** [Textual](https://textual.textualize.io/) (v0.60+).

**Why over alternatives:**
- Async-native — matches core's async-everywhere posture; the polling loop is a clean `async for`.
- Cross-platform (Windows 10+, macOS, Linux) without extra setup. Blessed/urwid have known Windows friction.
- Supports keybindings, widgets, scrollable panes, live-updating tables out of the box.
- Same maintainer as Rich; can embed Rich renderables inside Textual widgets for styled output.

**Trade-off:** Textual is heavier than Rich. Accepted because interactivity (pause/stop buttons, selectable observation rows) is a requirement.

---

## 6. UX sketch

```
┌────────────────────────────────────────────────────────────────────────┐
│ chainsmith watch              Target: example.com    Elapsed: 01:23    │
│ Scan: 8a7f9c1d...   Status: RUNNING   Profile: anthropic               │
├────────────────────────────────────────────────────────────────────────┤
│ Checks  [17/42]                         ┃ Observations [5]             │
│                                         ┃                              │
│ ✓ http_headers              0.4s        ┃ [HIGH]  Missing CSP header   │
│ ✓ tls_version               1.1s        ┃   check: tls_version         │
│ ⟳ port_scan                 ...         ┃   host: example.com          │
│ · dir_enumeration           pending     ┃                              │
│ · csrf_probe                pending     ┃ [MED]   Weak TLS config      │
│ ⊘ phi_leakage_detection     skipped     ┃   check: tls_version         │
│   (reason: no AI endpoint)              ┃   ...                        │
│                                         ┃                              │
├────────────────────────────────────────────────────────────────────────┤
│ [p] pause  [s] stop  [r] restart  [q] quit  [↑↓] scroll  [enter] detail│
└────────────────────────────────────────────────────────────────────────┘
```

Three widgets: header, two-column body (checks table + observations feed), footer with keybind hints.

### Keybindings

- `p` — pause (only when running) / resume (only when paused)
- `s` — stop (confirms with modal: "Cancel scan? [y/N]")
- `r` — restart (only when not running; re-POSTs with the same scope)
- `q` — quit the dashboard (does NOT stop the scan)
- `↑/↓` — scroll check table or observations (whichever has focus)
- `tab` — switch focus between panes
- `enter` — open detail view of selected observation

---

## 7. Data flow

```
core.api  ──polling (500ms)──▶  client.py  ──messages──▶  Textual App
                                                              │
                                                              ▼
                                                          widgets refresh
```

Two independent poll loops (Python `asyncio.Task` per loop):
1. **Status loop**: `GET /api/v1/scan` every 500ms → updates header + check table
2. **Checks loop**: `GET /api/v1/scan/checks` every 1s → diff against previous state; only refresh rows that changed
3. **Observations loop**: `GET /api/v1/scan/observations?since=<last_seen>` every 1s → append to observations pane

On action (pause/stop): POST the control endpoint, then force an immediate status poll to reflect the change within 100ms.

If SSE lands later, replace the three polling loops with a single SSE subscriber; the widget-refresh interface stays unchanged.

---

## 8. Cross-platform notes

- **Windows Terminal / PowerShell / conhost**: Textual works; conhost (legacy cmd.exe) has reduced color support but renders. Document that Windows Terminal is recommended.
- **TTY detection**: on startup, call `sys.stdout.isatty()`. If false, print a friendly message pointing to the web UI and exit 2.
- **Signal handling**: `Ctrl+C` should clean-exit the dashboard without stopping the scan. The module is a viewer, not the owner.
- **Resize**: Textual handles SIGWINCH on Unix and Windows resize events natively.

---

## 9. Testing

- `test_client.py` — mock `httpx.AsyncClient` responses; verify the polling loop produces the expected message stream.
- `test_widgets.py` — use Textual's `App.run_test()` pilot harness to drive keybinds and assert state.
- **No integration tests in CI** for the TTY itself (headless CI can't). Module ships with a `chainsmith watch --replay <fixture.jsonl>` developer flag that feeds canned events so humans can QA the UI without spinning up a scan.

---

## 10. Open questions

1. **Observations endpoint for live streaming.** `GET /api/v1/scan/observations?since=<id>` doesn't exist today — need to check `observations.py` route. If it doesn't, add it as part of §4 core prerequisites.
2. **Color palette.** Follow the web UI's palette, or let users configure? Default should look good in both light and dark terminals.
3. **Observation detail view.** Modal overlay vs. secondary screen? Suggest modal for Phase 1 (simpler); secondary screen in a future iteration.
4. **Scan restart semantics.** If we `[r]estart`, do we reuse the last scope or force the user to run `chainsmith scope` again? Suggest: only allow restart if scope is still set on the server.

---

## 11. Definition of done

- `chainsmith watch` launches a full-screen dashboard on Win/Mac/Linux
- Live updates within 1s of core state change (polling) or <100ms (SSE)
- Pause/stop/resume/restart all functional via keybind
- Graceful quit (`q`) leaves scan running
- Degrades cleanly on non-TTY with a helpful message
- `chainsmith watch --replay fixtures/sample-scan.jsonl` demos the UI offline
- Manifest validates; module disables cleanly if removed
