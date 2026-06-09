# Launching Chainsmith + range scenarios from VS Code

A wrapper config (`.vscode/`) ships with the repo so you can run, debug, and drive
the range from inside VS Code instead of juggling shells. This is the **native
Python** workflow: the Chainsmith app runs under VS Code's debugger on
`:8000`, while range scenarios run as Docker containers and are loaded into that
native instance.

> Targeting full Visual Studio instead of VS Code, or want the Docker-first
> (`chainsmith.sh`) flow? Those aren't wired here yet — ask and we'll add them.

## Prerequisites

- **VS Code** with the recommended extensions (it will prompt on first open:
  Python, Debugpy, Docker).
- **Python** — a conda env with the deps installed. `.vscode/settings.json`
  defaults the interpreter to base Anaconda (`C:\ProgramData\anaconda3`), which
  already has them. To use a different env: `Ctrl+Shift+P → Python: Select
  Interpreter`. To (re)install deps: run the task **Chainsmith: Install / update
  deps (editable)**.
- **Git for Windows** — the Range tasks call `range/*.sh` through Git Bash at
  `C:\Program Files\Git\bin\bash.exe`.
- **Docker Desktop** running — the range *targets* are containers, even though
  the app itself runs natively.
- **`.env`** present at the repo root (already is). The debugger loads it
  automatically; copy from `.env.example` if you ever need to recreate it.

## The one rule: start the app *before* the range

The native app listens on **:8000**. `start-range.sh` defaults to looking for
Chainsmith on **:8100** (its Docker port). The Range tasks override this with
`CHAINSMITH_PORT=8000` so the script finds your running native instance and
loads the scenario straight into it — **but only if the app is already up.**

If you launch the range first, the script won't find anything on :8000 and will
try to start its own Dockerized Chainsmith. So always:

1. Start the app (debug or run), **then**
2. Start the range.

## Run it

### 1. Debug the API server (recommended)

Press **F5** (or pick **Chainsmith: Debug API server (:8000)** from the Run and
Debug panel). Breakpoints in `app/**` bind — the config deliberately omits
uvicorn's `--reload` so the debugger attaches to the real process.

Open <http://localhost:8000> for the UI.

*(Prefer live reload over breakpoints? Run the task **Chainsmith: Run API server
(:8000, live reload)** instead — same port, no debugger.)*

### 2. Start a range scenario

`Ctrl+Shift+P → Tasks: Run Task → Range: Start scenario → native app (:8000)`,
then pick `fakobanko` or `demo-domain`. The task brings up the scenario's
containers and POSTs it to your native app's `/api/v1/scenarios/load`. The
scenario is then live in the UI for scanning.

### 3. Debug a scan through the CLI (optional)

With the server running, pick the **Chainsmith: Debug CLI (scan)** debug config.
It prompts for a target (default `127.0.0.1:8082`, a fakobanko service) and
steps through `python -m app scan <target>`.

### 4. Tear down

- **Range: Stop (all scenarios)** — stops the scenario containers.
- **Range: Reset scenario (clear state)** — stops + clears state/volumes and
  re-randomizes on next start.
- Stop the app from the debugger toolbar (or close the run terminal).

## What's in `.vscode/`

| File | Purpose |
|------|---------|
| `settings.json` | Default interpreter, pytest discovery, Git Bash default terminal, cache hygiene |
| `extensions.json` | Recommended extensions (Python, Debugpy, Docker) |
| `launch.json` | Debug configs: **API server (:8000)** and **CLI (scan)** |
| `tasks.json` | Install deps, run server, and Range start/stop/reset tasks |

## Troubleshooting

- **`docker: command not found` in a Range task** — Docker Desktop isn't running,
  or its CLI isn't on PATH for Git Bash. Start Docker Desktop and retry.
- **Range task launched a Docker Chainsmith on :8100** — you started the range
  before the app. Stop it, start the app on :8000 first, then re-run the task.
- **`Port 8000 already in use`** — a previous app instance is still running.
  Stop it from the debugger/terminal, or kill the process on :8000.
- **F5 can't find uvicorn / imports fail** — wrong interpreter. Re-select your
  conda env via `Python: Select Interpreter`, then run the install-deps task.
- **LLM / scan errors about missing keys** — fill in the relevant key in `.env`
  (`LLM_PROFILE` + matching `*_API_KEY`). The server boots without them; only
  AI-backed checks need them.
