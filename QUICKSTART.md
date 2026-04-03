# Quickstart

## Prerequisites

- Docker + Docker Compose v2
- An API key for your chosen LLM provider (not needed for Ollama)

## 1. Configure

```bash
cp .env.example .env
```

Edit `.env` — set `LLM_PROFILE` and the matching API key:

| Profile      | Required variable      |
|-------------|------------------------|
| `openai`    | `OPENAI_API_KEY`       |
| `anthropic` | `ANTHROPIC_API_KEY`    |
| `ollama`    | *(none)*               |
| `litellm`   | `LITELLM_BASE_URL`    |

## 2. Launch

```bash
./chainsmith.sh start --profile openai
```

## 3. Use

**Browser UI** — <http://localhost:8100>

**CLI (local):**

> **Tip:** Use a virtual environment (`python -m venv .venv`, conda, etc.)
> to avoid polluting your system Python.

```bash
pip install -r requirements.txt
pip install -e .                 # installs the `chainsmith` CLI
chainsmith --server 127.0.0.1:8100 scan <target>
```

## Other commands

```
./chainsmith.sh stop        # stop (keeps data)
./chainsmith.sh logs        # tail logs
./chainsmith.sh status      # container states
./chainsmith.sh teardown    # remove everything
```
