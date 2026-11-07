# Installation

Chainsmith Recon is not published to PyPI. Run it with Docker, or install it from
a source checkout.

## Docker (recommended)

Requires Docker and Docker Compose v2. Follow [QUICKSTART.md](../../QUICKSTART.md):

```bash
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
cp .env.example .env          # set LLM_PROFILE and the matching API key
./chainsmith.sh start --profile openai
```

The browser UI and API are then available at <http://localhost:8100>.

## CLI from Source

The `chainsmith` CLI talks to a running server. Install it locally to drive the
Docker stack (or a native server) from the command line.

Requirements: Python 3.12+. Use a virtual environment (`python -m venv .venv`,
conda, etc.).

```bash
pip install -r requirements.txt
pip install -e .                 # installs the `chainsmith` CLI
chainsmith --server 127.0.0.1:8100 list-checks
```

## Native Server (without Docker)

```bash
chainsmith serve                 # listens on 127.0.0.1:8000
chainsmith list-checks           # the CLI defaults to 127.0.0.1:8000
```

See [CLI Overview](../cli/overview.md#server-address) for the port difference
between Docker (8100) and native (8000).

## Verify Installation

```bash
chainsmith --version
chainsmith --server 127.0.0.1:8100 list-checks
# Lists 133 checks across 7 suites
```

## Optional Dependencies

PDF report output:

```bash
pip install -e ".[pdf]"
```

## LLM Provider

With Docker, the provider comes from `LLM_PROFILE` in `.env` (`openai`,
`anthropic`, `ollama`, or `litellm`) plus the matching key. To switch provider
for one launch without editing `.env`:

```bash
./chainsmith.sh start --profile anthropic
```

LLM features are optional; Chainsmith degrades gracefully when no provider is
configured.

## Development Setup

```bash
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for adding checks and running the
contract verifier.
