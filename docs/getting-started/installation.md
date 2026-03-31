# Installation

## Requirements

- Python 3.11+
- pip or pipx

## Install from PyPI

```bash
pip install chainsmith-recon
```

## Install from Source

```bash
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
pip install -e .
```

## Docker

```bash
docker pull ghcr.io/infosecinnovations/chainsmith-recon:latest
docker run -it chainsmith-recon scan example.com
```

## Verify Installation

```bash
chainsmith --version
# Chainsmith Recon v1.2.0

chainsmith list-checks
# Shows 25 checks across 7 suites
```

## Optional Dependencies

For LLM-powered chain analysis:

```bash
pip install chainsmith-recon[llm]
```

Configure provider:

```bash
export CHAINSMITH_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-...
```

## Development Setup

```bash
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
pip install -e ".[dev]"
pytest
```
