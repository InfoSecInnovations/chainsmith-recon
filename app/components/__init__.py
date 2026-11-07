"""
app/components/ - Component model layer.

Houses the cross-cutting machinery that the auto-discovery loader
(`app/component_loader.py`) builds on:

- `contracts.py`  — Pydantic v2 `contract.yaml` schema (identity + I/O). Authoritative.
- `config_models.py` — Pydantic `config.yaml` / `suite.yaml` source models + `ResolvedConfig`.
- `config_resolver.py` — load-time precedence resolver (§5.1 layers 1-4).
- `base.py` — minimal `BaseComponent` (identity + `from_config()` construction contract).

Per Phase 56 §2/§6 this is checks-only in shape today; agent/advisor/gate
contracts attach as their sub-phases (56.10-56.12) land.
"""
