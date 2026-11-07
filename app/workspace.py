"""
app/workspace.py - Workspace resolution.

A **workspace** is a directory that owns everything one body of work produces:

    ~/chainsmith/clients/acme/
      workspace.yaml     # optional per-workspace settings (57.1b, layer 5)
      chainsmith.db      # scans, observations, verdicts
      evidence/          # the capture store (57.2)
      reports/           # generated report output
      scratch/           # per-scan scratch files
      logs/              # traffic_log.jsonl, violations_log.jsonl, ...
      customizations/    # severity + scan overrides for this engagement

Selected once **at launch** and never switched at runtime — tearing down the DB
engine while scan sessions and SSE streams are live is its own phase.

Precedence, most specific first:

  1. explicit argument     (``--workspace`` on the CLI)
  2. ``CHAINSMITH_WORKSPACE`` env var
  3. ``workspace:`` in chainsmith.yaml
  4. default               (``~/chainsmith/default``)

Legacy path settings (``storage.db_path``, ``RECON_DB_PATH``, ``DATA_DIR``)
still parse, but the workspace wins when they disagree — see
``legacy_conflicts()``. Honouring them would let a database land outside its
workspace, which defeats the physical separation workspaces exist to provide.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

ENV_VAR = "CHAINSMITH_WORKSPACE"

#: Where a workspace lands when the operator names none.
DEFAULT_ROOT = Path.home() / "chainsmith" / "default"

#: The pre-workspace database location, checked once at startup so an upgrading
#: operator is told where their old data is rather than left to wonder.
LEGACY_DB_PATH = Path("./data/chainsmith.db")


@dataclass(frozen=True)
class Workspace:
    """One body of work's directory, and the paths rooted off it."""

    root: Path

    # ─── rooted paths ───────────────────────────────────────────
    @property
    def db_path(self) -> Path:
        return self.root / "chainsmith.db"

    @property
    def config_path(self) -> Path:
        """Per-workspace settings — consumed as config layer 5 in 57.1b."""
        return self.root / "workspace.yaml"

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def scratch_dir(self) -> Path:
        return self.root / "scratch"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def customizations_dir(self) -> Path:
        return self.root / "customizations"

    # ─── lifecycle ──────────────────────────────────────────────
    def ensure(self) -> Workspace:
        """Create the workspace and its subdirectories. Idempotent."""
        for path in (
            self.root,
            self.evidence_dir,
            self.reports_dir,
            self.scratch_dir,
            self.logs_dir,
            self.customizations_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
        return self


def resolve_root(
    explicit: Path | str | None = None,
    yaml_value: Path | str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[Path, str]:
    """
    Resolve the workspace root and report which source won.

    The source label is returned rather than logged here so the caller can put
    it in the startup line — an operator scanning into the wrong workspace is a
    §9 risk, and "which setting chose this directory" is the answer they need.
    """
    env = env if env is not None else dict(os.environ)

    if explicit:
        return Path(explicit).expanduser().resolve(), "--workspace"
    if env_value := env.get(ENV_VAR):
        return Path(env_value).expanduser().resolve(), ENV_VAR
    if yaml_value:
        return Path(yaml_value).expanduser().resolve(), "chainsmith.yaml"
    return DEFAULT_ROOT.expanduser().resolve(), "default"


def resolve(
    explicit: Path | str | None = None,
    yaml_value: Path | str | None = None,
    env: dict[str, str] | None = None,
    create: bool = True,
) -> tuple[Workspace, str]:
    """Resolve, optionally create, and return ``(workspace, source_label)``."""
    root, source = resolve_root(explicit, yaml_value, env)
    workspace = Workspace(root=root)
    if create:
        workspace.ensure()
    return workspace, source


def legacy_conflicts(workspace: Workspace, env: dict[str, str] | None = None) -> list[str]:
    """
    Describe legacy path settings that disagree with the workspace.

    The workspace wins in every case; these strings exist so the operator is
    told what was ignored instead of silently getting a different directory
    than the one they configured.
    """
    env = env if env is not None else dict(os.environ)
    conflicts: list[str] = []

    for name in ("RECON_DB_PATH", "CHAINSMITH_DB_PATH"):
        if value := env.get(name):
            if Path(value).expanduser() != workspace.db_path:
                conflicts.append(f"{name}={value} ignored; database is {workspace.db_path}")

    if value := env.get("DATA_DIR"):
        if Path(value).expanduser() != workspace.logs_dir:
            conflicts.append(f"DATA_DIR={value} ignored; logs are in {workspace.logs_dir}")

    return conflicts


def legacy_db_notice(workspace: Workspace) -> str | None:
    """
    Point an upgrading operator at their pre-workspace database.

    Deliberately does **not** move it. Relocating someone's database as a side
    effect of an upgrade is the wrong default; the migration is a ``mv`` the
    operator can make when they choose to.
    """
    legacy = LEGACY_DB_PATH.expanduser()
    if not legacy.exists():
        return None
    if legacy.resolve() == workspace.db_path:
        return None
    if workspace.db_path.exists():
        return None
    return (
        f"Found a pre-workspace database at {legacy} — it has NOT been moved. "
        f"This workspace starts empty at {workspace.db_path}. "
        f"To carry the old data over: mv {legacy} {workspace.db_path}"
    )


class WorkspaceConfigError(Exception):
    """`workspace.yaml` is malformed, or names a key nothing consumes yet."""


def load_workspace_config(workspace: Workspace | None = None):
    """
    Parse the workspace's `workspace.yaml` into a `WorkspaceConfig` (57.1b).

    Returns an empty config when the file is absent — a workspace without one is
    the normal case, not a degraded one.

    Raises `WorkspaceConfigError` rather than warning: a config file the operator
    wrote and Chainsmith silently ignored is the failure mode this whole layer
    exists to avoid.
    """
    import yaml
    from pydantic import ValidationError

    from app.components.config_models import UNIMPLEMENTED_WORKSPACE_KEYS, WorkspaceConfig

    workspace = workspace or get_workspace()
    path = workspace.config_path
    if not path.exists():
        return WorkspaceConfig()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise WorkspaceConfigError(f"{path}: not valid YAML — {exc}") from exc

    if not isinstance(raw, dict):
        raise WorkspaceConfigError(f"{path}: expected a mapping at the top level")

    # Reject keys that are planned but inert, by name, before Pydantic reports
    # them as a generic "extra field". An operator who writes `scope:` and
    # believes the engagement boundary is enforced is worse off than one who
    # gets told it is not wired yet.
    for key, why in UNIMPLEMENTED_WORKSPACE_KEYS.items():
        if key in raw:
            raise WorkspaceConfigError(f"{path}: `{key}` is {why}. Remove it to start Chainsmith.")

    try:
        return WorkspaceConfig(**raw)
    except ValidationError as exc:
        raise WorkspaceConfigError(f"{path}: {exc}") from exc


# ── Module-level active workspace ────────────────────────────────
#
# Set once at launch by whichever entry point is running (app.main lifespan or
# the CLI). Runtime switching is deliberately out of scope — see the module
# docstring.

_workspace: Workspace | None = None


def set_workspace(workspace: Workspace) -> Workspace:
    """Install the process-wide workspace. Called once, at launch."""
    global _workspace
    _workspace = workspace
    return workspace


def active() -> Workspace | None:
    """
    Return the installed workspace, or None if no entry point has chosen one.

    Distinct from `get_workspace()`, which falls back to resolving the default.
    Callers that must not *override* an operator's explicit choice use this to
    tell "nobody picked one yet" apart from "the default was picked".
    """
    return _workspace


def get_workspace() -> Workspace:
    """
    Return the active workspace, resolving the default if none was installed.

    The fallback keeps library-style imports (tests, ad-hoc scripts) working
    without an explicit launch step; anything with a real entry point calls
    ``set_workspace`` first.
    """
    global _workspace
    if _workspace is None:
        _workspace, _ = resolve()
    return _workspace


def reset_workspace() -> None:
    """Clear the active workspace. For tests."""
    global _workspace
    _workspace = None
