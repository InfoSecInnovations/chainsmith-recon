"""Guard: every simulation YAML emulates a real check and names real hosts (B-9).

`check_resolver.apply_scenario` swaps a simulation in only when its `emulates:`
equals a current check name. After the Phase 56 suite-prefix rename most
simulation YAMLs kept the old bare names and silently never applied. These
tests keep the simulation library in step with the check tree.
"""

from pathlib import Path

import pytest
import yaml

from app.component_loader import discover_component_metadata

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_DIR = REPO_ROOT / "app" / "checks"
GLOBAL_SIM_DIR = CHECKS_DIR / "simulator" / "simulations"
SCENARIOS_DIR = REPO_ROOT / "scenarios"

# Simulations with no matching check, kept rather than deleted. Each entry needs
# a reason; the test below fails once an entry resolves, so the list only shrinks.
KNOWN_UNRESOLVED = {
    # app/checks/mcp/invocation_safety.py is a shared safety helper used by
    # mcp_tool_invocation / mcp_resource_traversal / mcp_template_injection, not a
    # check. mcp_tool_invocation already has its own fakobanko simulation.
    "scenarios/fakobanko/simulations/mcp/mcp_invocation_safety_fakobanko.yaml": "invocation_safety",
}

RETIRED_HOSTS = ("rag.fakobanko.local", "cache.fakobanko.local")


def _simulation_files() -> list[Path]:
    files = sorted(GLOBAL_SIM_DIR.rglob("*.yaml"))
    files += sorted(SCENARIOS_DIR.glob("*/simulations/**/*.yaml"))
    return files


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _is_template(path: Path, emulates: object) -> bool:
    """Templates carry a placeholder `emulates: ""` and are never loaded as-is."""
    return (path.stem.upper() == "TEMPLATE" or "_template" in path.parts) and not emulates


def _emulated_names() -> dict[str, str]:
    out = {}
    for path in _simulation_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        emulates = data.get("emulates")
        if _is_template(path, emulates):
            continue
        out[_rel(path)] = emulates
    return out


def _current_check_names() -> set[str]:
    return {m.name for m in discover_component_metadata(CHECKS_DIR)}


def test_simulation_library_is_found():
    names = _emulated_names()
    assert len(names) > 100, f"expected the simulation library, found {len(names)} files"
    assert len(_current_check_names()) > 100


def test_every_simulation_emulates_a_current_check():
    checks = _current_check_names()
    offenders = sorted(
        f"{path}: emulates {name!r}"
        for path, name in _emulated_names().items()
        if name not in checks and path not in KNOWN_UNRESOLVED
    )
    assert not offenders, (
        f"{len(offenders)} simulation(s) emulate no current check (enabled or "
        "disabled), so apply_scenario will never swap them in. Rename `emulates:` "
        "to the current check name:\n  " + "\n  ".join(offenders)
    )


def test_known_unresolved_entries_are_still_unresolved():
    checks = _current_check_names()
    names = _emulated_names()
    stale = sorted(
        path
        for path, name in KNOWN_UNRESOLVED.items()
        if path not in names or names[path] != name or name in checks
    )
    assert not stale, f"drop these from KNOWN_UNRESOLVED (file gone or now resolves): {stale}"


def test_no_simulation_names_retired_hosts():
    offenders = []
    for path in _simulation_files():
        text = path.read_text(encoding="utf-8")
        for host in RETIRED_HOSTS:
            # Word-boundary check so e.g. secure-rag.fakobanko.local is not a hit.
            idx = text.find(host)
            while idx != -1:
                prev = text[idx - 1] if idx else ""
                if not (prev.isalnum() or prev in ".-"):
                    offenders.append(f"{_rel(path)}: {host}")
                    break
                idx = text.find(host, idx + 1)
    assert not offenders, (
        "simulation YAMLs name retired hosts (use vector.fakobanko.local for RAG, "
        "ml.fakobanko.local for the semantic cache):\n  " + "\n  ".join(sorted(offenders))
    )
