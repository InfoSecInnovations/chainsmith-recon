"""
app/check_resolver.py - Check List Builder

Builds the list of checks to run, handling:
- Real checks (default) — community + custom
- Scenario simulations (override real checks)
- Technique filtering (run only specific checks)

This is separate from execution — it just decides WHAT to run.
The CheckLauncher handles HOW to run them.

Usage:
    from app.check_resolver import resolve_checks

    checks = resolve_checks(
        techniques=["dns_enumeration", "port_scan"],  # Optional filter
        scenario_name="fakobanko"  # Optional scenario
    )
"""

import logging

logger = logging.getLogger(__name__)


def resolve_checks(
    techniques: list[str] | None = None,
    scenario_name: str | None = None,
    check_names: list[str] | None = None,
    suites: list[str] | None = None,
) -> list:
    """
    Build the list of checks to run.

    Args:
        techniques: If provided, only run checks with these names (legacy)
        scenario_name: If provided, load this scenario and use its simulations
        check_names: If provided, only run checks matching these names
        suites: If provided, only run checks belonging to these suites

    Returns:
        List of check instances ready to run
    """
    # Get all real checks
    real_checks = get_real_checks()
    logger.info(f"Real checks available: {len(real_checks)} — {[c.name for c in real_checks]}")

    # If scenario active, merge simulations with real checks
    if scenario_name:
        checks = apply_scenario(real_checks, scenario_name)
    else:
        checks = real_checks

    # Filter by techniques if specified (legacy)
    if techniques:
        checks = filter_by_techniques(checks, techniques)

    # Filter by explicit check names
    if check_names:
        checks = [c for c in checks if c.name in check_names]
        logger.info(f"Filtered to {len(checks)} checks by names: {check_names}")

    # Filter by suites
    if suites:
        checks = filter_by_suites(checks, suites)

    logger.info(f"Final check list: {len(checks)} — {[c.name for c in checks]}")
    return checks


def get_real_checks() -> list:
    """Get all real check instances via auto-discovery.

    Every check now lives in the folder shape (``contract.yaml`` + ``config.yaml``)
    and is discovered by ``component_loader``; the old hand-maintained import list
    is gone (retired in 56.9 once all seven suites were migrated).

    Custom checks are no longer special: ``app/checks/custom/`` is walked by the
    same ``discover_components`` call, so a custom check is just a folder-shape
    component under the ``custom`` suite (C9 — the ``CUSTOM_CHECK_REGISTRY`` tuple
    list + ``_get_custom_checks`` registry path were removed in 56.10d).
    """
    from pathlib import Path

    from app.component_loader import discover_components

    checks = discover_components(Path(__file__).parent / "checks", "check")
    logger.info(f"Total checks available: {len(checks)}")
    return checks


def apply_scenario(real_checks: list, scenario_name: str) -> list:
    """
    Apply scenario simulations to check list.

    Simulations replace real checks with the same name.
    Real checks without a simulation are kept as-is.

    Args:
        real_checks: List of real check instances
        scenario_name: Name of scenario to load

    Returns:
        Hybrid list with simulations where available
    """
    from app.scenarios import ScenarioLoadError, get_scenario_manager

    mgr = get_scenario_manager()

    # Load scenario if not already active
    if not mgr.is_active or mgr.active.name != scenario_name:
        try:
            mgr.load(scenario_name)
            logger.info(f"Loaded scenario: {scenario_name}")
        except ScenarioLoadError as e:
            logger.warning(f"Could not load scenario '{scenario_name}': {e}")
            return real_checks

    # Get simulations
    simulations = mgr.get_simulations()
    sim_by_name = {s.name: s for s in simulations}

    logger.info(
        f"Scenario '{scenario_name}' has {len(simulations)} simulations: {list(sim_by_name.keys())}"
    )

    # Build hybrid list
    result = []
    for check in real_checks:
        if check.name in sim_by_name:
            logger.info(f"  {check.name}: using SIMULATION")
            result.append(sim_by_name[check.name])
        else:
            logger.info(f"  {check.name}: using real check")
            result.append(check)

    return result


def filter_by_techniques(checks: list, techniques: list[str]) -> list:
    """
    Filter checks to only those in the techniques list.

    Args:
        checks: Full list of checks
        techniques: Names of checks to keep

    Returns:
        Filtered list
    """
    filtered = [c for c in checks if c.name in techniques]
    logger.info(f"Filtered to {len(filtered)} checks by techniques: {techniques}")
    return filtered


def filter_by_suites(checks: list, suites: list[str]) -> list:
    """
    Filter checks to only those belonging to the given suites.

    Suite is inferred from the check name since checks don't carry
    an explicit suite attribute.
    """
    filtered = [c for c in checks if infer_suite(c.name) in suites]
    logger.info(f"Filtered to {len(filtered)} checks by suites: {suites}")
    return filtered


# The seven core check suites plus the in-tree `custom` suite (C9). Used by
# infer_suite's prefix split (§14.4); custom checks are named `custom_<name>`.
_SUITE_NAMES = frozenset({"web", "network", "ai", "mcp", "agent", "rag", "cag", "custom"})


def infer_suite(check_name: str) -> str:
    """Infer the suite from a check's ``<suite>_<name>`` prefix (§14.4).

    Phase 56.7 made every check name uniformly suite-prefixed, so the suite is
    simply the first ``_``-delimited token validated against the known suites.
    A name without a known prefix routes to ``"other"``.

    (This replaced the pre-56.7 substring map + the ``_MCP_CHECK_NAMES`` exact-set
    hack, both of which existed only to disambiguate the stripped MCP names and
    the bare legacy names — dead once all suites carry prefixes.)
    """
    prefix = check_name.lower().split("_", 1)[0]
    return prefix if prefix in _SUITE_NAMES else "other"


def get_check_by_name(name: str):
    """Get a single check instance by name."""
    checks = get_real_checks()
    for c in checks:
        if c.name == name:
            return c
    return None


def get_all_check_metadata() -> list:
    """Import-free metadata for ALL checks, INCLUDING disabled ones.

    Unlike `get_real_checks()` (which the loader builds from enabled components
    only), this surfaces disabled checks too so the API/WebUI can show an
    enable/disable toggle. Returns a list of `ComponentMeta`.
    """
    from pathlib import Path

    from app.component_loader import discover_component_metadata

    return discover_component_metadata(Path(__file__).parent / "checks", "check")
