"""
app/engine/scanner.py - Scan Orchestration

Coordinates scans using CheckLauncher and CheckResolver.
Handles state updates and progress callbacks.
"""

import logging
import time
from typing import TYPE_CHECKING

from app.check_launcher import CheckLauncher
from app.check_resolver import get_real_checks, resolve_checks
from app.config import get_config
from app.db.persist import on_scan_complete, on_scan_start
from app.scenarios import get_scenario_manager

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger(__name__)


# ─── Check Registry (for API compatibility) ───────────────────


def get_all_checks() -> list:
    """Get all available real checks. Used by API endpoints."""
    return get_real_checks()


def get_check_info(check) -> dict:
    """Extract metadata from a check instance."""
    from app.check_resolver import infer_suite

    return {
        "name": check.name,
        "description": getattr(check, "description", ""),
        "reason": getattr(check, "reason", ""),
        "references": getattr(check, "references", []),
        "techniques": getattr(check, "techniques", []),
        "conditions": [
            f"{c.output_name} {c.operator}" + (f" {c.value}" if c.value else "")
            for c in getattr(check, "conditions", [])
        ],
        "produces": getattr(check, "produces", []),
        "suite": getattr(check, "suite", None) or infer_suite(check.name),
        "intrusive": getattr(check, "intrusive", False),
    }


# Build AVAILABLE_CHECKS dict for API
AVAILABLE_CHECKS = {}
for _check in get_all_checks():
    AVAILABLE_CHECKS[_check.name] = get_check_info(_check)


# ─── Scan Execution ───────────────────────────────────────────


async def run_scan(
    state: "AppState",
    check_names: list[str] | None = None,
    suites: list[str] | None = None,
    port_profile: str | None = None,
):
    """
    Run web reconnaissance checks with progress tracking.

    Args:
        state: The application state object to update during scan
        check_names: If provided, only run these specific checks
        suites: If provided, only run checks from these suites
        port_profile: Port scan profile override (web, ai, full, lab)
    """
    scan_start_time = time.time()
    scan_id = None
    try:
        logger.info(f"Starting scan against {state.target}")

        # Persist scan start (fire-and-forget on failure)
        scan_id = await on_scan_start(state)

        # Resolve which checks to run
        mgr = get_scenario_manager()
        scenario_name = mgr.active.name if mgr.is_active else None

        checks = resolve_checks(
            techniques=state.techniques if state.techniques else None,
            scenario_name=scenario_name,
            check_names=check_names if check_names else None,
            suites=suites if suites else None,
        )

        if not checks:
            logger.warning("No checks to run!")
            state.status = "complete"
            state.phase = "done"
            return

        # Build initial context
        context = {
            "scope_domains": [state.target],
            "excluded_domains": state.exclude or [],
            "base_domain": state.target,
            "services": [],  # Will be populated by port_scan
        }
        if port_profile:
            context["port_profile"] = port_profile

        # Initialize state tracking
        state.checks_total = len(checks)
        for check in checks:
            state.check_statuses[check.name] = "pending"

        # Define progress callbacks
        def on_start(name: str):
            state.current_check = name
            state.check_statuses[name] = "running"
            state.check_log.append(
                {
                    "check": name,
                    "event": "started",
                }
            )

        def on_complete(name: str, success: bool, findings_count: int):
            state.checks_completed += 1
            state.check_statuses[name] = "completed" if success else "failed"
            state.check_log.append(
                {
                    "check": name,
                    "event": "completed" if success else "failed",
                    "findings": findings_count,
                }
            )

        # Choose execution backend: swarm or local
        cfg = get_config()
        if cfg.swarm.enabled:
            from app.swarm.coordinator import get_coordinator
            from app.swarm.runner import SwarmRunner

            coordinator = get_coordinator()
            coordinator.create_tasks_from_plan(state, checks, context)

            runner = SwarmRunner(checks, context, coordinator)
            state.runner = runner

            findings = await runner.run_all(
                on_check_start=on_start,
                on_check_complete=on_complete,
            )
        else:
            # Standard single-node execution
            launcher = CheckLauncher(checks, context)
            state.runner = launcher

            findings = await launcher.run_all(
                on_check_start=on_start,
                on_check_complete=on_complete,
            )

        # Store findings in state
        state.findings = findings
        state.status = "complete"
        state.phase = "done"
        state.current_check = None

        logger.info(f"Scan complete. {len(findings)} findings.")

        # Run scan advisor if enabled (only for local CheckLauncher, not swarm)
        local_launcher = state.runner if not cfg.swarm.enabled else None
        _run_scan_advisor(state, local_launcher)

        # Persist results to database
        await on_scan_complete(state, scan_id, scan_start_time)

    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        state.status = "error"
        state.error_message = str(e)
        # Still try to persist the error state
        await on_scan_complete(state, scan_id, scan_start_time)


# ─── Scan Advisor ─────────────────────────────────────────────


def _run_scan_advisor(state: "AppState", launcher=None) -> None:
    """
    Run post-scan advisor analysis if enabled.

    Only runs when a local CheckLauncher was used (not swarm mode yet)
    and the advisor is enabled in config.
    """
    try:
        cfg = get_config()
        if not cfg.scan_advisor.enabled:
            return

        if launcher is None:
            logger.info("Scan advisor: skipped (no local launcher — swarm mode?)")
            return

        from app.scan_advisor import (
            ScanAdvisorConfig as AdvisorConfig,
        )
        from app.scan_advisor import (
            build_advisor_from_launcher,
        )

        advisor_cfg = AdvisorConfig(
            enabled=cfg.scan_advisor.enabled,
            mode=cfg.scan_advisor.mode,
            auto_seed_urls=cfg.scan_advisor.auto_seed_urls,
            require_approval=cfg.scan_advisor.require_approval,
        )

        all_checks = get_real_checks()
        advisor = build_advisor_from_launcher(launcher, all_checks, advisor_cfg)
        recommendations = advisor.analyze()

        state.advisor_recommendations = [r.to_dict() for r in recommendations]
        logger.info(f"Scan advisor: {len(recommendations)} recommendations stored")

    except Exception as e:
        logger.warning(f"Scan advisor failed (non-fatal): {e}")


# ─── Verification (placeholder) ───────────────────────────────


async def run_verification(state: "AppState"):
    """
    Run verification on findings.

    Placeholder — currently marks findings as verified without re-testing.
    """
    state.phase = "verifying"
    state.phase = "done"
    state.status = "complete"
