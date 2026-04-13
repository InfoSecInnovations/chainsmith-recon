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
from app.db.writers import CheckLogWriter, ObservationWriter
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
    from app.checks.frameworks import parse_all

    refs = getattr(check, "references", [])
    return {
        "name": check.name,
        "description": getattr(check, "description", ""),
        "reason": getattr(check, "reason", ""),
        "references": refs,
        "frameworks": parse_all(refs),
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
    obs_writer = None
    log_writer = None

    # Reset cooperative pause/stop controls for this scan
    state.stop_requested = False
    state.pause_event.set()

    try:
        logger.info(f"Starting scan against {state.target}")

        # Persist scan start (fire-and-forget on failure)
        scan_id = await on_scan_start(state)

        # Store scan_id on state so routes and post-scan phases can find it
        state.active_scan_id = scan_id
        state._last_scan_id = scan_id

        # Create streaming writers if we have a scan_id (persistence enabled)
        if scan_id:
            obs_writer = ObservationWriter(scan_id)
            log_writer = CheckLogWriter(scan_id)

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

        # Seed DNS enumeration wordlist with scenario-declared known_hosts so
        # AI/MCP/Agent/RAG/CAG subdomains (not in the default wordlist) get
        # resolved and enter target_hosts for downstream discovery.
        if mgr.is_active and mgr.active.target.known_hosts:
            from app.checks.network.dns_enumeration import DnsEnumerationCheck

            known = list(mgr.active.target.known_hosts)
            for check in checks:
                if isinstance(check, DnsEnumerationCheck):
                    existing = set(check.wordlist)
                    check.wordlist = check.wordlist + [h for h in known if h not in existing]
                    logger.info(
                        f"Extended DNS wordlist with {len(known)} scenario known_hosts: {known}"
                    )
                    break
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
            if log_writer:
                import asyncio

                asyncio.ensure_future(log_writer.log_event({"check": name, "event": "started"}))

        def on_complete(name: str, success: bool, observations_count: int):
            state.checks_completed += 1
            state.check_statuses[name] = "completed" if success else "failed"
            if log_writer:
                import asyncio

                asyncio.ensure_future(
                    log_writer.log_event(
                        {
                            "check": name,
                            "event": "completed" if success else "failed",
                            "observations": observations_count,
                        }
                    )
                )

        # Wire Guardian as scope_validator on each check (per-URL safety net)
        if state.guardian:
            for check in checks:
                if hasattr(check, "set_scope_validator"):
                    check.set_scope_validator(state.guardian.url_scope_validator)

        # Choose execution backend: swarm or local
        cfg = get_config()
        if cfg.swarm.enabled:
            from app.swarm.coordinator import get_coordinator
            from app.swarm.runner import SwarmRunner

            coordinator = get_coordinator()
            coordinator.create_tasks_from_plan(state, checks, context)
            coordinator.observation_writer = obs_writer

            runner = SwarmRunner(checks, context, coordinator)
            state.runner = runner

            observations = await runner.run_all(
                on_check_start=on_start,
                on_check_complete=on_complete,
            )

            # Final flush for any buffered observations
            if obs_writer:
                await obs_writer.flush()
        else:
            # Standard single-node execution
            launcher = CheckLauncher(
                checks, context, observation_writer=obs_writer, guardian=state.guardian
            )
            launcher.pause_event = state.pause_event
            launcher.stop_check = lambda: state.stop_requested
            state.runner = launcher

            observations = await launcher.run_all(
                on_check_start=on_start,
                on_check_complete=on_complete,
            )

        # Propagate skip reasons from launcher to state
        runner = state.runner
        if hasattr(runner, "skip_reasons"):
            state.skip_reasons = dict(runner.skip_reasons)
            for name, reason in runner.skip_reasons.items():
                if state.check_statuses.get(name) in ("pending", "completed", None):
                    state.check_statuses[name] = "skipped"
                if log_writer:
                    import asyncio

                    asyncio.ensure_future(
                        log_writer.log_event({"check": name, "event": "skipped", "error": reason})
                    )

        if state.stop_requested:
            state.status = "cancelled"
            logger.info(f"Scan cancelled. {len(observations)} observations collected before stop.")
        else:
            state.status = "complete"
            logger.info(f"Scan complete. {len(observations)} observations.")
        state.phase = "done"
        state.current_check = None

        # Notify if writer fell back to scratch space
        if obs_writer and obs_writer.db_failed:
            logger.warning(
                "Some observations were written to scratch space due to DB failure. "
                "Run scratch-to-db to import them."
            )

        # Run scan advisor if enabled (only for local CheckLauncher, not swarm)
        local_launcher = state.runner if not cfg.swarm.enabled else None
        await _run_scan_advisor(state, local_launcher, scan_id)

        # Guided Mode: proactive scan_complete message
        await _emit_scan_complete_proactive(state, len(observations), scan_id)

        # Persist remaining results to database (chains, scan completion)
        await on_scan_complete(state, scan_id, scan_start_time, obs_writer=obs_writer)

    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        state.status = "error"
        state.error_message = str(e)
        # Flush any buffered observations before recording failure
        if obs_writer:
            await obs_writer.flush()
        # Still try to persist the error state
        await on_scan_complete(state, scan_id, scan_start_time, obs_writer=obs_writer)


# ─── Scan Advisor ─────────────────────────────────────────────


async def _run_scan_advisor(state: "AppState", launcher=None, scan_id: str | None = None) -> None:
    """
    Run post-scan advisor analysis if enabled.

    Only runs when a local CheckLauncher was used (not swarm mode yet)
    and the advisor is enabled in config. Persists recommendations to DB.
    """
    try:
        cfg = get_config()
        if not cfg.scan_analysis_advisor.enabled:
            return

        if launcher is None:
            logger.info("Scan advisor: skipped (no local launcher — swarm mode?)")
            return

        from app.advisors.scan_analysis_advisor import (
            ScanAnalysisAdvisorConfig as AdvisorConfig,
        )
        from app.advisors.scan_analysis_advisor import (
            build_analysis_advisor_from_launcher,
        )

        advisor_cfg = AdvisorConfig(
            enabled=cfg.scan_analysis_advisor.enabled,
            mode=cfg.scan_analysis_advisor.mode,
            auto_seed_urls=cfg.scan_analysis_advisor.auto_seed_urls,
            require_approval=cfg.scan_analysis_advisor.require_approval,
        )

        all_checks = get_real_checks()
        advisor = build_analysis_advisor_from_launcher(launcher, all_checks, advisor_cfg)
        recommendations = advisor.analyze()

        recommendation_dicts = [r.to_dict() for r in recommendations]
        logger.info(f"Scan advisor: {len(recommendations)} recommendations")

        # Persist to DB
        if scan_id and recommendation_dicts:
            try:
                from app.db.repositories import AdvisorRepository

                await AdvisorRepository().bulk_create(scan_id, recommendation_dicts)
            except Exception:
                logger.warning("Failed to persist advisor recommendations to DB", exc_info=True)

    except Exception as e:
        logger.warning(f"Scan advisor failed (non-fatal): {e}")


# ─── Guided Mode: proactive scan_complete ─────────────────────


async def _emit_scan_complete_proactive(
    state: "AppState", observation_count: int, scan_id: str | None
) -> None:
    """Push a proactive scan_complete message if Guided Mode is active."""
    try:
        from app.engine.chat import sse_manager
        from app.engine.guided import maybe_emit_proactive
        from app.models import ComponentType

        # Quick-win count from triage if available
        quick_wins = 0
        if scan_id:
            try:
                from app.db.repositories import TriageRepository

                repo = TriageRepository()
                plan = await repo.get_plan(scan_id)
                if plan:
                    actions = await repo.get_actions(plan["id"])
                    quick_wins = sum(1 for a in actions if a.get("effort_estimate") == "low")
            except Exception:
                pass

        text = f"Scan finished. {observation_count} observations discovered."
        if quick_wins:
            text += f" {quick_wins} quick win(s) found — low-effort fixes. Want the action plan?"
        else:
            text += " Want me to show the triage summary?"

        await maybe_emit_proactive(
            sse_manager=sse_manager,
            session_id=state.session_id,
            agent=ComponentType.TRIAGE,
            trigger="scan_complete",
            text=text,
            actions=[
                {
                    "label": "Show action plan",
                    "injected_message": "Show me the triage action plan",
                }
            ],
        )
    except Exception:
        logger.debug("Guided mode proactive scan_complete failed (non-fatal)", exc_info=True)
