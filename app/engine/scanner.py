"""
app/engine/scanner.py - Scan Orchestration

Coordinates scans using CheckLauncher and CheckResolver. In Phase B of the
concurrent-scans overhaul, run_scan creates a ScanSession and drives all
per-scan state through it. `state` is still the entry point (operator
scope prep), but no per-scan fields live there anymore.
"""

import logging
import time
import uuid
from typing import TYPE_CHECKING

from app.check_launcher import CheckLauncher
from app.check_resolver import get_real_checks, resolve_checks
from app.config import get_config
from app.db.persist import on_scan_complete, on_scan_start
from app.db.writers import CheckLogWriter, ObservationWriter
from app.guardian import Guardian
from app.scan_registry import get_registry
from app.scan_session import ScanSession
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
    session: "ScanSession | None" = None,
):
    """
    Run web reconnaissance checks with progress tracking.

    `state` supplies operator scope prep (target, exclude, techniques,
    settings, proof_settings, session_id). Per-scan runtime state lives
    on a ScanSession. If the caller pre-registered one (route handler
    pre-registration so the scan_id is returned synchronously), we flip
    its status from "queued" to "running"; otherwise we create one here.
    """
    scan_start_time = time.time()
    scan_id = session.id if session is not None else None
    obs_writer = None
    log_writer = None

    try:
        logger.info(f"Starting scan against {state.target}")

        # Persist scan start (fire-and-forget on failure). If the route
        # pre-registered the session, reuse that id so the DB row matches.
        preregistered_id = scan_id
        scan_id = await on_scan_start(state, scan_id=preregistered_id)
        if not scan_id:
            # Persistence disabled or DB write failed. Keep the pre-registered
            # id if we have one (so the already-in-registry session stays
            # addressable); otherwise mint a fresh one.
            scan_id = preregistered_id or uuid.uuid4().hex[:16]

        # Construct and register the session if the caller didn't. Guardian
        # is built fresh per scan from the operator's scope prep.
        # state.techniques is the UI allowlist (already applied by
        # resolve_checks) — it must NOT be passed as forbidden_techniques,
        # which is the Guardian's denylist.
        if session is None:
            guardian = Guardian.from_scope(
                state.target or "",
                exclude=state.exclude,
            )
            session = ScanSession(
                id=scan_id,
                target=state.target or "",
                exclude=list(state.exclude or []),
                techniques=list(state.techniques or []),
                status="running",
                phase="scanning",
                guardian=guardian,
                settings=dict(state.settings),
                proof_settings=state.proof_settings,
                started_at=scan_start_time,
            )
            get_registry().register(session)
        else:
            # Pre-registered path: flip to running and align start time
            # with the DB row on_scan_start just wrote. The session id
            # stays the same (registry keyed off it).
            session.status = "running"
            session.phase = "scanning"
            session.started_at = scan_start_time
            if session.guardian is None:
                session.guardian = Guardian.from_scope(
                    state.target or "",
                    exclude=state.exclude,
                )

        obs_writer = ObservationWriter(scan_id, session=session)
        log_writer = CheckLogWriter(scan_id, session=session)

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
            if session is not None:
                session.phase = "done"
                session.mark_terminal("complete")
            return

        # Build initial context
        context = {
            "scope_domains": [state.target],
            "excluded_domains": state.exclude or [],
            "base_domain": state.target,
            "services": [],  # populated by port_scan
        }

        # Seed DNS enumeration wordlist with scenario-declared known_hosts.
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

        # Initialize session progress tracking
        if session is not None:
            session.checks_total = len(checks)
            for check in checks:
                session.check_statuses[check.name] = "pending"

        # Progress callbacks write to the session.
        def on_start(name: str):
            if session is not None:
                session.current_check = name
                session.check_statuses[name] = "running"
            if log_writer:
                import asyncio

                asyncio.ensure_future(log_writer.log_event({"check": name, "event": "started"}))

        def on_complete(name: str, success: bool, observations_count: int):
            if session is not None:
                session.checks_completed += 1
                session.check_statuses[name] = "completed" if success else "failed"
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

        # Wire Guardian as scope_validator on each check.
        if session is not None and session.guardian:
            for check in checks:
                if hasattr(check, "set_scope_validator"):
                    check.set_scope_validator(session.guardian.url_scope_validator)

        # Choose execution backend
        cfg = get_config()
        if cfg.swarm.enabled:
            from app.swarm.coordinator import get_coordinator
            from app.swarm.runner import SwarmRunner

            coordinator = get_coordinator()
            coordinator.create_tasks_from_plan(session, checks, context)
            coordinator.observation_writer = obs_writer

            runner = SwarmRunner(checks, context, coordinator)
            if session is not None:
                session.runner = runner

            observations = await runner.run_all(
                on_check_start=on_start,
                on_check_complete=on_complete,
            )

            if obs_writer:
                await obs_writer.flush()
        else:
            launcher = CheckLauncher(
                checks,
                context,
                observation_writer=obs_writer,
                guardian=session.guardian if session is not None else None,
            )
            if session is not None:
                launcher.pause_event = session.pause_event
                launcher.stop_check = lambda: session.stop_requested
                session.runner = launcher

            observations = await launcher.run_all(
                on_check_start=on_start,
                on_check_complete=on_complete,
            )

        # Propagate skip reasons from runner to session.
        runner_obj = session.runner if session is not None else None
        if runner_obj is not None and hasattr(runner_obj, "skip_reasons") and session is not None:
            session.skip_reasons = dict(runner_obj.skip_reasons)
            for name, reason in runner_obj.skip_reasons.items():
                if session.check_statuses.get(name) in ("pending", "completed", None):
                    session.check_statuses[name] = "skipped"
                if log_writer:
                    import asyncio

                    asyncio.ensure_future(
                        log_writer.log_event({"check": name, "event": "skipped", "error": reason})
                    )

        if session is not None:
            final_status = "cancelled" if session.stop_requested else "complete"
            if session.stop_requested:
                logger.info(
                    f"Scan cancelled. {len(observations)} observations collected before stop."
                )
            else:
                logger.info(f"Scan complete. {len(observations)} observations.")
            session.phase = "done"
            session.current_check = None
            session.mark_terminal(final_status)

        if obs_writer and obs_writer.db_failed:
            logger.warning(
                "Some observations were written to scratch space due to DB failure. "
                "Run scratch-to-db to import them."
            )

        # Scan advisor (local CheckLauncher only).
        local_launcher = session.runner if session is not None and not cfg.swarm.enabled else None
        await _run_scan_advisor(local_launcher, scan_id)

        # Guided Mode proactive message.
        await _emit_scan_complete_proactive(state, session, len(observations), scan_id)

        # Final persistence.
        await on_scan_complete(session, scan_id, scan_start_time, obs_writer=obs_writer)

    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        if session is not None:
            session.mark_terminal("error", error_message=str(e))
        if obs_writer:
            await obs_writer.flush()
        await on_scan_complete(session, scan_id, scan_start_time, obs_writer=obs_writer)


# ─── Scan Advisor ─────────────────────────────────────────────


async def _run_scan_advisor(launcher=None, scan_id: str | None = None) -> None:
    """Run post-scan advisor analysis if enabled."""
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
    state: "AppState",
    session: ScanSession | None,
    observation_count: int,
    scan_id: str | None,
) -> None:
    """Push a proactive scan_complete message if Guided Mode is active."""
    try:
        from app.engine.chat import sse_manager
        from app.engine.guided import maybe_emit_proactive
        from app.models import ComponentType

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
            scan_id=scan_id,
        )
    except Exception:
        logger.debug("Guided mode proactive scan_complete failed (non-fatal)", exc_info=True)
