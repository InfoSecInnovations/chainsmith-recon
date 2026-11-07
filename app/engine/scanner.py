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
from app.gates.guardian import Guardian
from app.scan_overrides import apply_check_overrides
from app.scan_presets import apply_runtime, get_preset, resolve_selection
from app.scan_registry import get_registry
from app.scan_session import ScanSession
from app.scenarios import get_scenario_manager

if TYPE_CHECKING:
    from app.capture.settings import CaptureSettings
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
        # The authored severity model. Contract, not config, so
        # it sits beside `intrusive` rather than inside the `config` block — the
        # WebUI must not offer it as an editable knob.
        "severity": dict(getattr(check, "severity", None) or {}),
        # Resolved tunable config + per-value layer attribution (56.16). Read-only
        # surfacing of the §5.1 load-time baseline; feeds the 56.17 WebUI modal.
        "config": {
            "timeout_seconds": getattr(check, "timeout_seconds", None),
            "requests_per_second": getattr(check, "requests_per_second", None),
            "retry_count": getattr(check, "retry_count", None),
            "delay_between_targets": getattr(check, "delay_between_targets", None),
            "on_critical": getattr(check, "on_critical", None),
            # The evidence-capture policy, resolved the same way.
            "capture": getattr(check, "capture", None),
            "provenance": dict(getattr(check, "config_provenance", {}) or {}),
        },
    }


# Build AVAILABLE_CHECKS dict for API (the display registry behind /api/v1/checks).
AVAILABLE_CHECKS: dict = {}


def rebuild_available_checks() -> dict:
    """Re-discover checks from disk and refresh the AVAILABLE_CHECKS display cache.

    The registry is built once at import; `get_real_checks()` is uncached so a scan
    always sees the current config.yaml, but the display cache is stale after a
    config write (the 56.17 "save as default" endpoint). Calling this rebuilds it
    in place so the WebUI reflects a saved default immediately, no restart.
    """
    AVAILABLE_CHECKS.clear()
    for _check in get_all_checks():
        AVAILABLE_CHECKS[_check.name] = get_check_info(_check)
    return AVAILABLE_CHECKS


rebuild_available_checks()


# ─── Scan Execution ───────────────────────────────────────────


async def run_scan(
    state: "AppState",
    check_names: list[str] | None = None,
    suites: list[str] | None = None,
    port_profile: str | None = None,
    session: "ScanSession | None" = None,
    preset: str | None = None,
    check_overrides: dict | None = None,
    capture: "CaptureSettings | None" = None,
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
    obs_writer = None
    log_writer = None

    try:
        # ── Resolve the session FIRST ────────────────────────────────
        # Everything below reads scope from `session`, never from `state`.
        # `state` is the operator's scope *prep* — a process-global that the
        # next /api/v1/scope call will overwrite, possibly while this scan is
        # still running. Snapshotting it here and then honouring the snapshot
        # is what keeps concurrent scans from reading each other's scope.
        if session is None:
            # No pre-registered session (CLI / direct callers): take the
            # snapshot now. Guardian is built fresh per scan from that scope.
            # state.techniques is the UI allowlist (already applied by
            # resolve_checks) — it must NOT be passed as forbidden_techniques,
            # which is the Guardian's denylist.
            # Minted before the session so the Guardian can be stamped with it
            # (57.2): a violation with no scan id cannot be scoped to a report.
            new_scan_id = uuid.uuid4().hex[:16]
            session = ScanSession(
                id=new_scan_id,
                target=state.target or "",
                exclude=list(state.exclude or []),
                techniques=list(state.techniques or []),
                status="running",
                phase="scanning",
                guardian=Guardian.from_scope(
                    state.target or "",
                    exclude=state.exclude,
                    scan_id=new_scan_id,
                ),
                settings=dict(state.settings),
                proof_settings=(
                    state.proof_settings.model_copy(deep=True)
                    if state.proof_settings is not None
                    else None
                ),
                operator_session_id=state.session_id,
                started_at=scan_start_time,
            )
            get_registry().register(session)
        else:
            # Pre-registered path (route handler): the snapshot was taken at
            # request time. Flip to running; the session id stays the same
            # (registry keyed off it).
            session.status = "running"
            session.phase = "scanning"
            session.started_at = scan_start_time
            if session.guardian is None:
                session.guardian = Guardian.from_scope(
                    session.target,
                    exclude=session.exclude,
                    scan_id=session.id,
                )

        scan_id = session.id
        logger.info(f"Starting scan against {session.target}")

        # Persist scan start (fire-and-forget on failure). The DB row is
        # written from the session, so it records the scope this scan actually
        # ran with rather than whatever scope prep happens to be current.
        await on_scan_start(session, scan_id=scan_id)

        obs_writer = ObservationWriter(scan_id, session=session)
        log_writer = CheckLogWriter(scan_id, session=session)

        # Resolve which checks to run
        mgr = get_scenario_manager()
        scenario_name = mgr.active.name if mgr.is_active else None

        # Layer-6 scan-time selection (§5.1): a preset is the floor; explicit
        # check_names/suites/port_profile passed by the caller win over it.
        preset_obj = get_preset(preset) if preset else None
        if preset and preset_obj is None:
            logger.warning("Unknown scan preset '%s' — ignoring", preset)
        eff_suites, eff_check_names, eff_port_profile = resolve_selection(
            preset_obj,
            suites=suites if suites else None,
            checks=check_names if check_names else None,
            port_profile=port_profile,
        )

        checks = resolve_checks(
            techniques=session.techniques if session.techniques else None,
            scenario_name=scenario_name,
            check_names=eff_check_names,
            suites=eff_suites,
        )

        # Apply the preset's runtime layer (intrusive filter + knob overrides)
        # onto the resolved instances, then the per-check scalpel on top (6b > 6a).
        checks = apply_runtime(preset_obj, checks)
        checks = apply_check_overrides(checks, check_overrides)

        if not checks:
            logger.warning("No checks to run!")
            if session is not None:
                session.phase = "done"
                session.mark_terminal("complete")
            return

        # Build initial context
        context = {
            "scope_domains": [session.target],
            "excluded_domains": session.exclude or [],
            "base_domain": session.target,
            "services": [],  # populated by port_scan
            # BaseCheck.execute() reads these to attribute and
            # gate captured evidence. The scan id already lives on the session;
            # putting it in the context is what makes it reachable from inside a
            # check without every check having to know about ScanSession.
            "scan_id": session.id,
            # The posture travels with the scan rather than sitting in a
            # module-level singleton: concurrent scans share one process, and one
            # scan's --capture must not change what another scan records.
            "capture_settings": capture,
        }
        if capture is not None and capture.enabled:
            logger.info(
                "Evidence capture ON for scan %s (protocols=%s, failures=%s, full=%s)",
                session.id,
                ",".join(sorted(capture.protocols)),
                capture.capture_failures,
                capture.full_capture,
            )

        # Seed DNS enumeration wordlist with scenario-declared known_hosts.
        if mgr.is_active and mgr.active.target.known_hosts:
            from app.checks.network.network_dns_enumeration import DnsEnumerationCheck

            known = list(mgr.active.target.known_hosts)
            for check in checks:
                if isinstance(check, DnsEnumerationCheck):
                    existing = set(check.wordlist)
                    check.wordlist = check.wordlist + [h for h in known if h not in existing]
                    logger.info(
                        f"Extended DNS wordlist with {len(known)} scenario known_hosts: {known}"
                    )
                    break
        if eff_port_profile:
            context["port_profile"] = eff_port_profile

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
        if obs_writer and obs_writer.collisions:
            logger.warning(
                "%d observation(s) repeated an id already stored for this scan and were kept "
                "in scratch space. That is a check minting a duplicate observation id, not a "
                "DB failure; importing them would collide again.",
                obs_writer.collisions,
            )

        # Scan advisor (local CheckLauncher only).
        local_launcher = session.runner if session is not None and not cfg.swarm.enabled else None
        await _run_scan_advisor(local_launcher, scan_id)

        # Guided Mode proactive message.
        await _emit_scan_complete_proactive(state, session, len(observations), scan_id)

        # Final persistence. Drain capture first: `BaseCheck.execute()` indexes
        # what each check recorded, but the agent LLM path and anything else
        # running outside a check has no such boundary of its own.
        from app import capture

        await capture.flush_index()

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
        from app.advisors.registry import get_advisor_registry
        from app.advisors.scan_analysis.advisor import (
            ScanAnalysisAdvisorConfig,
            build_analysis_advisor_from_launcher,
        )

        # `enabled` lives in app/advisors/scan_analysis/config.yaml now (56.11),
        # resolved via the advisor registry — not ChainsmithConfig.
        advisor_cfg = ScanAnalysisAdvisorConfig.from_component_config(
            get_advisor_registry().config("scan_analysis")
        )
        if not advisor_cfg.enabled:
            return

        if launcher is None:
            logger.info("Scan advisor: skipped (no local launcher — swarm mode?)")
            return

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
            session_id=session.operator_session_id or state.session_id,
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
