"""
app/check_launcher.py - Simple Check Execution Engine

Dead simple check execution with dependency resolution.
No scenario logic here — that happens before checks reach the launcher.

Supports on_critical behavior:
- When a check produces critical observations, the affected hosts are tracked.
- Before running downstream checks, the launcher resolves on_critical for
  that check's suite and applies annotate/skip/stop behavior per host.

Usage:
    from app.check_launcher import CheckLauncher

    launcher = CheckLauncher(checks, context)
    observations = launcher.run_all()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from app.customizations import apply_pre_run_override

if TYPE_CHECKING:
    from app.db.writers import ObservationWriter

logger = logging.getLogger(__name__)


class CheckLauncher:
    """
    Runs checks in dependency order until no more can run.

    Checks declare:
    - conditions: what context values must exist (e.g., "target_hosts is truthy")
    - produces: what context values they output (e.g., "services", "target_hosts")

    The launcher:
    1. Finds checks whose conditions are met
    2. Runs them
    3. Updates context with their outputs
    4. Tracks critical observations per host per suite
    5. Before running a check, applies on_critical behavior
    6. Repeats until nothing can run
    """

    def __init__(
        self,
        checks: list,
        context: dict,
        observation_writer: ObservationWriter | None = None,
    ):
        """
        Args:
            checks: List of check instances to run
            context: Shared context dict (modified in place)
            observation_writer: Optional streaming writer for DB persistence
        """
        self.checks = {c.name: c for c in checks}
        self.context = context
        self.observation_writer = observation_writer
        self.completed: set[str] = set()
        self.failed: set[str] = set()
        self.skipped: set[str] = set()
        self.observations: list = []
        self.scan_stopped: bool = False

        # critical_hosts tracks hosts with critical observations, keyed by host.
        # Each entry is a list of {suite, check_name, observation_title, observation_id}.
        self.critical_hosts: dict[str, list[dict]] = {}

        logger.info("=" * 60)
        logger.info(">>> NEW CHECK_LAUNCHER.PY IS RUNNING <<<")
        logger.info("=" * 60)
        logger.info(f"Checks received ({len(checks)}): {list(self.checks.keys())}")
        logger.info(f"port_scan in checks: {'port_scan' in self.checks}")

    async def run_all(self, on_check_start=None, on_check_complete=None) -> list:
        """
        Run all checks in dependency order.

        Args:
            on_check_start: Optional callback(check_name) before each check
            on_check_complete: Optional callback(check_name, success, observations_count)

        Returns:
            List of all observations from all checks
        """
        iteration = 0
        max_iterations = len(self.checks) + 1  # Safety limit

        while iteration < max_iterations:
            if self.scan_stopped:
                logger.info("Scan stopped due to on_critical='stop' — halting all checks")
                break

            iteration += 1
            logger.info(f"=== Iteration {iteration} ===")
            self._log_context_state()

            runnable = self._get_runnable()
            self._log_check_states(runnable)

            if not runnable:
                logger.info("No runnable checks remaining")
                break

            for check in runnable:
                if self.scan_stopped:
                    break

                # Check on_critical skip behavior before running
                skip_reason = self._should_skip_for_critical(check)
                if skip_reason:
                    logger.info(f"Skipping {check.name}: {skip_reason}")
                    self.skipped.add(check.name)
                    self.completed.add(check.name)  # Mark done so we don't retry
                    if on_check_complete:
                        on_check_complete(check.name, True, 0)
                    continue

                if on_check_start:
                    on_check_start(check.name)

                success, count = await self._run_check(check)

                if on_check_complete:
                    on_check_complete(check.name, success, count)

        # Final flush of any remaining buffered observations
        if self.observation_writer:
            await self.observation_writer.flush()

        # Store critical_hosts in context for downstream consumers
        self.context["critical_hosts"] = self.critical_hosts

        logger.info(f"Completed after {iteration} iterations. {len(self.observations)} total observations.")
        self._log_final_state()

        return self.observations

    def _get_runnable(self) -> list:
        """Get checks that are pending and have all conditions met."""
        runnable = []

        logger.info(f">>> Evaluating {len(self.checks)} checks for runnability")

        for name, check in self.checks.items():
            if name in self.completed or name in self.failed:
                logger.info(f"  {name}: SKIP (already completed/failed)")
                continue

            met, missing = self._check_conditions(check)
            if met:
                logger.info(f"  {name}: RUNNABLE (conditions met)")
                runnable.append(check)
            else:
                logger.info(f"  {name}: BLOCKED by {missing}")

        logger.info(f">>> Runnable this iteration: {[c.name for c in runnable]}")
        return runnable

    def _check_conditions(self, check) -> tuple[bool, list[str]]:
        """
        Check if all conditions are satisfied.

        Returns:
            (all_met: bool, missing: list of unmet condition descriptions)
        """
        missing = []
        conditions = getattr(check, "conditions", [])

        for cond in conditions:
            output_name = cond.output_name
            operator = cond.operator
            value = cond.value

            ctx_value = self.context.get(output_name)

            if operator == "truthy":
                if not ctx_value:
                    missing.append(f"{output_name} is truthy")
            elif operator == "equals":
                if ctx_value != value:
                    missing.append(f"{output_name} equals {value}")
            elif operator == "contains":
                if not ctx_value or value not in ctx_value:
                    missing.append(f"{output_name} contains {value}")
            elif operator == "gte" and (ctx_value is None or ctx_value < value):
                missing.append(f"{output_name} >= {value}")

        return (len(missing) == 0, missing)

    async def _run_check(self, check) -> tuple[bool, int]:
        """
        Execute a single check and update context.

        Returns:
            (success: bool, observations_count: int)
        """
        name = check.name
        logger.info(f"Running: {name}")

        try:
            # Run the check (await since checks are async)
            result = await check.run(self.context)

            self.completed.add(name)

            # Extract outputs and update context
            outputs = getattr(result, "outputs", {}) or {}
            produces = getattr(check, "produces", []) or []

            for key in produces:
                if key in outputs:
                    old_val = self.context.get(key)
                    new_val = outputs[key]
                    self.context[key] = new_val
                    logger.info(
                        f"  Context[{key}] = {self._summarize(new_val)} (was: {self._summarize(old_val)})"
                    )

            # Collect observations and track critical ones
            observations = getattr(result, "observations", []) or []
            check_suite = self._infer_suite(name)

            for obs in observations:
                # Extract host from the original object before dict conversion
                host = self._extract_host(obs)

                if hasattr(obs, "to_dict"):
                    obs_dict = obs.to_dict()
                elif isinstance(obs, dict):
                    obs_dict = obs
                else:
                    obs_dict = {"title": str(obs)}

                # Ensure host is in the dict for downstream use
                if host and "host" not in obs_dict:
                    obs_dict["host"] = host

                # Ensure raw_data dict exists
                if "raw_data" not in obs_dict or obs_dict["raw_data"] is None:
                    raw = getattr(obs, "raw_data", None)
                    obs_dict["raw_data"] = dict(raw) if raw else {}

                # Annotate observation if host has prior critical observations from another suite
                self._annotate_observation_if_needed(obs_dict, check_suite)

                # Apply pre-run severity overrides from user customizations
                apply_pre_run_override(obs_dict)

                self.observations.append(obs_dict)

                # Stream to DB if writer is available
                if self.observation_writer:
                    await self.observation_writer.write(obs_dict)

                # Track critical observations for on_critical behavior
                severity = obs_dict.get("severity", "").lower()
                if severity == "critical" and host:
                    self._record_critical(host, check_suite, name, obs_dict)

            # Flush any buffered observations after each check
            if self.observation_writer:
                await self.observation_writer.flush()

            logger.info(f"  Completed: {name} — {len(observations)} observations")
            return (True, len(observations))

        except Exception as e:
            logger.error(f"  Failed: {name} — {e}")
            self.failed.add(name)
            return (False, 0)

    # ── on_critical helpers ────────────────────────────────────────

    def _record_critical(self, host: str, suite: str, check_name: str, obs_dict: dict) -> None:
        """Record a critical observation for a host."""
        if host not in self.critical_hosts:
            self.critical_hosts[host] = []

        entry = {
            "suite": suite,
            "check_name": check_name,
            "observation_title": obs_dict.get("title", ""),
            "observation_id": obs_dict.get("id", ""),
        }
        self.critical_hosts[host].append(entry)
        logger.info(f"  Critical observation recorded: {host} from {suite}/{check_name}")

        # Check if on_critical for this suite is "stop"
        on_critical = self._resolve_on_critical(suite)
        if on_critical == "stop":
            logger.warning(f"on_critical='stop' triggered by {check_name} — halting scan")
            self.scan_stopped = True

    def _should_skip_for_critical(self, check) -> str | None:
        """
        Check if a check should be skipped due to on_critical='skip_downstream'.

        Only skips if ALL service hosts for this check have critical observations
        from an earlier suite. Returns a reason string if skipping, None otherwise.
        """
        if not self.critical_hosts:
            return None

        check_suite = self._infer_suite(check.name)

        # Find which suites produced critical observations
        critical_suites = set()
        for entries in self.critical_hosts.values():
            for entry in entries:
                critical_suites.add(entry["suite"])

        # Only skip if a DIFFERENT (earlier) suite produced the critical observations
        # and that suite's on_critical is skip_downstream
        for critical_suite in critical_suites:
            if critical_suite == check_suite:
                continue  # Same suite — don't skip
            on_critical = self._resolve_on_critical(critical_suite)
            if on_critical == "skip_downstream":
                # Check if this check's service hosts overlap with critical hosts
                # For simplicity: if ANY critical host exists from an earlier suite,
                # skip this check. More granular per-service filtering happens at
                # the individual check level via annotations.
                return (
                    f"on_critical='skip_downstream' from {critical_suite} suite — "
                    f"critical observations on hosts: {list(self.critical_hosts.keys())}"
                )

        return None

    def _annotate_observation_if_needed(self, obs_dict: dict, check_suite: str) -> None:
        """Annotate an observation if its host has critical observations from an earlier suite."""
        if not self.critical_hosts:
            return

        host = obs_dict.get("host") or ""
        if not host:
            # Try to extract from target
            target = obs_dict.get("target")
            if isinstance(target, dict):
                host = target.get("host", "")

        if host and host in self.critical_hosts:
            # Check if any critical observation is from a different suite
            for entry in self.critical_hosts[host]:
                if entry["suite"] != check_suite:
                    if "raw_data" not in obs_dict or obs_dict["raw_data"] is None:
                        obs_dict["raw_data"] = {}
                    obs_dict["raw_data"]["critical_observation_on_host"] = True
                    obs_dict["raw_data"]["critical_observation_source"] = {
                        "suite": entry["suite"],
                        "check_name": entry["check_name"],
                        "observation_title": entry["observation_title"],
                    }
                    break  # One annotation is enough

    def _resolve_on_critical(self, suite: str) -> str:
        """Resolve the on_critical behavior for a suite using preferences."""
        try:
            from app.preferences import get_preferences, resolve_on_critical

            prefs = get_preferences()
            return resolve_on_critical(prefs, suite)
        except Exception:
            return "annotate"  # Safe default

    def _extract_host(self, obs_obj) -> str | None:
        """Extract host from an observation object or dict."""
        # Try observation object attributes first
        if hasattr(obs_obj, "host"):
            return obs_obj.host
        if hasattr(obs_obj, "target") and obs_obj.target:
            target = obs_obj.target
            if hasattr(target, "host"):
                return target.host

        # Fall back to dict access
        if isinstance(obs_obj, dict):
            host = obs_obj.get("host")
            if host:
                return host
            target = obs_obj.get("target")
            if isinstance(target, dict):
                return target.get("host")
        return None

    @staticmethod
    def _infer_suite(check_name: str) -> str:
        """Infer the suite name from a check name."""
        from app.check_resolver import infer_suite

        return infer_suite(check_name)

    # ── Logging helpers ─────────────────────────────────────────

    def _log_context_state(self):
        """Log current context state."""
        logger.info(f"Context keys: {list(self.context.keys())}")

        # Log key values that checks depend on
        for key in ["target_hosts", "services", "chat_endpoints"]:
            val = self.context.get(key)
            logger.info(f"  {key} = {self._summarize(val)}")

    def _log_check_states(self, runnable: list):
        """Log state of each check."""
        runnable_names = {c.name for c in runnable}

        for name, check in self.checks.items():
            status = (
                "completed"
                if name in self.completed
                else "failed"
                if name in self.failed
                else "pending"
            )
            met, missing = self._check_conditions(check)
            can_run = name in runnable_names

            if status == "pending":
                if can_run:
                    logger.info(f"  {name}: READY to run")
                else:
                    logger.info(f"  {name}: waiting on {missing}")

    def _log_final_state(self):
        """Log final state summary."""
        pending = set(self.checks.keys()) - self.completed - self.failed

        logger.info("Final state:")
        logger.info(f"  Completed: {len(self.completed)} — {sorted(self.completed)}")
        logger.info(f"  Skipped (on_critical): {len(self.skipped)} — {sorted(self.skipped)}")
        logger.info(f"  Failed: {len(self.failed)} — {sorted(self.failed)}")
        logger.info(f"  Pending: {len(pending)} — {sorted(pending)}")

        if self.critical_hosts:
            logger.info(f"  Critical hosts: {list(self.critical_hosts.keys())}")

        if pending:
            logger.info("Pending checks could not run due to unmet conditions:")
            for name in sorted(pending):
                check = self.checks[name]
                _, missing = self._check_conditions(check)
                logger.info(f"    {name}: needs {missing}")

    def _summarize(self, val: Any, max_len: int = 60) -> str:
        """Summarize a value for logging."""
        if val is None:
            return "None"
        if isinstance(val, list):
            return f"[{len(val)} items]"
        if isinstance(val, dict):
            return f"{{{len(val)} keys}}"
        s = str(val)
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s
