"""
app/check_launcher.py - Simple Check Execution Engine

Dead simple check execution with dependency resolution.
No scenario logic here — that happens before checks reach the launcher.

Supports on_critical behavior:
- When a check produces a critical observation, the launcher resolves that
  check's on_critical policy (per-check `check.on_critical` from its config.yaml,
  falling back to the legacy suite-level preference only when the check is at the
  default "annotate") and applies it:
    * stop            — halt the whole scan at the next check boundary.
    * skip_downstream — skip the transitive DAG dependents of the critical check
                        (checks whose conditions consume its `produces`).
    * annotate        — (default) mark observations on the same host coming from
                        a later suite; nothing is skipped.
- NOTE: the swarm execution path (app/swarm/) does NOT enforce on_critical yet —
  tracked follow-up; this enforcement lives only in the local CheckLauncher.

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
    from app.gates.guardian import Guardian

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
        guardian: Guardian | None = None,
    ):
        """
        Args:
            checks: List of check instances to run
            context: Shared context dict (modified in place)
            observation_writer: Optional streaming writer for DB persistence
            guardian: Optional scope enforcer — blocks forbidden checks
        """
        self.checks = {c.name: c for c in checks}
        self.context = context
        self.observation_writer = observation_writer
        self.guardian = guardian
        self.completed: set[str] = set()
        self.failed: set[str] = set()
        self.skipped: set[str] = set()
        self.observations: list = []
        self.skip_reasons: dict[str, str] = {}
        self.scan_stopped: bool = False

        # Cooperative pause/stop hooks wired by the runner (optional).
        # pause_event cleared = paused; stop_check() true = abort between checks.
        self.pause_event: Any = None
        self.stop_check: Any = None

        # critical_hosts tracks hosts with critical observations, keyed by host.
        # Each entry is a list of {suite, check_name, observation_title, observation_id}.
        self.critical_hosts: dict[str, list[dict]] = {}

        # on_critical='skip_downstream' targets: check names to skip because an
        # upstream check they (transitively) depend on yielded a critical, mapped
        # to the source check that triggered the skip (for the skip reason).
        self.skip_downstream_targets: dict[str, str] = {}
        # name → set of check names that DIRECTLY depend on it (consume its
        # `produces`). Built once; transitive closure computed on demand.
        self._dependents_map: dict[str, set[str]] = self._build_dependents_map()

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

                if self.pause_event is not None and not self.pause_event.is_set():
                    logger.info("Scan paused — waiting for resume")
                    await self.pause_event.wait()

                if self.stop_check is not None and self.stop_check():
                    logger.info("Scan stop requested — halting at check boundary")
                    self.scan_stopped = True
                    break

                # Guardian gate: check if this check name is forbidden
                if self.guardian:
                    ok, reason = self.guardian.check_technique(check.name)
                    if not ok:
                        logger.info(f"Guardian blocked {check.name}: {reason}")
                        self.skipped.add(check.name)
                        self.skip_reasons[check.name] = f"scope_blocked: {reason}"
                        self.completed.add(check.name)
                        if on_check_complete:
                            on_check_complete(check.name, True, 0)
                        continue

                # Check on_critical skip behavior before running
                skip_reason = self._should_skip_for_critical(check)
                if skip_reason:
                    logger.info(f"Skipping {check.name}: {skip_reason}")
                    self.skipped.add(check.name)
                    self.skip_reasons[check.name] = skip_reason
                    self.completed.add(check.name)  # Mark done so we don't retry
                    if on_check_complete:
                        on_check_complete(check.name, True, 0)
                    continue

                if on_check_start:
                    on_check_start(check.name)

                success, count = await self._run_check(check)

                if on_check_complete:
                    on_check_complete(check.name, success, count)

        # Capture skip reasons for checks that never became runnable
        self._capture_pending_skip_reasons()

        # Final flush of any remaining buffered observations
        if self.observation_writer:
            await self.observation_writer.flush()

        # Store critical_hosts in context for downstream consumers
        self.context["critical_hosts"] = self.critical_hosts

        logger.info(
            f"Completed after {iteration} iterations. {len(self.observations)} total observations."
        )
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
            # Run the check through execute() for timeout protection
            result = await check.execute(self.context)

            # Grading stage. Deliberately here and not inside
            # `execute()`: grading is its own pass over recorded evidence, and
            # the function called here is the same one that will grade a stored
            # corpus offline. Running it before the severity scan below means
            # `on_critical` acts on a graded severity when a grader ran, and on
            # the candidate's provisional one when none did (§6.1).
            from app.grading import grade_result

            await grade_result(check, result, self.context)

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

                # Ensure host is in the dict for downstream use.
                # to_dict() may emit host=None when target_host wasn't set;
                # prefer the extracted host over a None placeholder.
                if host and not obs_dict.get("host"):
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

        except (TimeoutError, ValueError, AttributeError, RuntimeError) as e:
            logger.error(f"  Failed: {name} — {e}")
            self.failed.add(name)
            return (False, 0)

    # ── Skip-reason helpers ──────────────────────────────────────

    def _capture_pending_skip_reasons(self) -> None:
        """Determine and store why each pending check was never runnable."""
        pending = set(self.checks.keys()) - self.completed - self.failed

        for name in pending:
            check = self.checks[name]
            _, missing = self._check_conditions(check)
            check_suite = self._infer_suite(name)

            if missing:
                # Classify: is this a suite-level precondition or a check-level one?
                reason = self._classify_skip_reason(missing, check_suite)
            else:
                reason = "Scan stopped before check could run"

            self.skip_reasons[name] = reason
            self.skipped.add(name)

    def _classify_skip_reason(self, missing: list[str], suite: str) -> str:
        """
        Turn a list of unmet conditions into a human-readable skip reason.

        Heuristics:
        - If the missing condition references a suite's discovery output
          (e.g. 'mcp_servers is truthy'), it means the suite wasn't found.
        - Otherwise it's a generic precondition failure.
        """
        # Map well-known context keys to suite-level "not found" messages
        suite_discovery_keys = {
            "mcp_servers": "MCP",
            "chat_endpoints": "AI",
            "agent_endpoints": "Agent",
            "rag_endpoints": "RAG",
            "cag_endpoints": "CAG",
        }

        for cond_desc in missing:
            for key, suite_label in suite_discovery_keys.items():
                if key in cond_desc:
                    return f"{suite_label} not found on target"

        # Generic precondition message with the actual missing conditions
        if len(missing) == 1:
            return f"Precondition not met: {missing[0]}"
        return f"Preconditions not met: {', '.join(missing)}"

    # ── on_critical helpers ────────────────────────────────────────

    def _record_critical(self, host: str, suite: str, check_name: str, obs_dict: dict) -> None:
        """Record a critical observation and apply the check's on_critical policy."""
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

        # Resolve the policy for THIS check (per-check first, suite preference
        # fallback) and act on it.
        on_critical = self._resolve_check_on_critical(check_name, suite)

        if on_critical == "stop":
            logger.warning(f"on_critical='stop' triggered by {check_name} — halting scan")
            self.scan_stopped = True
        elif on_critical == "skip_downstream":
            dependents = self._transitive_dependents(check_name)
            for dep in dependents:
                # First trigger wins as the recorded source (deterministic).
                self.skip_downstream_targets.setdefault(dep, check_name)
            if dependents:
                logger.warning(
                    f"on_critical='skip_downstream' from {check_name} — "
                    f"will skip {len(dependents)} downstream check(s): {sorted(dependents)}"
                )

    def _should_skip_for_critical(self, check) -> str | None:
        """Return a reason if `check` is a downstream dependent of a check that
        yielded a critical under on_critical='skip_downstream', else None."""
        source = self.skip_downstream_targets.get(check.name)
        if source is None:
            return None
        return (
            f"on_critical='skip_downstream': upstream check '{source}' yielded a "
            f"critical observation"
        )

    def _resolve_check_on_critical(self, check_name: str, suite: str) -> str:
        """Resolve on_critical for a single check.

        Per-check `check.on_critical` (resolved from its config.yaml via the
        ConfigResolver — §5.3) wins. When the check is at the default "annotate",
        fall back to the legacy suite-level preference so existing
        `checks.on_critical_overrides` keep working (back-compat).
        """
        check = self.checks.get(check_name)
        value = (getattr(check, "on_critical", None) or "annotate") if check else "annotate"
        if value != "annotate":
            return value
        return self._resolve_on_critical(suite)

    def _build_dependents_map(self) -> dict[str, set[str]]:
        """Map each check name → the checks that DIRECTLY depend on it.

        A check D depends on producer P when one of D's `conditions` consumes an
        output P declares in `produces` (the same produces/conditions DAG the
        ChainOrchestrator builds). Computed once from the static check list.
        """
        output_producers: dict[str, list[str]] = {}
        for name, check in self.checks.items():
            for output in getattr(check, "produces", None) or []:
                output_producers.setdefault(output, []).append(name)

        dependents: dict[str, set[str]] = {name: set() for name in self.checks}
        for name, check in self.checks.items():
            for cond in getattr(check, "conditions", None) or []:
                for producer in output_producers.get(cond.output_name, []):
                    if producer != name:
                        dependents[producer].add(name)
        return dependents

    def _transitive_dependents(self, start: str) -> set[str]:
        """All checks reachable downstream of `start` in the dependents DAG
        (excludes `start` itself)."""
        seen: set[str] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            for dep in self._dependents_map.get(current, ()):
                if dep not in seen:
                    seen.add(dep)
                    stack.append(dep)
        return seen

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
        except (ImportError, KeyError, AttributeError):
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
