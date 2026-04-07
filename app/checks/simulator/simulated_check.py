"""
app/checks/simulator/simulated_check.py

Generic SimulatedCheck component.

Impersonates any check type based on a YAML config file.
Job control sees it identically to real checks — the only
distinguishing marker is metadata.simulated = True.

Config schema (app/checks/simulator/simulations/<suite>/<name>.yaml):

    suite: network
    emulates: dns_enumeration
    target: "fakobanko.local"
    disposition: hosts_found

    output:
      hosts:
        - name: "www.fakobanko.local"
          ip: "10.0.1.10"
          port: 8082

    behavior:              # optional
      latency_ms: 150
      failure_mode: none   # none | exception | timeout | malformed
      failure_message: "optional error text for failure_mode: exception"
"""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from app.checks.base import BaseCheck, CheckResult, Observation, Service

# ── Config schema ─────────────────────────────────────────────────

VALID_FAILURE_MODES = {"none", "exception", "timeout", "malformed"}


@dataclass
class SimulationBehavior:
    latency_ms: int = 0
    failure_mode: str = "none"
    failure_message: str = "Simulated failure"

    def __post_init__(self):
        if self.failure_mode not in VALID_FAILURE_MODES:
            raise ValueError(
                f"Invalid failure_mode '{self.failure_mode}'. "
                f"Must be one of: {sorted(VALID_FAILURE_MODES)}"
            )


@dataclass
class SimulationConfig:
    suite: str
    emulates: str
    target: str
    disposition: str
    output: dict[str, Any]
    behavior: SimulationBehavior = field(default_factory=SimulationBehavior)

    @classmethod
    def from_dict(cls, data: dict) -> "SimulationConfig":
        """Parse and validate a simulation config dict."""
        required = ["suite", "emulates", "target", "disposition"]
        for field_name in required:
            if field_name not in data:
                raise ValueError(f"Simulation config missing required field: '{field_name}'")

        behavior_data = data.get("behavior", {})
        behavior = SimulationBehavior(
            latency_ms=behavior_data.get("latency_ms", 0),
            failure_mode=behavior_data.get("failure_mode", "none"),
            failure_message=behavior_data.get("failure_message", "Simulated failure"),
        )

        return cls(
            suite=data["suite"],
            emulates=data["emulates"],
            target=data["target"],
            disposition=data["disposition"],
            output=data.get("output", {}),
            behavior=behavior,
        )

    @classmethod
    def from_yaml(cls, path: Path) -> "SimulationConfig":
        """Load and parse a simulation config from a YAML file."""
        if not path.exists():
            raise FileNotFoundError(f"Simulation config not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Simulation config must be a YAML mapping: {path}")

        return cls.from_dict(data)


# ── SimulatedCheck ────────────────────────────────────────────────


class SimulatedCheck(BaseCheck):
    """
    Generic simulation component that impersonates any real check.

    Behavior is entirely driven by a SimulationConfig. No domain logic lives here.

    The job controller sees this as any other check — it reports the same
    suite and check_name as the check it emulates. The only difference is
    metadata.simulated = True in the result.
    """

    # Registry of real check metadata (populated on first use)
    _real_check_registry: dict = None

    @classmethod
    def _get_real_check_registry(cls) -> dict:
        """Lazy-load registry of real check metadata."""
        if cls._real_check_registry is None:
            cls._real_check_registry = {}
            try:
                # Import here to avoid circular imports
                from app.main import get_all_checks

                for check in get_all_checks():
                    cls._real_check_registry[check.name] = {
                        "description": getattr(check, "description", ""),
                        "reason": getattr(check, "reason", ""),
                        "references": getattr(check, "references", []),
                        "techniques": getattr(check, "techniques", []),
                    }
            except ImportError:
                pass  # Fallback to empty registry if import fails
        return cls._real_check_registry

    def __init__(self, config: SimulationConfig):
        super().__init__()
        self._config = config

        # Masquerade as the emulated check
        self.name = config.emulates
        self.suite = config.suite

        # Mark as simulated for API responses
        self._is_simulated = True

        # No conditions — scheduling is the caller's responsibility
        self.conditions = []
        self.produces = []
        self.timeout_seconds = 60.0  # long enough for timeout simulation

        # Inherit educational metadata from the real check we're emulating
        real_check_info = self._get_real_check_registry().get(config.emulates, {})
        self.description = real_check_info.get("description", f"Simulated {config.emulates} check")
        self.reason = real_check_info.get("reason", "Simulated check for testing and demonstration")
        self.references = real_check_info.get("references", [])
        self.techniques = real_check_info.get("techniques", [])

    # ── BaseCheck interface ───────────────────────────────────────

    async def run(self, context: dict[str, Any]) -> CheckResult:
        """
        Execute the simulated check per config.

        Failure modes:
        - none:      Return canned output normally
        - exception: Raise an exception (tests framework error handling)
        - timeout:   Sleep indefinitely (tests framework timeout handling)
        - malformed: Return output that violates expected schema
        """
        config = self._config
        behavior = config.behavior
        started = datetime.now(UTC)

        # Artificial latency
        if behavior.latency_ms > 0:
            await asyncio.sleep(behavior.latency_ms / 1000.0)

        # Failure modes
        if behavior.failure_mode == "exception":
            raise RuntimeError(behavior.failure_message)

        if behavior.failure_mode == "timeout":
            # Sleep indefinitely — the framework's timeout will fire
            await asyncio.sleep(9999)

        # Normal path: build result from config
        result = CheckResult(success=True)
        result.check_name = self.name
        result.started_at = started

        if behavior.failure_mode == "malformed":
            # Intentionally bad output for validation testing
            result.outputs = config.output  # may violate expected schema
            result.outputs["_simulated"] = True
            result.outputs["_malformed"] = True
            return result

        # Normal output
        result.outputs = {**config.output}
        result.outputs["_simulated"] = True
        result.outputs["disposition"] = config.disposition

        # Handle DNS enumeration format (target_hosts + dns_records)
        # DNS checks output hostnames only — no Service creation
        if "target_hosts" in config.output and "dns_records" in config.output:
            target_hosts = config.output.get("target_hosts", [])
            dns_records = config.output.get("dns_records", {})

            for hostname in target_hosts:
                ip = dns_records.get(hostname, hostname)
                result.observations.append(
                    Observation(
                        id=f"{self.name}-{hostname}",
                        title=f"Host discovered: {hostname}",
                        description=f"DNS resolved {hostname} to {ip}",
                        severity="info",
                        evidence=f"Host: {hostname} | IP: {ip}",
                        target=None,
                        target_url=None,
                        check_name=self.name,
                        raw_data={"hostname": hostname, "ip": ip, "simulated": True},
                    )
                )

        # Handle legacy hosts format (for non-DNS checks like port_scan)
        # These checks output Service objects
        elif "hosts" in config.output and isinstance(config.output["hosts"], list):
            for host_entry in config.output["hosts"]:
                if isinstance(host_entry, dict):
                    host = host_entry.get("name", host_entry.get("host", ""))
                    port = int(host_entry.get("port", 80))
                    ip = host_entry.get("ip", host)
                    scheme = host_entry.get("scheme", "http")
                    svc_type = host_entry.get("service_type", host_entry.get("type", "unknown"))

                    svc = Service(
                        url=f"{scheme}://{host}:{port}",
                        host=host,
                        port=port,
                        scheme=scheme,
                        service_type=svc_type,
                        metadata={"ip": ip, "simulated": True},
                    )
                    result.services.append(svc)
                    result.observations.append(
                        Observation(
                            id=f"{self.name}-{host}",
                            title=f"Host discovered: {host}",
                            description=f"Simulated host at {host}:{port}",
                            severity="info",
                            evidence=f"Simulation: {host} -> {ip}:{port} ({svc_type})",
                            target=svc,
                            target_url=svc.url,
                            check_name=self.name,
                            raw_data=host_entry,
                        )
                    )

        # Propagate services to context key
        if result.services:
            result.outputs["services"] = result.services

        return result

    # ── Metadata ──────────────────────────────────────────────────

    @property
    def display_name(self) -> str:
        """Human-readable name with (simulated) suffix."""
        return f"{self.name} (simulated)"

    def to_dict(self) -> dict:
        base = super().to_dict()
        base["simulated"] = True
        base["emulates"] = self._config.emulates
        base["suite"] = self._config.suite
        base["disposition"] = self._config.disposition
        return base


# ── Factory ───────────────────────────────────────────────────────


def load_simulated_check(config_path: Path) -> SimulatedCheck:
    """
    Load a SimulatedCheck from a YAML config file.

    Args:
        config_path: Path to the simulation config YAML

    Returns:
        Configured SimulatedCheck instance

    Raises:
        FileNotFoundError: Config file not found
        ValueError: Config schema validation failure
    """
    config = SimulationConfig.from_yaml(config_path)
    return SimulatedCheck(config)


def load_simulated_checks_from_dir(
    simulations_dir: Path,
    suite: str | None = None,
) -> list[SimulatedCheck]:
    """
    Load all simulation configs from a directory tree.

    Args:
        simulations_dir: Root simulations/ directory
        suite:           If provided, only load configs from this suite subdirectory

    Returns:
        List of SimulatedCheck instances
    """
    checks = []
    search_dir = simulations_dir / suite if suite else simulations_dir

    for yaml_path in sorted(search_dir.rglob("*.yaml")):
        try:
            check = load_simulated_check(yaml_path)
            checks.append(check)
        except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
            # Log but don't abort — bad config shouldn't break the whole suite
            import logging

            logging.getLogger(__name__).warning(
                f"Skipping invalid simulation config {yaml_path}: {e}"
            )

    return checks
