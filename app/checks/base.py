"""
Base Check Framework

Production-viable foundation for recon checks with:
- Normalized output schema
- Per-service iteration
- Rate limiting / politeness
- Scope validation hooks
- Educational metadata
- Graceful failure handling
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from app.components.base import BaseComponent
from app.lib.timeutils import now_utc

if TYPE_CHECKING:
    # Imported for typing only: `app.grading` reads `Observation`
    # from here, and a runtime import in both directions would be a cycle.
    from app.grading.models import Candidate

logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Status of a check execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # Conditions not met


class Severity(Enum):
    """Observation severity levels.

    Note: prefer app.models.ObservationSeverity (StrEnum) for new code.
    This Enum is retained for backward compatibility with check-layer code.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Service:
    """
    Normalized representation of a discovered service.

    This is the standard shape passed between checks.
    """

    url: str  # Full URL: http://host:port
    host: str  # Hostname or IP
    port: int  # Port number
    scheme: str = "http"  # http, https
    service_type: str = "unknown"  # http, api, ai, html, tcp, unknown
    metadata: dict = field(default_factory=dict)  # Check-specific extras

    def __post_init__(self):
        # Ensure URL is consistent with components
        if not self.url:
            self.url = f"{self.scheme}://{self.host}:{self.port}"

    def with_path(self, path: str) -> str:
        """Return full URL with path appended."""
        base = self.url.rstrip("/")
        path = path if path.startswith("/") else f"/{path}"
        return f"{base}{path}"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "service_type": self.service_type,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Service":
        return cls(
            url=d.get("url", ""),
            host=d.get("host", ""),
            port=d.get("port", 0),
            scheme=d.get("scheme", "http"),
            service_type=d.get("service_type", "unknown"),
            metadata=d.get("metadata", {}),
        )


@dataclass
class Observation:
    """
    A security-relevant observation from a check.

    Designed to be traceable back to exactly what found it and where.
    """

    id: str  # Assigned by runner (F-001, etc.)
    title: str  # Brief description
    description: str  # Detailed explanation
    severity: str  # info, low, medium, high, critical
    evidence: str  # Raw proof (header value, response snippet)

    # Traceability
    target: Service | None = None  # Which service this was found on
    target_url: str | None = None  # Specific URL (may include path)
    # Canonical host identifier for this observation. Set whenever known,
    # even when target_url is also set — port scans and other network-layer
    # checks have a host before any URL exists.
    target_host: str | None = None
    check_name: str | None = None  # Which check found this

    # Additional context
    raw_data: dict | None = None  # Full raw data for deep inspection
    references: list[str] = field(default_factory=list)  # CVE, OWASP, etc.

    # ── Grading ──────────────────────────────────
    # An Observation is a graded Candidate. Grading state lives here and never
    # on the scan (§6.3): a scan that could not grade something still finishes,
    # and the gap is visible on the observation rather than in a scan status.
    #
    # `severity` above is always the *effective* one — the graded value once a
    # grader has placed it, the provisional one until then. `provisional_severity`
    # keeps the pre-grade value alongside it, so "provisional critical, graded
    # medium" is inspectable rather than a silent overwrite (§6.1).
    provisional_severity: str | None = None
    confidence: float | None = None
    grading_state: str = "ungraded"  # ungraded | graded | grading_failed
    grading_tier: str | None = None  # rule | llm | none
    grading_reasoning: str | None = None
    #: Exchange ids this verdict was derived from — the candidate binding (D-22).
    evidence_ids: list[str] = field(default_factory=list)
    #: Where those bytes came from: corpus (reproducible) | memory | empty.
    evidence_source: str | None = None
    #: What the grader weighed, for the record and for the planned LLM tier's escalation.
    signals: dict | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "target_url": self.target_url,
            "target_host": self.target_host,
            # `host` mirror for downstream consumers (DB repo, viz) that
            # already key on "host". Kept in sync with target_host.
            "host": self.target_host,
            "check_name": self.check_name,
            "references": self.references,
            "provisional_severity": self.provisional_severity,
            "confidence": self.confidence,
            "grading_state": self.grading_state,
            "grading_tier": self.grading_tier,
            "grading_reasoning": self.grading_reasoning,
            "evidence_ids": self.evidence_ids,
            "evidence_source": self.evidence_source,
            "signals": self.signals,
        }


@dataclass
class CheckResult:
    """Normalized output from any check."""

    success: bool

    # Outputs for downstream checks
    outputs: dict[str, Any] = field(default_factory=dict)

    # Services discovered/enriched (for service-discovering checks)
    services: list[Service] = field(default_factory=list)

    # Security observations
    observations: list[Observation] = field(default_factory=list)

    # Ungraded subjects a probe emitted. The grading stage turns
    # these into observations after the check returns; a check written before
    # 57.4 leaves the list empty and is unaffected.
    candidates: list["Candidate"] = field(default_factory=list)

    # Problems encountered (non-fatal)
    errors: list[str] = field(default_factory=list)

    # Metadata
    check_name: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: float | None = None

    # Stats
    targets_checked: int = 0
    targets_failed: int = 0


@dataclass
class CheckCondition:
    """A condition that must be satisfied to run a check."""

    output_name: str  # Name of output from another check
    operator: str = "exists"  # exists, equals, contains, truthy, gte, lte
    value: Any = None  # For comparison operators

    def evaluate(self, context: dict[str, Any]) -> bool:
        """Check if condition is satisfied given current context."""
        if self.output_name not in context:
            return False

        actual = context[self.output_name]

        if self.operator == "exists":
            return actual is not None
        elif self.operator == "truthy":
            return bool(actual)
        elif self.operator == "equals":
            return actual == self.value
        elif self.operator == "contains":
            if isinstance(actual, (list, tuple, set, str, dict)):
                return self.value in actual
            return False
        elif self.operator == "gte":
            return actual >= self.value
        elif self.operator == "lte":
            return actual <= self.value

        return False

    def __str__(self):
        if self.operator == "exists":
            return f"{self.output_name} exists"
        elif self.operator == "truthy":
            return f"{self.output_name} is truthy"
        else:
            return f"{self.output_name} {self.operator} {self.value}"


class BaseCheck(BaseComponent, ABC):
    """
    Base class for all recon checks.

    Subclasses must implement:
    - run(): The actual check logic

    Subclasses should define:
    - name: Unique identifier
    - description: What the check does
    - conditions: When this check should run
    - Educational metadata
    """

    # ─── Identity ───────────────────────────────────────────────
    name: str = "base_check"
    description: str = "Base check - override this"
    component_type: str = "check"  # BaseComponent identity

    # ─── Critical-observation policy (enforced per-check by the
    #     CheckLauncher — stop / skip_downstream / annotate) ──
    on_critical: str = "annotate"
    enabled: bool = True

    # Per-value config provenance (56.16) — filled by from_config from the resolved
    # baseline; empty for checks built bare (e.g. simulations/tests). Read-only.
    config_provenance: dict = {}

    # ─── Conditions ─────────────────────────────────────────────
    conditions: list[CheckCondition] = []

    # ─── Outputs ────────────────────────────────────────────────
    produces: list[str] = []  # What this check adds to context

    # ─── Execution Settings ─────────────────────────────────────
    timeout_seconds: float = 30.0
    retry_count: int = 1
    sequential: bool = True  # If False, can run in parallel with siblings

    # ─── Rate Limiting / Politeness ─────────────────────────────
    requests_per_second: float = 10.0  # Max request rate
    delay_between_targets: float = 0.1  # Pause between services (seconds)

    # ─── Service Filtering ──────────────────────────────────────
    # If set, only run on services matching these types
    service_types: list[str] = []  # e.g., ["http", "api"] - empty = all

    # ─── Intrusiveness ──────────────────────────────────────────
    intrusive: bool = False  # Active probing (writes, injection, auth attempts)

    # ─── Evidence capture ────────────────────
    # How much of what this check sends is recorded: "all", "observations_only"
    # (held until the run finishes, then kept only if it found something), or
    # "none". Set from `config.yaml` by `from_config`; the class default records
    # everything, because a check that should not be in the corpus says so.
    capture: str = "all"

    # ─── Probe / grade ─────────
    # The severity a candidate carries before a grader places one. It is what
    # the launcher reads if grading is deferred or fails, and it is never
    # presented as a verdict.
    #
    # As of 57.4 the authored home is `contract.yaml`'s `severity:` block and
    # `from_config` fills both attributes from it: `severity` is the whole
    # declared block (model, observations, range, rubric, signals) and
    # `provisional_severity` is the single value `create_candidate` falls back
    # to. The class attributes remain the default for a check whose contract
    # has not declared a block yet — the migration is incremental, so both
    # states have to work.
    severity: dict[str, Any] = {}
    provisional_severity: str = "info"

    # ─── Educational Metadata ───────────────────────────────────
    reason: str = ""  # Why a pentester would run this
    references: list[str] = []  # OWASP, RFC, CVE references
    techniques: list[str] = []  # MITRE ATT&CK, methodology tags

    def __init__(self):
        # Copy class-level mutable defaults to prevent cross-instance sharing
        self.conditions = list(self.__class__.conditions)
        self.produces = list(self.__class__.produces)
        self.service_types = list(self.__class__.service_types)
        self.references = list(self.__class__.references)
        self.techniques = list(self.__class__.techniques)
        self.severity = dict(self.__class__.severity)

        self.status = CheckStatus.PENDING
        self.result: CheckResult | None = None
        self._last_request_time: float = 0
        self._scope_validator: Callable[[str], bool] | None = None

    @classmethod
    def from_config(cls, contract, config) -> "BaseCheck":
        """Build a check instance from its parsed contract + resolved config (§6).

        Construction is no-arg (`cls()`), matching how `get_real_checks()`
        instantiates every check today; the load-time config baseline (§5.1
        layers 1-4) is then applied by attribute assignment. Per-scan overrides
        (layer 6) are applied later in the scan path, not here.

        Identity (`id`/`name`) is set authoritatively from the contract so the
        contract.yaml is the single source of truth even if a check class later
        drops its `name` attribute. Execution wiring (`conditions`/`produces`/
        applicability) continues to come from the class attributes — `contract.yaml`
        is the machine-readable mirror the loader/verify/diff read without
        importing, per §6 (from_config applies only the config baseline).

        Args:
            contract: a validated `app.components.contracts.CheckContract`.
            config:   a `app.components.config_models.ResolvedConfig`.
        """
        inst = cls()
        # Identity — authoritative from the contract.
        inst.id = str(contract.id)
        inst.name = contract.name
        inst.component_type = contract.type
        # Severity model — contract, not config (§7). Authored: the block states
        # what compliance means for this check's payload, which is not an
        # operator knob. A contract that has not declared one leaves the class
        # attributes in place, so a half-migrated tree runs.
        declared = getattr(contract, "severity", None)
        if declared is not None:
            inst.severity = declared.model_dump()
            if declared.default:
                inst.provisional_severity = declared.default
        # Load-time config baseline (tunables).
        inst.timeout_seconds = config.timeout_seconds
        inst.requests_per_second = config.requests_per_second
        inst.retry_count = config.retry_count
        inst.delay_between_targets = config.delay_between_targets
        inst.enabled = config.enabled
        inst.on_critical = config.on_critical
        inst.capture = config.capture
        # Per-value layer attribution (56.16) — surfaced read-only by get_check_info.
        inst.config_provenance = dict(config.provenance)
        return inst

    def set_scope_validator(self, validator: Callable[[str], bool]):
        """Set a function to validate URLs against scope."""
        self._scope_validator = validator

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope. Returns True if no validator set."""
        if self._scope_validator is None:
            return True
        return self._scope_validator(url)

    def can_run(self, context: dict[str, Any]) -> bool:
        """Check if all conditions are satisfied."""
        if not self.conditions:
            return True
        return all(cond.evaluate(context) for cond in self.conditions)

    def get_missing_conditions(self, context: dict[str, Any]) -> list[str]:
        """Get list of unsatisfied conditions (for diagnostics)."""
        return [str(cond) for cond in self.conditions if not cond.evaluate(context)]

    def filter_services(self, services: list[Service]) -> list[Service]:
        """Filter services to only those this check should run against."""
        if not self.service_types:
            return services
        return [s for s in services if s.service_type in self.service_types]

    async def _rate_limit(self):
        """Enforce rate limiting between requests."""
        if self.requests_per_second <= 0:
            return

        min_interval = 1.0 / self.requests_per_second
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request_time

        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        self._last_request_time = asyncio.get_event_loop().time()

    async def execute(self, context: dict[str, Any]) -> CheckResult:
        """
        Execute the check with timing, rate limiting, and error handling.
        """
        self.status = CheckStatus.RUNNING
        started = now_utc()

        result = CheckResult(success=False, check_name=self.name, started_at=started)

        # Attribute every exchange this check records. `execute` is
        # the one wrapper every check passes through and it already knows
        # `self.name` — note the loop below that stamps the same name onto
        # finished observations. This is that association made *before* the
        # fact, so a request can be recorded as it happens.
        from app.capture.context import capture_context

        scan_id = context.get("scan_id") or ""
        from app.check_resolver import infer_suite

        try:
            # Run with timeout
            with capture_context(
                scan_id=scan_id,
                check_name=self.name,
                policy=self.capture,
                suite=infer_suite(self.name),
                settings=context.get("capture_settings"),
            ):
                result = await asyncio.wait_for(self.run(context), timeout=self.timeout_seconds)
            result.check_name = self.name
            result.started_at = started
            self.status = CheckStatus.COMPLETED

        except TimeoutError:
            result.errors.append(f"Check timed out after {self.timeout_seconds}s")
            self.status = CheckStatus.FAILED

        except Exception as e:
            result.errors.append(f"Check failed: {str(e)}")
            self.status = CheckStatus.FAILED

        result.completed_at = now_utc()
        result.duration_ms = (result.completed_at - started).total_seconds() * 1000

        # Resolve `capture: observations_only` (D-20). This is the first moment
        # "did the run produce anything" can be answered, which is why the
        # decision lives here rather than in the writer. A check that timed out
        # or raised still gets its buffer resolved on whatever it managed to
        # produce — those exchanges are often the interesting ones.
        from app import capture

        # Candidates count as "the run produced something" (57.3): a migrated
        # check returns candidates and gets its observations from the grading
        # stage afterwards, so keying this on observations alone would throw
        # away the evidence of every check that probe/grade touched.
        capture.commit_check(
            scan_id, self.name, keep=bool(result.observations or result.candidates)
        )

        # Index whatever this check captured. `record()` is synchronous and
        # buffers; this is the async boundary where the buffer can reach the
        # database.
        await capture.flush_index()

        # Tag observations with check name
        for observation in result.observations:
            observation.check_name = self.name

        self.result = result
        return result

    @abstractmethod
    async def run(self, context: dict[str, Any]) -> CheckResult:
        """
        Execute the check logic.

        Args:
            context: Dict containing:
                - services: list[Service] - discovered services
                - Other outputs from previous checks

        Returns:
            CheckResult with success, outputs, services, observations, errors
        """
        pass

    def create_observation(
        self,
        title: str,
        description: str,
        severity: str,
        evidence: str,
        target: Service | None = None,
        target_url: str | None = None,
        host: str | None = None,
        raw_data: dict | None = None,
        references: list[str] | None = None,
    ) -> Observation:
        """Helper to create a properly formatted observation.

        Host precedence: explicit `host=` wins, then
        `target.host` when a Service is passed, then parsed from the
        effective target URL. Network-layer checks that know the host
        before a URL exists should pass `host=` directly.
        """
        effective_url = target_url or (target.url if target else None)
        resolved_host = host
        if resolved_host is None and target is not None:
            if target.host:
                resolved_host = target.host
            else:
                logger.warning(
                    "create_observation: Service target has empty host "
                    "(check=%s, url=%s); target_host will fall back to URL parse",
                    self.name,
                    target.url,
                )
        if resolved_host is None and effective_url:
            parsed = urlparse(effective_url)
            resolved_host = parsed.hostname or None

        return Observation(
            id="",  # Assigned by runner
            title=title,
            description=description,
            severity=severity,
            evidence=evidence,
            target=target,
            target_url=effective_url,
            target_host=resolved_host,
            check_name=self.name,
            raw_data=raw_data,
            references=references or [],
        )

    def provisional_for(self, discriminator: str | None = None) -> str:
        """The severity to assume for one subject before a grader places one.

        This is what §6.1 means by *"for `model: fixed` the provisional severity
        is free"*: the contract's `observations:` map already states what each
        discriminator is worth, so a fixed check's probe names its subject and
        the answer comes out of the contract rather than out of a guess. A
        contextual check has no such map and falls to its declared `default:`,
        which is exactly why `verify_contracts` requires one.
        """
        declared = self.severity or {}
        by_discriminator = declared.get("observations") or {}
        if discriminator and discriminator in by_discriminator:
            return by_discriminator[discriminator]
        return declared.get("default") or self.provisional_severity

    def create_candidate(
        self,
        host: str,
        *,
        discriminator: str | None = None,
        severity: str | None = None,
        target: Service | None = None,
        target_url: str | None = None,
        raw_data: dict | None = None,
    ) -> "Candidate":
        """Helper to create a candidate for the grading stage.

        The probe's half of `create_observation`: it names the subject and the
        severity to assume until a grader places one, and deliberately offers no
        way to state a title, a description or a verdict. Those are the grader's
        to write, from the evidence.

        `severity` is resolved by `provisional_for(discriminator)` when the
        caller does not name one: the contract's `severity.observations` map
        first, then its `default:`, then the class attribute (§6.1, §7).
        """
        from app.grading.models import Candidate

        return Candidate(
            check_name=self.name,
            host=host,
            provisional_severity=severity or self.provisional_for(discriminator),
            discriminator=discriminator,
            target=target,
            target_url=target_url or (target.url if target else None),
            raw_data=raw_data,
        )

    def to_dict(self) -> dict:
        """Serialize check metadata for API/UI."""
        return {
            "name": self.name,
            "description": self.description,
            "conditions": [str(c) for c in self.conditions],
            "produces": self.produces,
            "service_types": self.service_types,
            "timeout_seconds": self.timeout_seconds,
            "sequential": self.sequential,
            "rate_limit": self.requests_per_second,
            "educational": {
                "reason": self.reason,
                "references": self.references,
                "techniques": self.techniques,
            },
            "status": self.status.value if self.status else None,
        }


def merge_service_outputs(into: dict[str, Any], new: dict[str, Any]) -> None:
    """Fold one service's outputs into the check's accumulated outputs (B-3).

    A list output (`chat_endpoints`, `rag_endpoints`, `cag_endpoints`,
    `mcp_servers`, ...) is concatenated across services, skipping entries
    already present, so downstream checks see every service's entries and not
    just the last one's. Before this fix, `dict.update` overwrote the list. Any
    other value keeps the old behaviour: the last service's value wins.
    """
    for key, value in new.items():
        existing = into.get(key)
        if isinstance(existing, list) and isinstance(value, list):
            for item in value:
                if item not in existing:
                    existing.append(item)
        elif isinstance(value, list):
            into[key] = list(value)  # a copy, so later merges never mutate a service's list
        else:
            into[key] = value


class ServiceIteratingCheck(BaseCheck):
    """
    Base class for checks that iterate over multiple services.

    Handles:
    - Filtering services by type
    - Rate limiting between services
    - Graceful per-service failure handling
    - Scope validation per service
    """

    async def run(self, context: dict[str, Any]) -> CheckResult:
        """Run check against each applicable service."""
        result = CheckResult(success=True)

        # Get services from context
        services = context.get("services", [])
        if not services:
            result.errors.append("No services in context")
            return result

        # Convert dicts to Service objects if needed
        services = [Service.from_dict(s) if isinstance(s, dict) else s for s in services]

        # Filter to applicable service types
        applicable = self.filter_services(services)

        if not applicable:
            result.errors.append(f"No services match types: {self.service_types}")
            return result

        result.targets_checked = len(applicable)

        # Process each service
        for service in applicable:
            # Scope check
            if not self.is_in_scope(service.url):
                result.errors.append(f"Out of scope: {service.url}")
                result.targets_failed += 1
                continue

            # Rate limit
            await self._rate_limit()

            # Delay between targets
            if self.delay_between_targets > 0:
                await asyncio.sleep(self.delay_between_targets)

            try:
                # Run check on this service
                service_result = await self.check_service(service, context)

                # Accumulate results
                result.observations.extend(service_result.observations)
                # Candidates accumulate alongside observations (57.3): a probe
                # iterating services emits one per service, and the grading
                # stage sees them all at once after the check returns.
                result.candidates.extend(service_result.candidates)
                result.services.extend(service_result.services)
                merge_service_outputs(result.outputs, service_result.outputs)
                result.errors.extend(service_result.errors)

            except Exception as e:
                result.errors.append(f"{service.url}: {str(e)}")
                result.targets_failed += 1
                continue

        return result

    @abstractmethod
    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        """
        Check a single service. Override this in subclasses.

        Args:
            service: The service to check
            context: Full context (for cross-referencing)

        Returns:
            CheckResult with observations for this service
        """
        pass
