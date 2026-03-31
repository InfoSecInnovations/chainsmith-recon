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

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Callable
import asyncio


class CheckStatus(Enum):
    """Status of a check execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # Conditions not met


class Severity(Enum):
    """Finding severity levels."""
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
    url: str                          # Full URL: http://host:port
    host: str                         # Hostname or IP
    port: int                         # Port number
    scheme: str = "http"              # http, https
    service_type: str = "unknown"     # http, api, ai, html, tcp, unknown
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
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "Service":
        return cls(
            url=d.get("url", ""),
            host=d.get("host", ""),
            port=d.get("port", 0),
            scheme=d.get("scheme", "http"),
            service_type=d.get("service_type", "unknown"),
            metadata=d.get("metadata", {})
        )


@dataclass
class Finding:
    """
    A security-relevant observation from a check.
    
    Designed to be traceable back to exactly what found it and where.
    """
    id: str                           # Assigned by runner (F-001, etc.)
    title: str                        # Brief description
    description: str                  # Detailed explanation
    severity: str                     # info, low, medium, high, critical
    evidence: str                     # Raw proof (header value, response snippet)
    
    # Traceability
    target: Optional[Service] = None  # Which service this was found on
    target_url: Optional[str] = None  # Specific URL (may include path)
    check_name: Optional[str] = None  # Which check found this
    
    # Additional context
    raw_data: Optional[dict] = None   # Full raw data for deep inspection
    references: list[str] = field(default_factory=list)  # CVE, OWASP, etc.
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "target_url": self.target_url,
            "check_name": self.check_name,
            "references": self.references
        }


@dataclass 
class CheckResult:
    """Normalized output from any check."""
    success: bool
    
    # Outputs for downstream checks
    outputs: dict[str, Any] = field(default_factory=dict)
    
    # Services discovered/enriched (for service-discovering checks)
    services: list[Service] = field(default_factory=list)
    
    # Security findings
    findings: list[Finding] = field(default_factory=list)
    
    # Problems encountered (non-fatal)
    errors: list[str] = field(default_factory=list)
    
    # Metadata
    check_name: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    # Stats
    targets_checked: int = 0
    targets_failed: int = 0


@dataclass
class CheckCondition:
    """A condition that must be satisfied to run a check."""
    output_name: str                  # Name of output from another check
    operator: str = "exists"          # exists, equals, contains, truthy, gte, lte
    value: Any = None                 # For comparison operators
    
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
            if isinstance(actual, (list, tuple, set)):
                return self.value in actual
            elif isinstance(actual, str):
                return self.value in actual
            elif isinstance(actual, dict):
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


class BaseCheck(ABC):
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
    
    # ─── Conditions ─────────────────────────────────────────────
    conditions: list[CheckCondition] = []
    
    # ─── Outputs ────────────────────────────────────────────────
    produces: list[str] = []  # What this check adds to context
    
    # ─── Execution Settings ─────────────────────────────────────
    timeout_seconds: float = 30.0
    retry_count: int = 1
    sequential: bool = True           # If False, can run in parallel with siblings
    
    # ─── Rate Limiting / Politeness ─────────────────────────────
    requests_per_second: float = 10.0  # Max request rate
    delay_between_targets: float = 0.1 # Pause between services (seconds)
    
    # ─── Service Filtering ──────────────────────────────────────
    # If set, only run on services matching these types
    service_types: list[str] = []     # e.g., ["http", "api"] - empty = all
    
    # ─── Intrusiveness ──────────────────────────────────────────
    intrusive: bool = False           # Active probing (writes, injection, auth attempts)

    # ─── Educational Metadata ───────────────────────────────────
    reason: str = ""                  # Why a pentester would run this
    references: list[str] = []        # OWASP, RFC, CVE references
    techniques: list[str] = []        # MITRE ATT&CK, methodology tags
    
    def __init__(self):
        self.status = CheckStatus.PENDING
        self.result: Optional[CheckResult] = None
        self._last_request_time: float = 0
        self._scope_validator: Optional[Callable[[str], bool]] = None
    
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
        started = datetime.utcnow()
        
        result = CheckResult(
            success=False,
            check_name=self.name,
            started_at=started
        )
        
        try:
            # Run with timeout
            result = await asyncio.wait_for(
                self.run(context),
                timeout=self.timeout_seconds
            )
            result.check_name = self.name
            result.started_at = started
            self.status = CheckStatus.COMPLETED
            
        except asyncio.TimeoutError:
            result.errors.append(f"Check timed out after {self.timeout_seconds}s")
            self.status = CheckStatus.FAILED
            
        except Exception as e:
            result.errors.append(f"Check failed: {str(e)}")
            self.status = CheckStatus.FAILED
        
        result.completed_at = datetime.utcnow()
        result.duration_ms = (result.completed_at - started).total_seconds() * 1000
        
        # Tag findings with check name
        for finding in result.findings:
            finding.check_name = self.name
        
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
            CheckResult with success, outputs, services, findings, errors
        """
        pass
    
    def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        evidence: str,
        target: Optional[Service] = None,
        target_url: Optional[str] = None,
        raw_data: Optional[dict] = None,
        references: Optional[list[str]] = None
    ) -> Finding:
        """Helper to create a properly formatted finding."""
        return Finding(
            id="",  # Assigned by runner
            title=title,
            description=description,
            severity=severity,
            evidence=evidence,
            target=target,
            target_url=target_url or (target.url if target else None),
            check_name=self.name,
            raw_data=raw_data,
            references=references or []
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
                "techniques": self.techniques
            },
            "status": self.status.value if self.status else None
        }


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
        services = [
            Service.from_dict(s) if isinstance(s, dict) else s 
            for s in services
        ]
        
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
                result.findings.extend(service_result.findings)
                result.services.extend(service_result.services)
                result.outputs.update(service_result.outputs)
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
            CheckResult with findings for this service
        """
        pass
