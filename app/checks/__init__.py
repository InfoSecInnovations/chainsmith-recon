"""
Checks Package

Modular reconnaissance check system.

Organized by category:
- network/: DNS enumeration, port scanning, service probing
- web/: HTTP headers, paths, robots.txt, CORS, OpenAPI
- ai/: LLM endpoints, model info, prompt probing, tools, rate limits
- simulator/: Generic SimulatedCheck driven by YAML configs

Usage:
    from app.checks import CheckRunner
    from app.checks.network import DnsEnumerationCheck, ServiceProbeCheck
    from app.checks.web import HeaderAnalysisCheck, PathProbeCheck
    from app.checks.ai import LLMEndpointCheck, ModelInfoCheck
    from app.checks.simulator.simulated_check import load_simulated_check

    runner = CheckRunner(
        scope_domains=["*.example.com"],
        excluded_domains=[],
        parallel=False
    )

    runner.register_check(DnsEnumerationCheck(base_domain="example.com"))
    runner.register_check(ServiceProbeCheck())
    runner.register_check(HeaderAnalysisCheck())

    findings = await runner.run()
"""

from app.checks.base import (
    BaseCheck,
    ServiceIteratingCheck,
    CheckResult,
    CheckCondition,
    CheckStatus,
    Finding,
    Service,
    Severity
)
from app.checks.runner import CheckRunner

__all__ = [
    # Base classes
    "BaseCheck",
    "ServiceIteratingCheck",
    "CheckResult",
    "CheckCondition",
    "CheckStatus",
    "Finding",
    "Service",
    "Severity",
    # Runner
    "CheckRunner",
]
