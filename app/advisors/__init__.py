"""
Advisors — deterministic, rule-based analysis components.

Advisors read results and produce recommendations without LLM calls.
See docs/future-ideas/completed/component-taxonomy.md for the taxonomy.
"""

__all__ = ["CheckProofAdvisor", "ScanAdvisor"]


def __getattr__(name: str):
    """Lazy import of advisor classes."""
    if name == "CheckProofAdvisor":
        from app.advisors.check_proof import CheckProofAdvisor

        return CheckProofAdvisor
    if name == "ScanAdvisor":
        from app.advisors.scan_advisor import ScanAdvisor

        return ScanAdvisor
    raise AttributeError(f"module 'app.advisors' has no attribute {name!r}")
