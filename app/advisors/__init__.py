"""
Advisors — deterministic, rule-based analysis components.

Advisors read results and produce recommendations without LLM calls.
See docs/future-ideas/completed/component-taxonomy.md for the taxonomy.
"""

__all__ = ["CheckProofAdvisor", "ScanAnalysisAdvisor", "ScanPlannerAdvisor"]


def __getattr__(name: str):
    """Lazy import of advisor classes."""
    if name == "CheckProofAdvisor":
        from app.advisors.check_proof import CheckProofAdvisor

        return CheckProofAdvisor
    if name == "ScanAnalysisAdvisor":
        from app.advisors.scan_analysis_advisor import ScanAnalysisAdvisor

        return ScanAnalysisAdvisor
    if name == "ScanPlannerAdvisor":
        from app.advisors.scan_planner_advisor import ScanPlannerAdvisor

        return ScanPlannerAdvisor
    raise AttributeError(f"module 'app.advisors' has no attribute {name!r}")
