"""
Advisors — deterministic, rule-based analysis components.

Advisors read results and produce recommendations without LLM calls.
See docs/component-taxonomy.md for the taxonomy.
"""

__all__ = ["CheckProofAdvisor", "ScanAnalysisAdvisor", "ScanPlannerAdvisor"]


def __getattr__(name: str):
    """Lazy import of advisor classes."""
    if name == "CheckProofAdvisor":
        from app.advisors.check_proof import CheckProofAdvisor

        return CheckProofAdvisor
    # NOTE: check_proof / scan_analysis / scan_planner are now subpackages
    # (folder shape, 56.11); these lazy imports resolve to their package re-exports.
    if name == "ScanAnalysisAdvisor":
        from app.advisors.scan_analysis import ScanAnalysisAdvisor

        return ScanAnalysisAdvisor
    if name == "ScanPlannerAdvisor":
        from app.advisors.scan_planner import ScanPlannerAdvisor

        return ScanPlannerAdvisor
    raise AttributeError(f"module 'app.advisors' has no attribute {name!r}")
