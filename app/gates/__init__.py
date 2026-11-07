"""
Gates — deterministic allow/block authorities at the scan chokepoint.

A gate answers "may this proceed?" — scope, scan-window, and forbidden-technique
enforcement — and is the single point where a scan is allowed or blocked
([[project_guardian_gating]]). Gates decide (return allow/block + reason); they
never call an LLM and never merely recommend (that's an advisor).

The `Guardian` is re-exported here so the historical import surface resolves to
the folder-shape component.
"""

__all__ = ["Guardian"]


def __getattr__(name: str):
    """Lazy import of gate classes (avoids importing the entry module at
    package import time, mirroring app/advisors)."""
    if name == "Guardian":
        from app.gates.guardian import Guardian

        return Guardian
    raise AttributeError(f"module 'app.gates' has no attribute {name!r}")
