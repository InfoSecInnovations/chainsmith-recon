"""Check-proof advisor component.

Re-exports the public surface so existing imports
(`from app.advisors.check_proof import CheckProofAdvisor`) and the lazy
`app.advisors` accessor resolve to the same objects.
"""

from app.advisors.check_proof.advisor import (
    CheckProofAdvisor,
    CheckProofAdvisorConfig,
)

__all__ = ["CheckProofAdvisor", "CheckProofAdvisorConfig"]
