"""
app/routes - API Route Handlers

Organized by functional area:
- scope: Target and scope configuration
- scan: Scan execution and status
- findings: Finding retrieval and analysis
- checks: Check metadata
- chains: Attack chain analysis
- scenarios: Scenario management
- preferences: User preferences and profiles
- compliance: Proof of scope and compliance
- customizations: User severity override management
"""

from app.routes.scope import router as scope_router
from app.routes.scan import router as scan_router
from app.routes.findings import router as findings_router
from app.routes.checks import router as checks_router
from app.routes.chains import router as chains_router
from app.routes.scenarios import router as scenarios_router
from app.routes.preferences import router as preferences_router
from app.routes.compliance import router as compliance_router
from app.routes.scans import router as scans_router
from app.routes.engagements import router as engagements_router
from app.routes.swarm import router as swarm_router
from app.routes.customizations import router as customizations_router

__all__ = [
    "scope_router",
    "scan_router",
    "findings_router",
    "checks_router",
    "chains_router",
    "scenarios_router",
    "preferences_router",
    "compliance_router",
    "scans_router",
    "engagements_router",
    "swarm_router",
    "customizations_router",
]
