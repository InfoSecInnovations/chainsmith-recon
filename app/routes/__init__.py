"""
app/routes - API Route Handlers

Organized by functional area:
- scope: Target and scope configuration
- scan: Scan execution and status (active/live)
- scan_history: Historical scan data and comparisons
- observations: Observation retrieval and analysis
- checks: Check metadata
- chains: Attack chain analysis
- scenarios: Scenario management
- preferences: User preferences and profiles
- compliance: Proof of scope and compliance
- customizations: User severity override management
"""

from app.routes.adjudication import router as adjudication_router
from app.routes.advisor import router as advisor_router
from app.routes.chains import router as chains_router
from app.routes.chat import router as chat_router
from app.routes.checks import router as checks_router
from app.routes.compliance import router as compliance_router
from app.routes.customizations import router as customizations_router
from app.routes.engagements import router as engagements_router
from app.routes.observations import router as observations_router
from app.routes.preferences import router as preferences_router
from app.routes.scan import router as scan_router
from app.routes.scan_history import router as scan_history_router
from app.routes.scenarios import router as scenarios_router
from app.routes.scope import router as scope_router
from app.routes.swarm import router as swarm_router

__all__ = [
    "scope_router",
    "scan_router",
    "observations_router",
    "checks_router",
    "chains_router",
    "adjudication_router",
    "scenarios_router",
    "preferences_router",
    "compliance_router",
    "scan_history_router",
    "engagements_router",
    "swarm_router",
    "customizations_router",
    "advisor_router",
    "chat_router",
]
