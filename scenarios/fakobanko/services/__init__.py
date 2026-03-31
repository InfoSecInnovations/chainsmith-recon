"""
Fakobanko Services Package

Contains all target services for both standard and range mode.
"""

from scenarios.fakobanko.services.www import app as www_app
from scenarios.fakobanko.services.chat import app as chat_app
from scenarios.fakobanko.services.api import app as api_app

# Range mode services (may not be active)
try:
    from scenarios.fakobanko.services.docs import app as docs_app
    from scenarios.fakobanko.services.ml import app as ml_app
    from scenarios.fakobanko.services.internal import app as internal_app
    from scenarios.fakobanko.services.admin import app as admin_app
    from scenarios.fakobanko.services.vector import app as vector_app
    from scenarios.fakobanko.services.agent import app as agent_app
    from scenarios.fakobanko.services.mcp import app as mcp_app
except ImportError:
    pass
