"""
Fakobanko Services Package

Contains all target services for both standard and range mode.
"""

from scenarios.fakobanko.services.api import app as api_app  # noqa: F401
from scenarios.fakobanko.services.chat import app as chat_app  # noqa: F401
from scenarios.fakobanko.services.www import app as www_app  # noqa: F401

# Range mode services (may not be active)
try:
    from scenarios.fakobanko.services.admin import app as admin_app  # noqa: F401
    from scenarios.fakobanko.services.agent import app as agent_app  # noqa: F401
    from scenarios.fakobanko.services.docs import app as docs_app  # noqa: F401
    from scenarios.fakobanko.services.internal import app as internal_app  # noqa: F401
    from scenarios.fakobanko.services.mcp import app as mcp_app  # noqa: F401
    from scenarios.fakobanko.services.ml import app as ml_app  # noqa: F401
    from scenarios.fakobanko.services.vector import app as vector_app  # noqa: F401
except ImportError:
    pass
