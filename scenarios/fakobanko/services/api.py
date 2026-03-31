"""
Fakobanko API Service

Mobile/web API backend.
This is a thin wrapper that imports from the original api.py.
"""

# Import the app from the original location for backward compatibility
from fakobanko.api import app

__all__ = ["app"]
