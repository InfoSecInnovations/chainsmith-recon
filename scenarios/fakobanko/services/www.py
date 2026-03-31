"""
Fakobanko Main Website Service

Regional bank's public-facing website.
This is a thin wrapper that imports from the original main.py.
"""

# Import the app from the original location for backward compatibility
from fakobanko.main import app

__all__ = ["app"]
