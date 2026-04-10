"""
Compliance framework badge plugin system.

Usage::

    from app.checks.frameworks import parse_all

    tags = parse_all(check.references)
    # -> [{"framework": "OWASP LLM Top 10", "short_label": "LLM",
    #       "tag_id": "LLM07", "url": "https://...", "badge_color": "#..."}]
"""

from app.checks.frameworks.base import FrameworkTag, parse_all

__all__ = ["FrameworkTag", "parse_all"]
