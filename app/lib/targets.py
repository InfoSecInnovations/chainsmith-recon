"""
app/lib/targets.py - Target Resolver

Utilities for parsing, normalizing, and pattern-matching targets.
Handles hostnames, IPs, URLs, wildcard patterns, and scope checks.
"""

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from app.checks.base import Service


@dataclass
class TargetSpec:
    """
    Parsed representation of a raw target string.

    Input may be any of:
        "example.com"
        "http://example.com:8080"
        "10.0.0.1"
        "10.0.0.1:8080"
        "*.example.com"
    """

    raw: str
    host: str
    port: int | None
    scheme: str
    is_wildcard: bool
    is_ip: bool

    @property
    def netloc(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host

    def __str__(self) -> str:
        return self.raw


def parse_target(raw: str) -> TargetSpec:
    """
    Parse a raw target string into a TargetSpec.

    Handles:
    - bare hostnames: "example.com"
    - bare IPs: "10.0.0.1"
    - host:port: "example.com:8080"
    - full URLs: "https://example.com:8080/path"
    - wildcards: "*.example.com"
    """
    raw = raw.strip()

    # If it looks like a URL, use urlparse
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme
    elif "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme or "http"
    else:
        scheme = "http"
        # May have port: "host:8080" or just "host" or wildcard "*.host"
        if raw.startswith("*"):
            host = raw
            port = None
        elif ":" in raw and not raw.startswith("["):  # avoid IPv6
            parts = raw.rsplit(":", 1)
            try:
                port = int(parts[1])
                host = parts[0]
            except ValueError:
                host = raw
                port = None
        else:
            host = raw
            port = None

    is_wildcard = "*" in host
    is_ip = _is_ip(host)

    return TargetSpec(
        raw=raw,
        host=host,
        port=port,
        scheme=scheme,
        is_wildcard=is_wildcard,
        is_ip=is_ip,
    )


def _is_ip(host: str) -> bool:
    """True if host is an IPv4 or IPv6 address."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_matches_pattern(host: str, pattern: str) -> bool:
    """
    Check if a host matches a scope pattern.

    Supports:
    - Exact match:    "example.com" matches "example.com"
    - Wildcard:       "*.example.com" matches "api.example.com"
    - Subdomain:      "example.com" matches "api.example.com" (implicit wildcard)
    - IP:             "10.0.0.1" matches exactly
    """
    host = host.lower().strip()
    pattern = pattern.lower().strip()

    # Direct fnmatch first (handles wildcards and exact matches)
    if fnmatch(host, pattern):
        return True

    # If pattern doesn't start with wildcard, also check if host is a subdomain
    # e.g., "fakobanko.local" should match "www.fakobanko.local"
    return bool(not pattern.startswith("*") and host.endswith("." + pattern))


def url_matches_patterns(url: str, patterns: list[str]) -> bool:
    """
    True if the URL's host matches any pattern in the list.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        return False

    return any(host_matches_pattern(host, p) for p in patterns)


def is_in_scope(
    url: str,
    scope_patterns: list[str],
    excluded_patterns: list[str] = None,
) -> bool:
    """
    Check if a URL is within scope and not excluded.

    Args:
        url:               The URL to check
        scope_patterns:    Allowlist patterns (wildcards ok)
        excluded_patterns: Denylist patterns (wildcards ok)

    Returns:
        True if in scope and not excluded.
        If scope_patterns is empty, everything is in scope.
    """
    if excluded_patterns and url_matches_patterns(url, excluded_patterns):
        return False

    if not scope_patterns:
        return True

    return url_matches_patterns(url, scope_patterns)


def service_from_target(
    host: str,
    port: int,
    scheme: str = "http",
    service_type: str = "unknown",
    metadata: dict | None = None,
) -> Service:
    """
    Construct a Service object from resolved target components.
    """
    url = f"{scheme}://{host}:{port}"
    return Service(
        url=url,
        host=host,
        port=port,
        scheme=scheme,
        service_type=service_type,
        metadata=metadata or {},
    )


def extract_host_from_url(url: str) -> str:
    """Return just the hostname from a URL."""
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def deduplicate_services(services: list[Service]) -> list[Service]:
    """
    Remove duplicate services by (host, port) tuple.
    First occurrence wins.
    """
    seen = set()
    result = []
    for svc in services:
        key = (svc.host, svc.port)
        if key not in seen:
            seen.add(key)
            result.append(svc)
    return result
