"""
app/lib/parsing.py - Response Parsing Utilities

Content-type detection, JSON/HTML extraction, and
structured data normalization for check outputs.
"""

import json
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse


def detect_content_type(headers: dict[str, str], body: str) -> str:
    """
    Detect content type from headers, falling back to body sniffing.

    Returns one of: json, html, xml, text, binary, unknown
    """
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break

    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    if "text" in ct:
        return "text"
    if "octet-stream" in ct or "binary" in ct:
        return "binary"

    # Body sniffing fallback
    stripped = body.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if stripped.lower().startswith("<!doctype html") or stripped.lower().startswith("<html"):
        return "html"
    if stripped.startswith("<"):
        return "xml"

    return "unknown"


def safe_json(body: str) -> Optional[Any]:
    """
    Parse JSON body, returning None on failure (no exceptions).
    """
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def extract_headers_dict(raw_headers: dict[str, str]) -> dict[str, str]:
    """
    Normalize headers to lowercase keys.
    """
    return {k.lower(): v for k, v in raw_headers.items()}


def extract_links(html: str, base_url: str) -> list[str]:
    """
    Extract and absolutize all href links from HTML.
    """
    hrefs = re.findall(r'href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE)
    links = []
    for href in hrefs:
        try:
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme in ("http", "https"):
                links.append(absolute)
        except Exception:
            continue
    return list(dict.fromkeys(links))  # deduplicate, preserve order


def extract_paths_from_openapi(spec: dict) -> list[str]:
    """
    Extract all paths from an OpenAPI spec dict.
    """
    return list(spec.get("paths", {}).keys())


def extract_server_header(headers: dict[str, str]) -> Optional[str]:
    """Return the Server header value if present."""
    normalized = extract_headers_dict(headers)
    return normalized.get("server")


def extract_security_headers(headers: dict[str, str]) -> dict[str, Optional[str]]:
    """
    Extract presence/value of common security headers.

    Returns a dict where missing headers have None as value.
    """
    normalized = extract_headers_dict(headers)
    security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
        "cache-control",
    ]
    return {h: normalized.get(h) for h in security_headers}


def extract_cors_headers(headers: dict[str, str]) -> dict[str, Optional[str]]:
    """
    Extract CORS-related response headers.
    """
    normalized = extract_headers_dict(headers)
    cors_headers = [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "access-control-expose-headers",
        "access-control-max-age",
    ]
    return {h: normalized.get(h) for h in cors_headers}


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate text for use in evidence fields."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [{len(text) - max_len} chars truncated]"


def normalize_url(url: str) -> str:
    """Strip trailing slash and normalize scheme."""
    return url.rstrip("/")
