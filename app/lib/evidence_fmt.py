"""
app/lib/evidence_fmt.py - Evidence *strings*, for reports.

The `fmt_*` helpers that turn a check result into the one-line, human-readable
`Observation.evidence` a report prints. Concise enough to read in a report,
specific enough to reproduce the observation.

**Not the evidence corpus.** That is `app/capture`: the verbatim
request/response pair, hashed and stored, from which this string is derived.
This module was `evidence.py` until 57.2 and was renamed to free the name for
the domain that earns it — see the phase doc §8.1. It never did more than
formatting; its unused `EvidenceBundle` was deleted in the same change.
"""

import json
from typing import Any

MAX_EVIDENCE_LENGTH = 1000  # chars; truncated beyond this


def fmt_header_evidence(header_name: str, header_value: str | None) -> str:
    """Format a header observation as evidence string."""
    if header_value is None:
        return f"Header '{header_name}' not present in response"
    return f"Header '{header_name}': {_truncate(header_value)}"


def fmt_status_evidence(url: str, status_code: int, body_preview: str = "") -> str:
    """Format an HTTP status response as evidence."""
    base = f"GET {url} -> HTTP {status_code}"
    if body_preview:
        return f"{base} | {_truncate(body_preview, 200)}"
    return base


def fmt_json_field_evidence(field_path: str, value: Any) -> str:
    """Format a JSON field value as evidence."""
    try:
        value_str = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        value_str = str(value)
    return f"JSON field '{field_path}': {_truncate(value_str)}"


def fmt_cors_evidence(origin_sent: str, acao_header: str | None) -> str:
    """Format a CORS check result as evidence."""
    if acao_header is None:
        return f"Origin: {origin_sent} -> No ACAO header returned"
    return f"Origin: {origin_sent} -> Access-Control-Allow-Origin: {acao_header}"


def fmt_error_evidence(url: str, error_message: str) -> str:
    """Format an error leak as evidence."""
    return f"Error response from {url}: {_truncate(error_message)}"


def fmt_endpoint_evidence(url: str, status_code: int, content_type: str = "") -> str:
    """Format an endpoint discovery result as evidence."""
    parts = [f"Endpoint: {url}", f"Status: {status_code}"]
    if content_type:
        parts.append(f"Content-Type: {content_type}")
    return " | ".join(parts)


def fmt_dns_evidence(hostname: str, ip: str, port: int, service_type: str = "") -> str:
    """Format a DNS discovery result as evidence."""
    parts = [f"Host: {hostname}", f"IP: {ip}", f"Port: {port}"]
    if service_type:
        parts.append(f"Type: {service_type}")
    return " | ".join(parts)


def _truncate(text: str, max_len: int = MAX_EVIDENCE_LENGTH) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"...[+{len(text) - max_len}]"
