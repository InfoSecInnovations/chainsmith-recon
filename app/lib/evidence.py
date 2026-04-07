"""
app/lib/evidence.py - Evidence Collector

Utilities for formatting, truncating, and bundling evidence
that backs up security observations.

Evidence should be:
- Concise enough to read in a report
- Specific enough to reproduce the observation
- Machine-readable for future correlation
"""

import json
from dataclasses import dataclass, field
from typing import Any

MAX_EVIDENCE_LENGTH = 1000  # chars; truncated beyond this


@dataclass
class EvidenceBundle:
    """
    Structured evidence package for a single observation.

    Carries both a human-readable summary and structured raw data
    for downstream processing or replay.
    """

    summary: str  # One-line human-readable evidence
    raw: dict[str, Any] = field(default_factory=dict)  # Full structured data
    snippets: list[str] = field(default_factory=list)  # Key response snippets

    def to_evidence_string(self) -> str:
        """Return the summary for use in Observation.evidence."""
        return self.summary

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "raw": self.raw,
            "snippets": self.snippets,
        }


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


def bundle_http_response(
    url: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
    summary: str | None = None,
) -> EvidenceBundle:
    """
    Create an EvidenceBundle from an HTTP response.
    """
    body_preview = body[:500] if body else ""
    auto_summary = summary or fmt_status_evidence(url, status_code, body_preview)

    return EvidenceBundle(
        summary=auto_summary,
        raw={
            "url": url,
            "status_code": status_code,
            "headers": headers,
            "body_length": len(body),
        },
        snippets=[body_preview] if body_preview else [],
    )


def _truncate(text: str, max_len: int = MAX_EVIDENCE_LENGTH) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"...[+{len(text) - max_len}]"
