"""
app/lib/observations.py - Observation Builder

Stable observation ID generation and structured observation construction.

ID Format: {check_id}-{host}-{discriminator}
  - check_id:      check name, e.g. "headers"
  - host:          target hostname, e.g. "www.example.com"
  - discriminator: per-check qualifier, e.g. "missing-csp" (optional)

Examples:
  dns-www.example.com
  headers-www.example.com-missing-csp
  headers-www.example.com-missing-hsts
  llm_endpoint-chat.example.com
"""

import hashlib
import re
from datetime import datetime

from app.checks.base import Observation, Service
from app.checks.base import Observation as CheckObservation
from app.models import Observation as ModelObservation
from app.models import ObservationSeverity, ObservationStatus


def _slugify(value: str) -> str:
    """Convert a value to a safe slug for use in observation IDs."""
    value = value.lower().strip()
    # Replace colons and slashes (ports, paths) with dashes
    value = re.sub(r"[:/]", "-", value)
    # Remove any character that isn't alphanumeric, dash, or dot
    value = re.sub(r"[^a-z0-9_\-.]", "", value)
    # Collapse multiple dashes
    value = re.sub(r"-{2,}", "-", value)
    return value.strip("-")


def make_observation_id(
    check_id: str,
    host: str,
    discriminator: str | None = None,
) -> str:
    """
    Generate a stable, human-readable observation ID.

    Args:
        check_id:      The check's name attribute (e.g. "dns_enumeration")
        host:          The target host (e.g. "www.example.com" or "10.0.0.1:8080")
        discriminator: Optional per-observation qualifier (e.g. "missing-csp")

    Returns:
        e.g. "dns_enumeration-www.example.com"
             "headers-www.example.com-missing-csp"
    """
    parts = [_slugify(check_id), _slugify(host)]
    if discriminator:
        parts.append(_slugify(discriminator))
    return "-".join(p for p in parts if p)


def make_observation_id_hashed(
    check_id: str,
    host: str,
    discriminator: str | None = None,
    extra: str | None = None,
) -> str:
    """
    Generate a stable ID with a short hash suffix for high-cardinality observations.

    Useful when discriminators might collide (e.g. many path observations on same host).

    Returns:
        e.g. "paths-www.example.com-admin-a3f2"
    """
    base = make_observation_id(check_id, host, discriminator)
    payload = f"{check_id}:{host}:{discriminator or ''}:{extra or ''}"
    suffix = hashlib.sha256(payload.encode()).hexdigest()[:4]
    return f"{base}-{suffix}"


def build_observation(
    check_name: str,
    title: str,
    description: str,
    severity: str,
    evidence: str,
    host: str,
    discriminator: str | None = None,
    target: Service | None = None,
    target_url: str | None = None,
    raw_data: dict | None = None,
    references: list[str] | None = None,
) -> Observation:
    """
    Construct an Observation with a stable ID.

    Args:
        check_name:    The check's name (used for ID prefix)
        title:         Brief description of the observation
        description:   Detailed explanation
        severity:      info | low | medium | high | critical
        evidence:      Raw proof (header value, response snippet, etc.)
        host:          Target hostname (used for ID)
        discriminator: Optional per-check qualifier for ID uniqueness
        target:        Service object (optional)
        target_url:    Specific URL (optional, falls back to target.url)
        raw_data:      Full raw data dict (optional)
        references:    CVE, OWASP, etc. (optional)

    Returns:
        Observation with stable ID assigned
    """
    observation_id = make_observation_id(check_name, host, discriminator)

    return Observation(
        id=observation_id,
        title=title,
        description=description,
        severity=severity,
        evidence=evidence,
        target=target,
        target_url=target_url or (target.url if target else None),
        check_name=check_name,
        raw_data=raw_data,
        references=references or [],
    )


# ── Observation type conversion ───────────────────────────────────
#
# Two Observation types exist:
#   - app.checks.base.Observation (dataclass) — produced by checks
#   - app.models.Observation (Pydantic)        — used by agents/engine
#
# These functions convert between them.


def check_to_model_observation(obs: CheckObservation) -> ModelObservation:
    """Convert a check-layer Observation (dataclass) to a model-layer Observation (Pydantic)."""
    return ModelObservation(
        id=obs.id,
        observation_type=obs.check_name or "unknown",
        title=obs.title,
        description=obs.description,
        severity=ObservationSeverity(obs.severity),
        status=ObservationStatus.PENDING,
        check_name=obs.check_name,
        discovered_at=datetime.utcnow(),
        target_url=obs.target_url,
        target_service=obs.target.url if obs.target else None,
        evidence_summary=obs.evidence,
        references=obs.references or [],
    )


def model_to_check_observation(obs: ModelObservation) -> CheckObservation:
    """Convert a model-layer Observation (Pydantic) to a check-layer Observation (dataclass)."""
    return CheckObservation(
        id=obs.id,
        title=obs.title,
        description=obs.description,
        severity=str(obs.severity),
        evidence=obs.evidence_summary or "",
        target_url=obs.target_url,
        check_name=obs.check_name,
        references=obs.references or [],
    )


# ── Severity helpers ──────────────────────────────────────────────

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def validate_severity(severity: str) -> str:
    """
    Normalize and validate a severity string.
    Raises ValueError for unrecognized values.
    """
    normalized = severity.lower().strip()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}"
        )
    return normalized
