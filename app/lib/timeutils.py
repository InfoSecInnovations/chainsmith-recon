"""Timezone-aware UTC datetime helpers.

Project rule: all internal datetimes are timezone-aware UTC. Local-time
rendering happens only at display boundaries. Use these helpers instead
of `datetime.utcnow()` or bare `datetime.now()`.
"""

from datetime import UTC, datetime


def now_utc() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def iso_utc(dt: datetime | None = None) -> str:
    """ISO 8601 string with explicit UTC offset (`...+00:00`).

    If `dt` is naive, it is assumed to already be UTC.
    """
    if dt is None:
        dt = now_utc()
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.isoformat()


def parse_iso_utc(s: str) -> datetime:
    """Parse ISO 8601, require an offset, return as UTC.

    Accepts `Z` suffix. Raises ValueError on naive input.
    """
    normalized = s.replace("Z", "+00:00") if s.endswith("Z") else s
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        raise ValueError(f"Datetime string is naive (no offset): {s!r}")
    return dt.astimezone(UTC)
