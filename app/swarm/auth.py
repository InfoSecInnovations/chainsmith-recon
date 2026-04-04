"""
app/swarm/auth.py - Swarm API key management and authentication.

Keys are stored as SHA-256 hashes in the swarm_api_keys table.
The raw key is shown once at creation time and never stored.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, Request
from sqlalchemy import delete, select

from app.db.engine import get_session
from app.db.models import SwarmApiKey

logger = logging.getLogger(__name__)


def generate_api_key() -> str:
    """Generate a cryptographically random API key."""
    return secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """SHA-256 hash of a raw API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


async def create_api_key(name: str) -> tuple[str, str]:
    """
    Create a new swarm API key.

    Returns:
        (key_id, raw_key) -- raw_key is shown once and never stored.
    """
    raw_key = generate_api_key()
    key_id = str(uuid.uuid4())
    key_hash = hash_api_key(raw_key)

    async with get_session() as session:
        row = SwarmApiKey(
            id=key_id,
            name=name,
            key_hash=key_hash,
            created_at=datetime.now(UTC),
        )
        session.add(row)
        await session.commit()

    logger.info("Created swarm API key %s (%s)", key_id, name)
    return key_id, raw_key


async def validate_api_key(raw_key: str) -> str | None:
    """
    Validate a raw API key against stored hashes.

    Returns the key_id if valid, None otherwise.
    Also updates last_used_at on the matching row.
    """
    key_hash = hash_api_key(raw_key)

    async with get_session() as session:
        result = await session.execute(select(SwarmApiKey).where(SwarmApiKey.key_hash == key_hash))
        row = result.scalar_one_or_none()
        if row is None:
            return None

        row.last_used_at = datetime.now(UTC)
        await session.commit()
        return row.id


async def revoke_api_key(key_id: str) -> bool:
    """Revoke (delete) a swarm API key. Returns True if a key was deleted."""
    async with get_session() as session:
        result = await session.execute(delete(SwarmApiKey).where(SwarmApiKey.id == key_id))
        await session.commit()
        deleted = result.rowcount > 0

    if deleted:
        logger.info("Revoked swarm API key %s", key_id)
    return deleted


async def list_api_keys() -> list[dict]:
    """List all swarm API keys (metadata only, never the hash)."""
    async with get_session() as session:
        result = await session.execute(select(SwarmApiKey).order_by(SwarmApiKey.created_at.desc()))
        rows = result.scalars().all()
        return [
            {
                "key_id": r.id,
                "name": r.name,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            }
            for r in rows
        ]


# ── FastAPI dependency ───────────────────────────────────────────


async def require_swarm_auth(request: Request) -> str:
    """
    FastAPI dependency that validates the Authorization: Bearer <key> header.

    Returns the key_id on success. Raises 401 on failure.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    raw_key = auth_header[7:]  # strip "Bearer "
    key_id = await validate_api_key(raw_key)
    if key_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return key_id
