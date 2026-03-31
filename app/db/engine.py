"""
app/db/engine.py - SQLAlchemy async engine and session management.

Handles database connection setup, session factory, and schema creation.
"""

import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.models import Base

logger = logging.getLogger(__name__)

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def _build_url(backend: str, db_path: Path, postgresql_url: str) -> str:
    """Build the SQLAlchemy connection URL from config."""
    if backend == "postgresql" and postgresql_url:
        # Swap postgresql:// for postgresql+asyncpg:// if needed
        url = postgresql_url
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url
    # Default: async SQLite
    return f"sqlite+aiosqlite:///{db_path}"


async def init_db(
    backend: str = "sqlite",
    db_path: Path = Path("./data/chainsmith.db"),
    postgresql_url: str = "",
) -> None:
    """
    Initialize the database engine and create tables if needed.

    Called once at app startup. If the database file or tables don't
    exist, they are created automatically.
    """
    global _engine, _session_factory

    # Ensure parent directory exists for SQLite
    if backend == "sqlite":
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"SQLite database path: {db_path.resolve()}")

    url = _build_url(backend, db_path, postgresql_url)
    _engine = create_async_engine(url, echo=False)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    # Create tables (safe if they already exist)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database initialized successfully")


def get_session() -> AsyncSession:
    """Get a new async database session. Caller must use `async with`."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_factory()


async def close_db() -> None:
    """Dispose of the engine connection pool. Called at app shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database connection closed")
