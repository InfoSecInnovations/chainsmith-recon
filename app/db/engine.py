"""
app/db/engine.py - SQLAlchemy async engine and session management.

Handles database connection setup, session factory, and schema creation.
"""

import logging
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.models import Base

logger = logging.getLogger(__name__)


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


# ═══════════════════════════════════════════════════════════════════════════════
# Database class — owns engine + session factory, no globals
# ═══════════════════════════════════════════════════════════════════════════════


class Database:
    """Scoped database connection. Create one per app lifetime (or per test)."""

    def __init__(self) -> None:
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    async def init(
        self,
        backend: str = "sqlite",
        db_path: Path = Path("./data/chainsmith.db"),
        postgresql_url: str = "",
    ) -> None:
        """Initialize the engine and create tables if needed."""
        if backend == "sqlite":
            db_path = Path(db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"SQLite database path: {db_path.resolve()}")

        url = _build_url(backend, db_path, postgresql_url)
        self._engine = create_async_engine(
            url,
            echo=False,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database initialized successfully")

    def session(self) -> AsyncSession:
        """Get a new async session. Caller must use ``async with``."""
        if self._session_factory is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        return self._session_factory()

    async def close(self) -> None:
        """Dispose of the engine connection pool."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database connection closed")


# ═══════════════════════════════════════════════════════════════════════════════
# Module-level convenience — thin wrappers over a default Database instance
# ═══════════════════════════════════════════════════════════════════════════════

_default_db = Database()


async def init_db(
    backend: str = "sqlite",
    db_path: Path = Path("./data/chainsmith.db"),
    postgresql_url: str = "",
) -> None:
    """Initialize the default database instance."""
    await _default_db.init(backend=backend, db_path=db_path, postgresql_url=postgresql_url)


def get_session() -> AsyncSession:
    """Get a session from the default database instance."""
    return _default_db.session()


async def close_db() -> None:
    """Close the default database instance."""
    await _default_db.close()
