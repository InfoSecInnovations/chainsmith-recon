"""
app/db/engine.py - SQLAlchemy async engine and session management.

Handles database connection setup, session factory, and schema creation.
Includes lightweight column-level migration for SQLite (ALTER TABLE ADD COLUMN).
"""

import logging
from pathlib import Path

from sqlalchemy import inspect, text
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


def _sync_add_missing_columns(connection) -> None:
    """Add columns defined in ORM models but missing from existing tables.

    SQLAlchemy's ``create_all`` creates new tables but never alters existing
    ones. This helper bridges the gap for SQLite by issuing
    ``ALTER TABLE … ADD COLUMN`` for any columns the ORM expects but the
    live schema lacks.  Runs synchronously inside ``conn.run_sync()``.
    """
    inspector = inspect(connection)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue  # create_all will handle it

        existing = {col["name"] for col in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue

            # Build a minimal column definition
            col_type = col.type.compile(connection.dialect)
            nullable = "NULL" if col.nullable else "NOT NULL"
            default = ""
            if col.default is not None and col.default.is_scalar:
                default = f" DEFAULT {col.default.arg!r}"

            stmt = (
                f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {col_type} {nullable}{default}'
            )
            logger.info("Auto-migrating: %s", stmt)
            connection.execute(text(stmt))


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
        self._engine = create_async_engine(url, echo=False)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

        async with self._engine.begin() as conn:
            await conn.run_sync(_sync_add_missing_columns)
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
