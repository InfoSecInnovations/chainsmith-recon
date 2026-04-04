"""
Alembic migration environment for Chainsmith.

Supports both online (async) and offline migration modes.
Reads the database URL from Chainsmith config so migrations
always target the correct database.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.db.models import Base

# Alembic Config object
config = context.config

# Set up loggers from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ORM metadata for autogenerate support
target_metadata = Base.metadata


def _get_url() -> str:
    """Resolve DB URL from Chainsmith config, falling back to alembic.ini."""
    try:
        from app.config import get_config

        cfg = get_config()
        if cfg.storage.backend == "postgresql" and cfg.storage.postgresql_url:
            url = cfg.storage.postgresql_url
            if url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url
        return f"sqlite+aiosqlite:///{cfg.storage.db_path}"
    except Exception:
        return config.get_main_option("sqlalchemy.url", "sqlite+aiosqlite:///./data/chainsmith.db")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generates SQL without connecting)."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with an async engine."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _get_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
