"""Async SQLAlchemy engine and session management."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from redhills_engine.config import get_settings

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return or lazily create the global async engine with optimized pooling."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=300,
            echo=settings.LOG_LEVEL == "DEBUG",
        )
        logger.info(
            "Database engine created with pool_size=20, max_overflow=10"
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return or lazily create the session factory bound to the global engine."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional database session with automatic rollback on error."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        logger.exception("Database session rolled back due to exception")
        raise
    finally:
        await session.close()


async def init_db() -> None:
    """Create all tables from the ORM metadata (development utility)."""
    from redhills_engine.database.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized successfully")


async def shutdown_db() -> None:
    """Dispose the engine connection pool on application shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        logger.info("Database engine disposed")
        _engine = None
        _session_factory = None
