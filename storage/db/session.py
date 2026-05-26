from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        raw_url = os.getenv("DATABASE_URL")
        if not raw_url:
            raise RuntimeError("DATABASE_URL is required")
        _session_factory = async_sessionmaker(
            bind=create_async_engine(_normalize_database_url(raw_url), future=True, poolclass=NullPool),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


def AsyncSessionLocal() -> AsyncSession:
    """Lazy wrapper kept for workers that call AsyncSessionLocal() directly."""
    return _get_session_factory()()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _get_session_factory()() as session:
        yield session
