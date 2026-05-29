from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import MissingGreenlet
from sqlalchemy.ext.asyncio import create_async_engine

ROOT_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = ROOT_DIR / "alembic.ini"
DEFAULT_TEST_DATABASE_URL = "postgresql+asyncpg://proofscan:proofscan@localhost:5432/proofscan_test"
REQUIRED_TABLES = {"scans", "findings", "proof_artifacts", "attack_tasks", "runners"}


def _sync_url(database_url: str, database: str | None = None) -> URL:
    url = make_url(database_url)
    drivername = url.drivername.split("+", maxsplit=1)[0]
    return url.set(drivername=drivername, database=database if database is not None else url.database)


def _async_url(database_url: str, database: str | None = None) -> URL:
    url = make_url(database_url)
    drivername = url.drivername
    if "+" not in drivername:
        drivername = f"{drivername}+asyncpg"
    return url.set(drivername=drivername, database=database if database is not None else url.database)


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _drop_connections_statement() -> str:
    return """
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = :database_name
          AND pid <> pg_backend_pid()
        """


def _recreate_database_sync(database_url: str, database_name: str, quoted_database: str) -> bool:
    try:
        admin_engine = create_engine(_sync_url(database_url, "postgres"), isolation_level="AUTOCOMMIT")
    except ModuleNotFoundError:
        return False

    try:
        with admin_engine.connect() as connection:
            connection.execute(text(_drop_connections_statement()), {"database_name": database_name})
            connection.execute(text(f"DROP DATABASE IF EXISTS {quoted_database}"))
            connection.execute(text(f"CREATE DATABASE {quoted_database}"))
    except (MissingGreenlet, ModuleNotFoundError):
        return False
    finally:
        admin_engine.dispose()

    return True


def _drop_database_sync(database_url: str, database_name: str, quoted_database: str) -> bool:
    try:
        admin_engine = create_engine(_sync_url(database_url, "postgres"), isolation_level="AUTOCOMMIT")
    except ModuleNotFoundError:
        return False

    try:
        with admin_engine.connect() as connection:
            connection.execute(text(_drop_connections_statement()), {"database_name": database_name})
            connection.execute(text(f"DROP DATABASE IF EXISTS {quoted_database}"))
    except (MissingGreenlet, ModuleNotFoundError):
        return False
    finally:
        admin_engine.dispose()

    return True


async def _recreate_database_async(database_url: str, database_name: str, quoted_database: str) -> None:
    admin_engine = create_async_engine(_async_url(database_url, "postgres"), isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as connection:
            await connection.execute(text(_drop_connections_statement()), {"database_name": database_name})
            await connection.execute(text(f"DROP DATABASE IF EXISTS {quoted_database}"))
            await connection.execute(text(f"CREATE DATABASE {quoted_database}"))
    finally:
        await admin_engine.dispose()


async def _drop_database_async(database_url: str, database_name: str, quoted_database: str) -> None:
    admin_engine = create_async_engine(_async_url(database_url, "postgres"), isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as connection:
            await connection.execute(text(_drop_connections_statement()), {"database_name": database_name})
            await connection.execute(text(f"DROP DATABASE IF EXISTS {quoted_database}"))
    finally:
        await admin_engine.dispose()


@pytest.fixture
def fresh_database_url() -> Iterator[str]:
    database_url = os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)
    test_url = make_url(database_url)
    if not test_url.database:
        raise RuntimeError("TEST_DATABASE_URL must include a database name")
    quoted_database = _quote_identifier(test_url.database)

    if not _recreate_database_sync(database_url, test_url.database, quoted_database):
        asyncio.run(_recreate_database_async(database_url, test_url.database, quoted_database))

    try:
        yield database_url
    finally:
        if not _drop_database_sync(database_url, test_url.database, quoted_database):
            asyncio.run(_drop_database_async(database_url, test_url.database, quoted_database))


@pytest.mark.asyncio
async def test_alembic_upgrade_head_on_fresh_database(fresh_database_url: str) -> None:
    env = os.environ.copy()
    env["DATABASE_URL"] = fresh_database_url

    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head"],
        cwd=ROOT_DIR,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    engine = create_async_engine(fresh_database_url)
    try:
        async with engine.connect() as connection:
            table_names = await connection.run_sync(
                lambda sync_connection: set(inspect(sync_connection).get_table_names())
            )
    finally:
        await engine.dispose()

    assert REQUIRED_TABLES <= table_names
