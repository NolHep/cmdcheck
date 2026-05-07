"""Postgres connection pool and query helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import asyncpg

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(dsn=os.environ["DATABASE_URL"], min_size=1, max_size=10)
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def run_migrations() -> None:
    migration_dir = Path(__file__).parent.parent / "migrations"
    pool = await get_pool()
    async with pool.acquire() as conn:
        for sql_file in sorted(migration_dir.glob("*.sql")):
            sql = sql_file.read_text()
            await conn.execute(sql)


async def upsert_analysis(slug: str, command: str, result: dict[str, Any]) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO analyses (slug, command, result)
            VALUES ($1, $2, $3::jsonb)
            ON CONFLICT (slug) DO NOTHING
            """,
            slug,
            command,
            json.dumps(result),
        )


async def fetch_analysis(slug: str) -> dict[str, Any] | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT slug, command, result FROM analyses WHERE slug = $1", slug
        )
    if row is None:
        return None
    return {"slug": row["slug"], "command": row["command"], **json.loads(row["result"])}
