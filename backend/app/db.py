"""Postgres connection pool and query helpers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import asyncpg

# Load .env from the backend root if present (dev convenience)
_env_file = Path(__file__).parent.parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("DATABASE_URL")
        if not dsn:
            print(
                "\n[cmdcheck] DATABASE_URL is not set.\n"
                "  Create backend/.env with:\n"
                "    DATABASE_URL=postgresql://user:pass@host:5432/dbname\n"
                "  Free Postgres: https://neon.tech\n",
                file=sys.stderr,
            )
            sys.exit(1)
        _pool = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=10)
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
