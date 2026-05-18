"""pytest configuration and shared fixtures."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# Lightweight DB mock — no Postgres required for unit tests.
# The in-memory store is reset per test via the fixture.
# ---------------------------------------------------------------------------
_store: dict[str, dict[str, Any]] = {}


async def _mock_run_migrations() -> None:
    pass


async def _mock_upsert(
    slug: str,
    command: str,
    result: dict[str, Any],
    is_private: bool = False,
    user_id: str | None = None,
    workspace_id: str | None = None,
) -> None:
    _store[slug] = {"slug": slug, "command": command, "is_private": is_private, **result}


async def _mock_fetch(slug: str, requesting_user_id: str | None = None) -> dict[str, Any] | None:
    return _store.get(slug)


async def _mock_search(query: str, limit: int = 20) -> list[dict[str, Any]]:
    results = []
    for slug, data in _store.items():
        if not data.get("is_private") and query.lower() in data.get("command", "").lower():
            results.append({
                "slug": slug,
                "command": data["command"][:200],
                "has_lolbas": bool(data.get("lolbas_match") or data.get("lolbas_matches")),
                "has_encoding": len(data.get("decoded_layers", [])) > 0,
                "threat_labels": [],
                "created_at": "2024-01-01T00:00:00",
            })
    return results[:limit]


@pytest.fixture(autouse=True)
def reset_store():
    _store.clear()
    yield
    _store.clear()


@pytest.fixture
async def client():
    with (
        patch("app.main.run_migrations", new=AsyncMock(side_effect=_mock_run_migrations)),
        patch("app.main.upsert_analysis", new=AsyncMock(side_effect=_mock_upsert)),
        patch("app.main.fetch_analysis", new=AsyncMock(side_effect=_mock_fetch)),
        patch("app.main.search_analyses", new=AsyncMock(side_effect=_mock_search)),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
