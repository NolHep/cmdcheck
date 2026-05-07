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


async def _mock_upsert(slug: str, command: str, result: dict[str, Any]) -> None:
    _store[slug] = {"slug": slug, "command": command, **result}


async def _mock_fetch(slug: str) -> dict[str, Any] | None:
    return _store.get(slug)


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
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
