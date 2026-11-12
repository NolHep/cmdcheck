"""API-level handling of input that is hostile to the plumbing rather than the detector."""
from __future__ import annotations

import pytest


@pytest.mark.anyio
@pytest.mark.parametrize("command", [
    "whoami\u0000 /all",                 # NUL — Postgres text columns reject it
    "echo 😀 done",            # astral character
    "ipconfig ‮/all",               # right-to-left override
    "   \t  ",                           # whitespace only
    "\u0000",                            # nothing but NUL
])
async def test_awkward_characters_get_a_structured_answer(client, command: str) -> None:
    resp = await client.post("/analyze", json={"command": command})
    assert resp.status_code in (200, 422), resp.text
    body = resp.json()
    if resp.status_code == 200:
        assert "\u0000" not in body["command"]
        assert body["verdict"]["severity"] in {"clean", "low", "notable", "suspicious", "malicious"}
    else:
        assert "detail" in body


@pytest.mark.anyio
async def test_lone_surrogate_is_rejected_or_cleaned(client) -> None:
    # Sent as a raw JSON escape: a lone high surrogate cannot be encoded as UTF-8.
    resp = await client.post(
        "/analyze",
        content=b'{"command": "echo \\ud800 hi"}',
        headers={"content-type": "application/json"},
    )
    assert resp.status_code in (200, 422), resp.text


@pytest.mark.anyio
async def test_oversized_command_is_rejected(client) -> None:
    resp = await client.post("/analyze", json={"command": "a" * 70000})
    assert resp.status_code in (413, 422)


@pytest.mark.anyio
async def test_same_command_same_slug_and_verdict(client) -> None:
    cmd = "vssadmin delete shadows /all /quiet"
    first = (await client.post("/analyze", json={"command": cmd})).json()
    second = (await client.post("/analyze", json={"command": cmd})).json()
    assert first["slug"] == second["slug"]
    assert first["verdict"] == second["verdict"]
