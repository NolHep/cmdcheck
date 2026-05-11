"""Integration-style tests for new API features.

These tests use the same ASGI+mocked-DB approach as test_analyze.py but cover
features added after the initial scaffold: private submissions, API key auth,
rate limiting rejection, and workspace_id tagging.

All DB calls are mocked — no live Postgres required.
"""

from __future__ import annotations

import hashlib
import secrets
from unittest.mock import AsyncMock, patch

import pytest


# ── Private submission ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_private_requires_auth(client):
    """is_private=True without user_email must return 401."""
    resp = await client.post("/analyze", json={
        "command": "whoami",
        "is_private": True,
    })
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "unauthenticated"


@pytest.mark.asyncio
async def test_private_requires_subscription(client):
    """is_private=True with unsubscribed user must return 402."""
    free_user = {
        "id": "00000000-0000-0000-0000-000000000001",
        "email": "free@example.com",
        "password_hash": "x",
        "role": "user",
        "verified": True,
        "stripe_customer_id": None,
        "subscription_status": "free",
        "subscription_tier": "free",
    }
    with patch("app.main.fetch_user_by_email", new=AsyncMock(return_value=free_user)):
        resp = await client.post("/analyze", json={
            "command": "whoami",
            "is_private": True,
            "user_email": "free@example.com",
        })
    assert resp.status_code == 402
    assert resp.json()["detail"]["code"] == "subscription_required"


@pytest.mark.asyncio
async def test_private_allowed_for_subscriber(client):
    """is_private=True with active subscriber must return 200."""
    paid_user = {
        "id": "00000000-0000-0000-0000-000000000002",
        "email": "paid@example.com",
        "password_hash": "x",
        "role": "user",
        "verified": True,
        "stripe_customer_id": "cus_test",
        "subscription_status": "active",
        "subscription_tier": "individual",
    }
    with patch("app.main.fetch_user_by_email", new=AsyncMock(return_value=paid_user)):
        resp = await client.post("/analyze", json={
            "command": "whoami",
            "is_private": True,
            "user_email": "paid@example.com",
        })
    assert resp.status_code == 200
    assert resp.json()["is_private"] is True


# ── API key authentication ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_key_auth_accepted(client):
    """Valid X-API-Key resolves user and returns 200."""
    plaintext = "cckey_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    api_user = {
        "id": "00000000-0000-0000-0000-000000000003",
        "email": "apiuser@example.com",
        "role": "user",
        "subscription_status": "active",
        "subscription_tier": "individual",
        "stripe_customer_id": "cus_api",
        "key_id": "00000000-0000-0000-0000-000000000099",
    }
    with patch("app.main.fetch_user_by_api_key", new=AsyncMock(return_value=api_user)):
        resp = await client.post(
            "/analyze",
            json={"command": "whoami"},
            headers={"X-API-Key": plaintext},
        )
    assert resp.status_code == 200
    # API-key submissions are always private
    assert resp.json()["is_private"] is True


@pytest.mark.asyncio
async def test_api_key_invalid_ignored(client):
    """Invalid / absent X-API-Key falls through to anonymous public analysis."""
    with patch("app.main.fetch_user_by_api_key", new=AsyncMock(return_value=None)):
        resp = await client.post(
            "/analyze",
            json={"command": "whoami"},
            headers={"X-API-Key": "cckey_notreal"},
        )
    assert resp.status_code == 200
    # No valid key → public analysis (is_private defaults to False)
    assert resp.json()["is_private"] is False


# ── Rate limiting ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_limit_free_tier(client):
    """Authenticated free-tier user gets rate-limited after 60 req/min."""
    free_user = {
        "id": "00000000-0000-0000-0000-000000000004",
        "email": "ratelimit@example.com",
        "password_hash": "x",
        "role": "user",
        "verified": True,
        "stripe_customer_id": None,
        "subscription_status": "free",
        "subscription_tier": "free",
    }
    # Exhaust the window by direct manipulation of the limiter state
    from app.main import _rate_windows, _TIER_RPM
    import time
    key = "email:ratelimit@example.com"
    rpm = _TIER_RPM["free"]
    now = time.monotonic()
    _rate_windows[key].extend([now] * rpm)

    with patch("app.main.fetch_user_by_email", new=AsyncMock(return_value=free_user)):
        resp = await client.post("/analyze", json={
            "command": "whoami",
            "user_email": "ratelimit@example.com",
        })
    assert resp.status_code == 429
    assert resp.json()["detail"]["code"] == "rate_limited"

    # Clean up so other tests aren't affected
    _rate_windows.pop(key, None)


# ── Workspace tagging ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_workspace_id_requires_member(client):
    """workspace_id from a non-member must be silently ignored (not 403)."""
    # fetch_workspace returns None (not a member)
    with patch("app.main.fetch_workspace", new=AsyncMock(return_value=None)):
        resp = await client.post("/analyze", json={
            "command": "whoami",
            "workspace_id": "00000000-0000-0000-0000-000000000010",
        })
    # workspace_id without user_id is silently dropped — public analysis succeeds
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_workspace_id_accepted_for_member(client):
    """workspace_id from a verified member is accepted and analysis is private."""
    paid_user = {
        "id": "00000000-0000-0000-0000-000000000005",
        "email": "member@example.com",
        "password_hash": "x",
        "role": "user",
        "verified": True,
        "stripe_customer_id": "cus_ws",
        "subscription_status": "active",
        "subscription_tier": "teams",
    }
    ws_data = {"id": "00000000-0000-0000-0000-000000000010", "name": "IR Team", "your_role": "member", "members": [], "recent_analyses": [], "owner_id": "x", "created_at": "2026-01-01T00:00:00"}
    with (
        patch("app.main.fetch_user_by_email", new=AsyncMock(return_value=paid_user)),
        patch("app.main.fetch_workspace", new=AsyncMock(return_value=ws_data)),
    ):
        resp = await client.post("/analyze", json={
            "command": "whoami",
            "is_private": True,
            "user_email": "member@example.com",
            "workspace_id": "00000000-0000-0000-0000-000000000010",
        })
    assert resp.status_code == 200
    assert resp.json()["is_private"] is True


# ── Skip redaction ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_skip_redaction_ignored_for_free_user(client):
    """skip_redaction=True is silently ignored for free-tier users."""
    free_user = {
        "id": "00000000-0000-0000-0000-000000000006",
        "email": "skipr@example.com",
        "password_hash": "x",
        "role": "user",
        "verified": True,
        "stripe_customer_id": None,
        "subscription_status": "free",
        "subscription_tier": "free",
    }
    sub_status = {"status": "free", "tier": "free", "stripe_customer_id": None}
    with (
        patch("app.main.fetch_user_by_email", new=AsyncMock(return_value=free_user)),
        patch("app.main.fetch_subscription_status", new=AsyncMock(return_value=sub_status)),
    ):
        resp = await client.post("/analyze", json={
            "command": "password=hunter2 whoami",
            "skip_redaction": True,
            "user_email": "skipr@example.com",
        })
    assert resp.status_code == 200
    # The credential should have been redacted despite skip_redaction=True
    assert "hunter2" not in resp.json().get("command", "")
