"""Email delivery via Resend API; falls back to console logging in dev."""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

_RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
_FROM_EMAIL = os.getenv("FROM_EMAIL", "ShellHawk <noreply@shellhawk.net>")
_APP_URL = os.getenv("APP_URL", "http://localhost:3000")


async def send_verification_email(to_email: str, token: str) -> None:
    verify_url = f"{_APP_URL}/verify-email?token={token}"
    subject = "Verify your ShellHawk email address"
    body_text = (
        f"Click the link below to verify your ShellHawk account:\n\n"
        f"{verify_url}\n\n"
        f"This link expires in 24 hours. If you didn't sign up, ignore this email."
    )
    body_html = (
        f"<p>Click the link below to verify your <strong>ShellHawk</strong> account:</p>"
        f'<p><a href="{verify_url}">{verify_url}</a></p>'
        f"<p>This link expires in 24 hours. If you didn't sign up, ignore this email.</p>"
    )

    if not _RESEND_API_KEY:
        logger.info(
            "[email-dev] Verification email → %s\n  Link: %s",
            to_email,
            verify_url,
        )
        return

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {_RESEND_API_KEY}"},
            json={
                "from": _FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "text": body_text,
                "html": body_html,
            },
        )
        if resp.status_code >= 400:
            logger.error("Resend error %d: %s", resp.status_code, resp.text)


async def send_password_reset_email(to_email: str, token: str) -> None:
    reset_url = f"{_APP_URL}/reset-password?token={token}"
    subject = "Reset your ShellHawk password"
    body_text = (
        f"Click the link below to reset your ShellHawk password:\n\n"
        f"{reset_url}\n\n"
        f"This link expires in 1 hour. If you didn't request a reset, ignore this email."
    )
    body_html = (
        f"<p>Click the link below to reset your <strong>ShellHawk</strong> password:</p>"
        f'<p><a href="{reset_url}">{reset_url}</a></p>'
        f"<p>This link expires in 1 hour. If you didn't request a reset, ignore this email.</p>"
    )

    if not _RESEND_API_KEY:
        logger.info(
            "[email-dev] Password reset → %s\n  Link: %s",
            to_email,
            reset_url,
        )
        return

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {_RESEND_API_KEY}"},
            json={
                "from": _FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "text": body_text,
                "html": body_html,
            },
        )
        if resp.status_code >= 400:
            logger.error("Resend error %d: %s", resp.status_code, resp.text)


async def send_workspace_invite_email(to_email: str, workspace_name: str, token: str) -> None:
    invite_url = f"{_APP_URL}/workspaces/invite/{token}"
    subject = f"You've been invited to join {workspace_name} on ShellHawk"
    body_text = (
        f"You've been invited to join the workspace \"{workspace_name}\" on ShellHawk.\n\n"
        f"Accept your invite:\n{invite_url}\n\n"
        f"This invite expires in 7 days."
    )
    body_html = (
        f"<p>You've been invited to join the workspace <strong>{workspace_name}</strong> on ShellHawk.</p>"
        f'<p><a href="{invite_url}">Accept invite →</a></p>'
        f"<p>This invite expires in 7 days.</p>"
    )

    if not _RESEND_API_KEY:
        logger.info(
            "[email-dev] Workspace invite → %s (workspace: %s)\n  Link: %s",
            to_email,
            workspace_name,
            invite_url,
        )
        return

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {_RESEND_API_KEY}"},
            json={
                "from": _FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "text": body_text,
                "html": body_html,
            },
        )
        if resp.status_code >= 400:
            logger.error("Resend error %d: %s", resp.status_code, resp.text)
