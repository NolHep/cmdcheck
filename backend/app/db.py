"""Postgres connection pool and query helpers."""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

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



def _validate_and_encode_dsn(dsn: str) -> str:
    """Validate the DATABASE_URL structure and return a pool-safe DSN.

    Parses the URL manually so that passwords containing literal ``@`` symbols
    (common in Supabase connection strings) are handled correctly.  The
    standard library's ``urlparse`` treats every ``@`` as a potential
    user/host delimiter, so it cannot reliably split a URL whose password
    contains ``@``.

    The approach used here is:
      1. Split on the first ``://`` to extract the scheme.
      2. Find the *last* ``@`` in the remainder — that is always the
         user/host delimiter in a valid PostgreSQL URL.
      3. Everything to the left of that ``@`` is ``username:password``;
         split on the first ``:`` to separate them.
      4. Percent-encode the raw password with ``quote(safe="")`` so that
         special characters (``@``, ``:``, ``/``, …) do not confuse asyncpg.
      5. Reconstruct the full URL with the encoded password.

    A ``ValueError`` with a human-readable message is raised when the URL
    does not match the expected shape.
    """
    # ── Step 1: extract scheme ─────────────────────────────────────────────────
    if "://" not in dsn:
        raise ValueError(
            "\n\n[cmdcheck] DATABASE_URL is malformed.\n"
            "  Problems detected:\n"
            "    scheme   : missing '://' separator\n\n"
            "  Expected format:\n"
            "    postgresql://username:password@hostname:5432/database\n"
        )

    scheme, _, after_scheme = dsn.partition("://")

    errors: list[str] = []

    if scheme not in ("postgresql", "postgres"):
        errors.append(
            f"  scheme   : got {scheme!r}, expected 'postgresql' or 'postgres'"
        )

    # ── Step 2: find the last '@' — the user/host delimiter ───────────────────
    last_at = after_scheme.rfind("@")
    if last_at == -1:
        errors.append(
            "  userinfo : missing '@' — URL must be postgresql://user:pass@HOSTNAME/db"
        )
        if errors:
            raise ValueError(
                "\n\n[cmdcheck] DATABASE_URL is malformed.\n"
                "  Problems detected:\n"
                + "\n".join(errors)
                + "\n\n"
                "  Expected format:\n"
                "    postgresql://username:password@hostname:5432/database\n\n"
                "  Common causes:\n"
                "    • The URL was copied without the username prefix.\n"
                "    • The URL was split across multiple lines in the environment.\n"
            )

    userinfo = after_scheme[:last_at]
    hostinfo = after_scheme[last_at + 1:]

    # ── Step 3: split userinfo into username and raw password ──────────────────
    if ":" not in userinfo:
        errors.append(
            "  password : missing — URL must be postgresql://username:PASSWORD@host/db"
        )
        username = userinfo
        raw_password: str | None = None
    else:
        username, _, raw_password = userinfo.partition(":")

    if not username:
        errors.append(
            "  username : missing — URL must be postgresql://USERNAME:password@host/db"
        )

    if raw_password is None:
        errors.append(
            "  password : missing — URL must be postgresql://username:PASSWORD@host/db"
        )

    # Basic hostname check (hostinfo is "host:port/db" or "host/db")
    hostname_part = hostinfo.split("/")[0].split(":")[0]
    if not hostname_part:
        errors.append(
            "  hostname : missing — URL must be postgresql://user:pass@HOSTNAME:port/db"
        )

    if errors:
        raise ValueError(
            "\n\n[cmdcheck] DATABASE_URL is malformed.\n"
            f"  Received (redacted): {scheme}://{username or '<missing>'}:<redacted>@{hostname_part or '<missing>'}/<db>\n"
            "  Problems detected:\n"
            + "\n".join(errors)
            + "\n\n"
            "  Expected format:\n"
            "    postgresql://username:password@hostname:5432/database\n\n"
            "  Common causes:\n"
            "    • The password contains a literal '@' — encode it as '%40' in the URL.\n"
            "    • The URL was copied without the username prefix.\n"
            "    • The URL was split across multiple lines in the environment.\n"
        )

    # ── Step 4: percent-encode the raw password ────────────────────────────────
    # ``raw_password`` is the literal string from the URL (not decoded), so any
    # already-encoded sequences (e.g. ``%40``) are preserved and the bare
    # special characters (``@``, ``:``, ``/``, …) are encoded for the first time.
    encoded_password = quote(raw_password, safe="")  # type: ignore[arg-type]

    # ── Step 5: reconstruct the full URL ──────────────────────────────────────
    return f"{scheme}://{username}:{encoded_password}@{hostinfo}"


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

        try:
            safe_dsn = _validate_and_encode_dsn(dsn)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)

        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                _pool = await asyncpg.create_pool(
                    dsn=safe_dsn,
                    min_size=1,
                    max_size=10,
                    # Supabase poolers (pgBouncer) require no prepared-statement
                    # cache; without this asyncpg sends named statements that
                    # pgBouncer can't route, causing connection failures.
                    statement_cache_size=0,
                )
                break
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    import asyncio
                    wait = 2 ** attempt
                    print(
                        f"[cmdcheck] DB connection attempt {attempt + 1} failed, "
                        f"retrying in {wait}s: {exc}",
                        file=sys.stderr,
                    )
                    await asyncio.sleep(wait)
        else:
            print(
                f"\n[cmdcheck] Could not connect to database after 3 attempts.\n"
                f"  Last error: {last_exc}\n"
                f"  Ensure DATABASE_URL is set correctly in Railway variables and\n"
                f"  that your Supabase project is not paused (free tier sleeps).\n"
                f"  Use the Session mode pooler URL (port 5432), not port 6543.\n",
                file=sys.stderr,
            )
            sys.exit(1)
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


async def upsert_analysis(
    slug: str,
    command: str,
    result: dict[str, Any],
    is_private: bool = False,
    user_id: str | None = None,
    workspace_id: str | None = None,
) -> None:
    from .encryption import encrypt
    stored_command, encrypted = encrypt(command) if is_private else (command, False)

    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO analyses (slug, command, result, is_private, user_id, encrypted, workspace_id)
            VALUES ($1, $2, $3::jsonb, $4, $5::uuid, $6, $7::uuid)
            ON CONFLICT (slug) DO UPDATE
              SET deleted_at   = NULL,
                  result       = EXCLUDED.result,
                  command      = EXCLUDED.command,
                  is_private   = EXCLUDED.is_private,
                  user_id      = EXCLUDED.user_id,
                  encrypted    = EXCLUDED.encrypted,
                  workspace_id = EXCLUDED.workspace_id
              WHERE analyses.deleted_at IS NOT NULL
            """,
            slug,
            stored_command,
            json.dumps(result),
            is_private,
            user_id,
            encrypted,
            workspace_id,
        )


async def delete_analysis(
    slug: str,
    user_email: str | None = None,
    is_admin: bool = False,
) -> bool:
    """Soft-delete an analysis. Returns True if a row was updated.

    If is_admin is True, any analysis may be deleted.
    If user_email is provided, only analyses owned by that user may be deleted.
    If neither is provided, returns False (no anonymous deletes).
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        if is_admin:
            result = await conn.execute(
                "UPDATE analyses SET deleted_at = NOW() WHERE slug = $1 AND deleted_at IS NULL",
                slug,
            )
        elif user_email:
            result = await conn.execute(
                """
                UPDATE analyses SET deleted_at = NOW()
                WHERE slug = $1 AND deleted_at IS NULL
                  AND user_id = (SELECT id FROM users WHERE email = $2 LIMIT 1)
                """,
                slug,
                user_email.lower().strip(),
            )
        else:
            return False
    return result == "UPDATE 1"


async def delete_all_analyses() -> int:
    """Soft-delete every non-deleted analysis. Returns count of rows affected."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE analyses SET deleted_at = NOW() WHERE deleted_at IS NULL"
        )
    # result is like "UPDATE 42"
    try:
        return int(result.split()[-1])
    except (IndexError, ValueError):
        return 0


async def fetch_recent(limit: int = 50) -> list[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT slug, command, result, created_at
            FROM analyses
            WHERE deleted_at IS NULL AND is_private = false
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    items: list[dict[str, Any]] = []
    for row in rows:
        result = json.loads(row["result"])
        high_threats = [
            tc["label"]
            for tc in result.get("threat_classes", [])
            if tc.get("confidence") in ("high", "medium")
        ]
        items.append({
            "slug": row["slug"],
            "command": row["command"][:200],
            "has_lolbas": result.get("lolbas_match") is not None,
            "has_encoding": len(result.get("decoded_layers", [])) > 0,
            "threat_labels": high_threats,
            "severity": (result.get("verdict") or {}).get("severity"),
            "created_at": row["created_at"].isoformat(),
        })
    return items


async def search_analyses(query: str, limit: int = 20) -> list[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT slug, command, result, created_at
            FROM analyses
            WHERE deleted_at IS NULL
              AND is_private = false
              AND command ILIKE $1
            ORDER BY created_at DESC
            LIMIT $2
            """,
            f"%{query}%",
            limit,
        )
    items: list[dict[str, Any]] = []
    for row in rows:
        result = json.loads(row["result"])
        high_threats = [
            tc["label"]
            for tc in result.get("threat_classes", [])
            if tc.get("confidence") in ("high", "medium")
        ]
        items.append({
            "slug": row["slug"],
            "command": row["command"][:200],
            "has_lolbas": result.get("lolbas_match") is not None,
            "has_encoding": len(result.get("decoded_layers", [])) > 0,
            "threat_labels": high_threats,
            "severity": (result.get("verdict") or {}).get("severity"),
            "created_at": row["created_at"].isoformat(),
        })
    return items


# ── Users ──────────────────────────────────────────────────────────────────────

async def create_user(email: str, password_hash: str, role: str = "user") -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO users (email, password_hash, role, verified)
            VALUES ($1, $2, $3, true)
            RETURNING id, email, role, created_at
            """,
            email.lower().strip(),
            password_hash,
            role,
        )
    return dict(row)


async def fetch_user_by_email(email: str) -> dict[str, Any] | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, password_hash, role, verified, stripe_customer_id FROM users WHERE email = $1",
            email.lower().strip(),
        )
    return dict(row) if row else None


# ── Stripe billing ─────────────────────────────────────────────────────────────

async def set_stripe_customer_id(email: str, customer_id: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET stripe_customer_id = $1 WHERE email = $2",
            customer_id,
            email.lower().strip(),
        )


async def update_subscription_by_customer(
    customer_id: str,
    status: str,
    tier: str,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE users
            SET subscription_status     = $1,
                subscription_tier       = $2,
                subscription_updated_at = NOW()
            WHERE stripe_customer_id = $3
            """,
            status,
            tier,
            customer_id,
        )


async def fetch_subscription_status(email: str) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT stripe_customer_id, subscription_status, subscription_tier
            FROM users WHERE email = $1
            """,
            email.lower().strip(),
        )
    if not row:
        return {"status": "free", "tier": "free", "stripe_customer_id": None}
    return {
        "status": row["subscription_status"],
        "tier": row["subscription_tier"],
        "stripe_customer_id": row["stripe_customer_id"],
    }


# ── Email verification ──────────────────────────────────────────────────────────

async def create_verification_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Invalidate any previous unused tokens for this user
        await conn.execute(
            "UPDATE email_verification_tokens SET used = true WHERE user_id = $1::uuid AND NOT used",
            user_id,
        )
        await conn.execute(
            "INSERT INTO email_verification_tokens (token, user_id) VALUES ($1, $2::uuid)",
            token,
            user_id,
        )
    return token


async def consume_verification_token(token: str) -> str | None:
    """Mark token used, set user verified, return user_id on success."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT user_id FROM email_verification_tokens
                WHERE token = $1 AND NOT used AND expires_at > NOW()
                """,
                token,
            )
            if row is None:
                return None
            user_id = str(row["user_id"])
            await conn.execute(
                "UPDATE email_verification_tokens SET used = true WHERE token = $1",
                token,
            )
            await conn.execute(
                "UPDATE users SET verified = true WHERE id = $1::uuid",
                user_id,
            )
    return user_id


async def create_password_reset_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE password_reset_tokens SET used = true WHERE user_id = $1::uuid AND NOT used",
            user_id,
        )
        await conn.execute(
            "INSERT INTO password_reset_tokens (token, user_id) VALUES ($1, $2::uuid)",
            token,
            user_id,
        )
    return token


async def consume_password_reset_token(token: str) -> str | None:
    """Mark token used and return user_id, or None if invalid/expired."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT user_id FROM password_reset_tokens
                WHERE token = $1 AND NOT used AND expires_at > NOW()
                """,
                token,
            )
            if row is None:
                return None
            user_id = str(row["user_id"])
            await conn.execute(
                "UPDATE password_reset_tokens SET used = true WHERE token = $1",
                token,
            )
    return user_id


async def update_user_password(user_id: str, password_hash: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET password_hash = $1 WHERE id = $2::uuid",
            password_hash,
            user_id,
        )


async def count_users() -> int:
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT COUNT(*) FROM users")


# ── Site settings ───────────────────────────────────────────────────────────────

async def get_setting(key: str) -> str | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT value FROM site_settings WHERE key = $1", key)


async def set_setting(key: str, value: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO site_settings (key, value, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            key,
            value,
        )


async def get_banner() -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT key, value FROM site_settings WHERE key IN ('banner_enabled', 'banner_message', 'banner_type')"
        )
    settings = {r["key"]: r["value"] for r in rows}
    return {
        "enabled": settings.get("banner_enabled", "false") == "true",
        "message": settings.get("banner_message", ""),
        "type": settings.get("banner_type", "info"),
    }


# ── Bug reports ─────────────────────────────────────────────────────────────────

async def create_bug_report(
    title: str,
    description: str,
    severity: str,
    contact_email: str | None,
) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO bug_reports (title, description, severity, contact_email)
            VALUES ($1, $2, $3, $4)
            RETURNING id, title, severity, status, created_at
            """,
            title,
            description,
            severity,
            contact_email,
        )
    return dict(row)


async def fetch_bug_reports(status: str | None = None) -> list[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                "SELECT * FROM bug_reports WHERE status = $1 ORDER BY created_at DESC",
                status,
            )
        else:
            rows = await conn.fetch("SELECT * FROM bug_reports ORDER BY created_at DESC")
    return [dict(r) for r in rows]


async def update_bug_report(report_id: str, status: str, admin_notes: str | None) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE bug_reports
            SET status = $1, admin_notes = $2, updated_at = NOW()
            WHERE id = $3
            """,
            status,
            admin_notes,
            report_id,
        )
    return result == "UPDATE 1"


# ── Threat groups ───────────────────────────────────────────────────────────────

async def fetch_threat_groups() -> list[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        groups = await conn.fetch(
            "SELECT id, name, description, created_at FROM threat_groups ORDER BY created_at DESC"
        )
        members = await conn.fetch(
            """
            SELECT m.group_id, m.slug, m.notes, m.added_at,
                   a.command, a.encrypted
            FROM threat_group_members m
            LEFT JOIN analyses a ON a.slug = m.slug AND a.deleted_at IS NULL
            ORDER BY m.added_at ASC
            """
        )
    from .encryption import decrypt
    member_map: dict[str, list[dict[str, Any]]] = {}
    for m in members:
        gid = str(m["group_id"])
        raw_cmd = m["command"]
        cmd_preview = decrypt(raw_cmd, m.get("encrypted", False))[:120] if raw_cmd else None
        member_map.setdefault(gid, []).append({
            "slug": m["slug"],
            "notes": m["notes"],
            "added_at": m["added_at"].isoformat(),
            "command": cmd_preview,
        })
    return [
        {
            "id": str(g["id"]),
            "name": g["name"],
            "description": g["description"],
            "created_at": g["created_at"].isoformat(),
            "members": member_map.get(str(g["id"]), []),
        }
        for g in groups
    ]


async def create_threat_group(name: str, description: str | None) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO threat_groups (name, description) VALUES ($1, $2) RETURNING id, name, description, created_at",
            name, description,
        )
    return {"id": str(row["id"]), "name": row["name"], "description": row["description"],
            "created_at": row["created_at"].isoformat(), "members": []}


async def delete_threat_group(group_id: str) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM threat_groups WHERE id = $1::uuid", group_id)
    return result == "DELETE 1"


async def add_threat_group_member(group_id: str, slug: str, notes: str | None) -> dict[str, Any] | None:
    from .encryption import decrypt
    pool = await get_pool()
    async with pool.acquire() as conn:
        analysis_row = await conn.fetchrow(
            "SELECT command, encrypted FROM analyses WHERE slug = $1 AND deleted_at IS NULL", slug
        )
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO threat_group_members (group_id, slug, notes)
                VALUES ($1::uuid, $2, $3)
                ON CONFLICT (group_id, slug) DO UPDATE SET notes = EXCLUDED.notes
                RETURNING slug, notes, added_at
                """,
                group_id, slug, notes,
            )
        except Exception:
            return None
    if analysis_row:
        cmd_preview = decrypt(analysis_row["command"], analysis_row.get("encrypted", False))[:120]
    else:
        cmd_preview = None
    return {
        "slug": row["slug"],
        "notes": row["notes"],
        "added_at": row["added_at"].isoformat(),
        "command": cmd_preview,
    }


async def remove_threat_group_member(group_id: str, slug: str) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM threat_group_members WHERE group_id = $1::uuid AND slug = $2",
            group_id, slug,
        )
    return result == "DELETE 1"


# ── Workspaces ──────────────────────────────────────────────────────────────────

async def create_workspace(name: str, owner_id: str) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "INSERT INTO workspaces (name, owner_id) VALUES ($1, $2::uuid) RETURNING id, name, created_at",
                name, owner_id,
            )
            await conn.execute(
                "INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
                str(row["id"]), owner_id,
            )
    return {"id": str(row["id"]), "name": row["name"], "created_at": row["created_at"].isoformat()}


async def fetch_workspaces_for_user(user_id: str) -> list[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT w.id, w.name, w.created_at, wm.role,
                   (SELECT COUNT(*) FROM workspace_members wm2 WHERE wm2.workspace_id = w.id) AS member_count
            FROM workspaces w
            JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = $1::uuid
            ORDER BY w.created_at DESC
            """,
            user_id,
        )
    return [
        {"id": str(r["id"]), "name": r["name"], "role": r["role"],
         "member_count": r["member_count"], "created_at": r["created_at"].isoformat()}
        for r in rows
    ]


async def fetch_workspace(workspace_id: str, requesting_user_id: str) -> dict[str, Any] | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        ws = await conn.fetchrow(
            "SELECT id, name, owner_id, created_at FROM workspaces WHERE id = $1::uuid", workspace_id
        )
        if not ws:
            return None
        membership = await conn.fetchval(
            "SELECT role FROM workspace_members WHERE workspace_id = $1::uuid AND user_id = $2::uuid",
            workspace_id, requesting_user_id,
        )
        if not membership:
            return None
        members = await conn.fetch(
            """
            SELECT u.id, u.email, wm.role, wm.joined_at
            FROM workspace_members wm JOIN users u ON u.id = wm.user_id
            WHERE wm.workspace_id = $1::uuid ORDER BY wm.joined_at
            """,
            workspace_id,
        )
        analyses = await conn.fetch(
            """
            SELECT slug, command, result, created_at, encrypted
            FROM analyses
            WHERE workspace_id = $1::uuid AND deleted_at IS NULL
            ORDER BY created_at DESC LIMIT 50
            """,
            workspace_id,
        )
    from .encryption import decrypt
    recent: list[dict[str, Any]] = []
    for row in analyses:
        result = json.loads(row["result"])
        command = decrypt(row["command"], row.get("encrypted", False))
        recent.append({
            "slug": row["slug"],
            "command": command[:200],
            "threat_labels": [tc["label"] for tc in result.get("threat_classes", []) if tc.get("confidence") in ("high", "medium")],
            "created_at": row["created_at"].isoformat(),
        })
    return {
        "id": str(ws["id"]), "name": ws["name"],
        "owner_id": str(ws["owner_id"]), "created_at": ws["created_at"].isoformat(),
        "your_role": membership,
        "members": [{"id": str(m["id"]), "email": m["email"], "role": m["role"], "joined_at": m["joined_at"].isoformat()} for m in members],
        "recent_analyses": recent,
    }


async def create_workspace_invite(workspace_id: str, email: str, invited_by: str, token: str) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO workspace_invites (workspace_id, email, token, invited_by)
            VALUES ($1::uuid, $2, $3, $4::uuid)
            RETURNING id, email, token, expires_at
            """,
            workspace_id, email.lower().strip(), token, invited_by,
        )
    return {"id": str(row["id"]), "email": row["email"], "token": row["token"],
            "expires_at": row["expires_at"].isoformat()}


async def fetch_invite(token: str) -> dict[str, Any] | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT wi.id, wi.workspace_id, wi.email, wi.expires_at, wi.accepted_at,
                   w.name AS workspace_name
            FROM workspace_invites wi JOIN workspaces w ON w.id = wi.workspace_id
            WHERE wi.token = $1
            """,
            token,
        )
    if not row:
        return None
    return {
        "id": str(row["id"]), "workspace_id": str(row["workspace_id"]),
        "email": row["email"], "workspace_name": row["workspace_name"],
        "expires_at": row["expires_at"].isoformat(),
        "accepted": row["accepted_at"] is not None,
    }


async def accept_workspace_invite(token: str, user_id: str, user_email: str) -> dict[str, Any] | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        invite = await conn.fetchrow(
            "SELECT id, workspace_id, email, expires_at, accepted_at FROM workspace_invites WHERE token = $1",
            token,
        )
        if not invite or invite["accepted_at"] is not None:
            return None
        if invite["expires_at"].replace(tzinfo=None) < __import__("datetime").datetime.utcnow():
            return None
        if invite["email"] != user_email.lower().strip():
            return None
        async with conn.transaction():
            await conn.execute(
                "UPDATE workspace_invites SET accepted_at = NOW() WHERE token = $1", token
            )
            await conn.execute(
                """
                INSERT INTO workspace_members (workspace_id, user_id, role)
                VALUES ($1::uuid, $2::uuid, 'member')
                ON CONFLICT (workspace_id, user_id) DO NOTHING
                """,
                str(invite["workspace_id"]), user_id,
            )
    return {"workspace_id": str(invite["workspace_id"])}


async def remove_workspace_member(workspace_id: str, user_id: str, requesting_user_id: str) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        is_owner = await conn.fetchval(
            "SELECT role = 'owner' FROM workspace_members WHERE workspace_id = $1::uuid AND user_id = $2::uuid",
            workspace_id, requesting_user_id,
        )
        if not is_owner:
            return False
        result = await conn.execute(
            "DELETE FROM workspace_members WHERE workspace_id = $1::uuid AND user_id = $2::uuid AND role != 'owner'",
            workspace_id, user_id,
        )
    return result == "DELETE 1"


async def delete_workspace(workspace_id: str, requesting_user_id: str) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        is_owner = await conn.fetchval(
            "SELECT role = 'owner' FROM workspace_members WHERE workspace_id = $1::uuid AND user_id = $2::uuid",
            workspace_id, requesting_user_id,
        )
        if not is_owner:
            return False
        result = await conn.execute("DELETE FROM workspaces WHERE id = $1::uuid", workspace_id)
    return result == "DELETE 1"


# ── API keys ────────────────────────────────────────────────────────────────────

async def create_api_key(user_id: str, name: str, key_hash: str, key_prefix: str) -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO api_keys (user_id, name, key_hash, key_prefix) VALUES ($1::uuid, $2, $3, $4) RETURNING id, name, key_prefix, created_at",
            user_id, name, key_hash, key_prefix,
        )
    return {"id": str(row["id"]), "name": row["name"], "key_prefix": row["key_prefix"],
            "created_at": row["created_at"].isoformat()}


async def fetch_api_keys_for_user(user_id: str) -> list[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, name, key_prefix, created_at, last_used_at FROM api_keys WHERE user_id = $1::uuid AND revoked_at IS NULL ORDER BY created_at DESC",
            user_id,
        )
    return [
        {"id": str(r["id"]), "name": r["name"], "key_prefix": r["key_prefix"],
         "created_at": r["created_at"].isoformat(),
         "last_used_at": r["last_used_at"].isoformat() if r["last_used_at"] else None}
        for r in rows
    ]


async def revoke_api_key(key_id: str, user_id: str) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1::uuid AND user_id = $2::uuid AND revoked_at IS NULL",
            key_id, user_id,
        )
    return result == "UPDATE 1"


async def fetch_user_by_api_key(key_hash: str) -> dict[str, Any] | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT u.id, u.email, u.role, u.subscription_status, u.subscription_tier,
                   u.stripe_customer_id, ak.id AS key_id
            FROM api_keys ak
            JOIN users u ON u.id = ak.user_id
            WHERE ak.key_hash = $1 AND ak.revoked_at IS NULL
            """,
            key_hash,
        )
        if row:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", row["key_id"]
            )
    return dict(row) if row else None


# ── Admin stats ─────────────────────────────────────────────────────────────────

async def fetch_admin_stats() -> dict[str, Any]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        total_analyses = await conn.fetchval(
            "SELECT COUNT(*) FROM analyses WHERE deleted_at IS NULL"
        )
        today_analyses = await conn.fetchval(
            "SELECT COUNT(*) FROM analyses WHERE deleted_at IS NULL AND created_at >= CURRENT_DATE"
        )
        week_analyses = await conn.fetchval(
            "SELECT COUNT(*) FROM analyses WHERE deleted_at IS NULL AND created_at >= CURRENT_DATE - 7"
        )
        total_users = await conn.fetchval("SELECT COUNT(*) FROM users")
        open_bugs = await conn.fetchval(
            "SELECT COUNT(*) FROM bug_reports WHERE status IN ('open', 'triaging')"
        )
        # Threat class breakdown from stored JSONB — top 10 labels
        threat_rows = await conn.fetch(
            """
            SELECT tc->>'label' AS label, COUNT(*) AS cnt
            FROM analyses,
                 jsonb_array_elements(result->'threat_classes') AS tc
            WHERE deleted_at IS NULL
            GROUP BY label
            ORDER BY cnt DESC
            LIMIT 10
            """
        )

    return {
        "total_analyses": total_analyses,
        "today_analyses": today_analyses,
        "week_analyses": week_analyses,
        "total_users": total_users,
        "open_bugs": open_bugs,
        "top_threat_classes": [{"label": r["label"], "count": r["cnt"]} for r in threat_rows],
    }


async def fetch_analyses_for_user(user_id: str, limit: int = 50) -> list[dict[str, Any]]:
    from .encryption import decrypt
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT slug, command, result, created_at, is_private, encrypted
            FROM analyses
            WHERE user_id = $1::uuid AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $2
            """,
            user_id,
            limit,
        )
    items: list[dict[str, Any]] = []
    for row in rows:
        result = json.loads(row["result"])
        command = decrypt(row["command"], row.get("encrypted", False))
        high_threats = [
            tc["label"]
            for tc in result.get("threat_classes", [])
            if tc.get("confidence") in ("high", "medium")
        ]
        items.append({
            "slug": row["slug"],
            "command": command[:200],
            "has_lolbas": bool(result.get("lolbas_match") or result.get("lolbas_matches")),
            "has_encoding": len(result.get("decoded_layers", [])) > 0,
            "threat_labels": high_threats,
            "severity": (result.get("verdict") or {}).get("severity"),
            "created_at": row["created_at"].isoformat(),
            "is_private": row["is_private"],
        })
    return items


async def count_analyses() -> int:
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT COUNT(*) FROM analyses WHERE deleted_at IS NULL")


async def fetch_analysis(slug: str, requesting_user_id: str | None = None) -> dict[str, Any] | None:
    from .encryption import decrypt
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT a.slug, a.command, a.result, a.deleted_at, a.encrypted,
                   a.is_private, a.workspace_id, a.user_id AS owner_id,
                   u.email AS submitter_email
            FROM analyses a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.slug = $1
            """,
            slug,
        )
        if row is None:
            return None
        if row["deleted_at"] is not None:
            return {"slug": row["slug"], "deleted": True}
        if row["is_private"]:
            if row["workspace_id"]:
                # Workspace-private: must be a workspace member.
                if not requesting_user_id:
                    return None
                is_member = await conn.fetchval(
                    """
                    SELECT 1 FROM workspace_members
                    WHERE workspace_id = $1 AND user_id = $2::uuid
                    """,
                    row["workspace_id"],
                    requesting_user_id,
                )
                if not is_member:
                    return None
            elif row["owner_id"]:
                # Personal private: only the owner may read it.
                if not requesting_user_id or requesting_user_id != str(row["owner_id"]):
                    return None
        command = decrypt(row["command"], row.get("encrypted", False))
    return {
        "slug": row["slug"],
        "command": command,
        "submitter_email": row["submitter_email"],
        **json.loads(row["result"]),
    }
