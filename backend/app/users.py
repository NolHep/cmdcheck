"""User management: password hashing and credential verification."""

from __future__ import annotations

import os

import bcrypt

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").lower().strip()


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def is_admin_email(email: str) -> bool:
    return bool(ADMIN_EMAIL) and email.lower().strip() == ADMIN_EMAIL
