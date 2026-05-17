"""Slug generation for analyses.

Public analyses: deterministic base32(SHA256(normalized_command))[:12] — same
command always maps to the same slug, enabling deduplication and stable links.

Private analyses: random 12-char base32 token — unguessable, no deduplication.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets


def normalize(command: str) -> str:
    """Strip leading/trailing whitespace; collapse internal runs to single space."""
    return re.sub(r"\s+", " ", command.strip())


def make_slug(command: str) -> str:
    digest = hashlib.sha256(normalize(command).encode("utf-8")).digest()
    return base64.b32encode(digest).decode("ascii")[:12]


def make_private_slug() -> str:
    """Generate a random unguessable 12-char base32 slug for private analyses."""
    return base64.b32encode(secrets.token_bytes(8)).decode("ascii")[:12]
