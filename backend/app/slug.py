"""Deterministic slug generation: base32(SHA256(normalized_command))[:12]."""

from __future__ import annotations

import base64
import hashlib
import re


def normalize(command: str) -> str:
    """Strip leading/trailing whitespace; collapse internal runs to single space."""
    return re.sub(r"\s+", " ", command.strip())


def make_slug(command: str) -> str:
    digest = hashlib.sha256(normalize(command).encode("utf-8")).digest()
    return base64.b32encode(digest).decode("ascii")[:12]
