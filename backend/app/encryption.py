"""Fernet symmetric encryption for private command storage.

Private analyses have their command text encrypted at rest using a key
set via the ENCRYPTION_KEY environment variable. The key must be a valid
Fernet key (32-byte URL-safe base64 string).

Generate a key:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

If ENCRYPTION_KEY is not set, encryption is skipped and a warning is logged at
startup. Private analyses still work but are not encrypted at rest — acceptable
for development, not for production.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_fernet = None
_warned = False


def _get_fernet():
    global _fernet, _warned
    if _fernet is not None:
        return _fernet

    key = os.getenv("ENCRYPTION_KEY", "").strip()
    if not key:
        if not _warned:
            logger.warning(
                "ENCRYPTION_KEY is not set — private analyses will NOT be encrypted at rest. "
                "Generate a key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
            _warned = True
        return None

    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(key.encode())
        return _fernet
    except Exception as exc:
        logger.error("Invalid ENCRYPTION_KEY: %s — encryption disabled", exc)
        return None


def encrypt(plaintext: str) -> tuple[str, bool]:
    """Encrypt plaintext. Returns (stored_value, was_encrypted).

    If no key is configured, returns the plaintext unchanged and False.
    """
    f = _get_fernet()
    if f is None:
        return plaintext, False
    token = f.encrypt(plaintext.encode("utf-8")).decode("ascii")
    return token, True


def decrypt(stored: str, encrypted: bool) -> str:
    """Decrypt a stored value. Returns plaintext.

    If encrypted=False or no key configured, returns the value unchanged.
    Gracefully handles pre-encryption legacy rows.
    """
    if not encrypted:
        return stored
    f = _get_fernet()
    if f is None:
        return stored  # key removed after encryption — return raw token with a note
    try:
        return f.decrypt(stored.encode("ascii")).decode("utf-8")
    except Exception:
        logger.warning("Failed to decrypt stored command — key may have rotated")
        return "[decryption failed — encryption key may have changed]"
