"""Redact sensitive data from command strings before public storage."""

from __future__ import annotations

import re

_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# Captures the keyword + separator, so we can replace only the value
_CREDENTIAL = re.compile(
    r"(?i)((?<![A-Za-z])(?:password|passwd|pwd|secret|apikey|api[_\-]key)"
    r"(?:\s*[=:]\s*|\s+))\S+"
)

_NTLM_HASH = re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")


def redact(command: str) -> tuple[str, bool]:
    """Return (redacted_command, was_anything_redacted).

    Masks private IPs, credential flag values, and NTLM hashes.
    Base64 blobs are left intact — they are the payload being analyzed.
    """
    out = command
    changed = False

    out, n = _PRIVATE_IP.subn("[INTERNAL-IP]", out)
    if n:
        changed = True

    out, n = _CREDENTIAL.subn(r"\1[REDACTED]", out)
    if n:
        changed = True

    out, n = _NTLM_HASH.subn("[NTLM-HASH]", out)
    if n:
        changed = True

    return out, changed
