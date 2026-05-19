"""Redact sensitive data from command strings before public storage.

Privacy is load-bearing (CLAUDE.md invariant #4): analysts paste real
incident command lines. We err on the side of over-redacting — a masked
internal hostname is recoverable from context; a leaked one is not.

Order matters: structural secrets (PEM blocks) and unambiguous tokens
(NTLM hashes, IPs) are masked before the looser host/credential heuristics
so the heuristics never see — or double-mask — an already-redacted value.
"""

from __future__ import annotations

import re

# ── Private / internal IPv4 ───────────────────────────────────────────────────
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# ── Private IPv6: link-local (fe80::/10) and ULA (fc00::/7 → fc/fd) ────────────
# Require ≥2 colon-separated groups so we only hit real addresses, never a
# stray hex token (base64 has no colons; NTLM hashes are masked earlier).
_PRIVATE_IP6 = re.compile(
    r"\b(?:fe80|f[cd][0-9a-fA-F]{2})(?::[0-9a-fA-F]{0,4}){2,}\b",
    re.IGNORECASE,
)

# ── PEM private key blocks (multi-line) ───────────────────────────────────────
_PEM_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# ── NTLM hash (LM:NT) ─────────────────────────────────────────────────────────
_NTLM_HASH = re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")

# ── Credentials ───────────────────────────────────────────────────────────────
# keyword = value  (password / pwd / secret / token / apikey / connection-string Pwd)
_CREDENTIAL = re.compile(
    r"(?i)((?<![A-Za-z])(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token"
    r"|client[_\-]?secret|aws_secret_access_key)(?:\s*[=:]\s*|\s+))\S+"
)
# net use / runas style:  /user:DOMAIN\user  (and the value after it)
_USER_FLAG = re.compile(r"(?i)(/user:)\S+")
# HTTP bearer / basic auth tokens
_AUTH_HEADER = re.compile(
    r"(?i)(Authorization\s*:\s*)(?:Bearer|Basic)\s+[A-Za-z0-9+/=._\-]+"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{12,}=*")
# AWS access key id
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# PowerShell plaintext secure strings
_SECURE_STRING = re.compile(
    r"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)('[^']*'|\"[^\"]*\"|\S+)"
)

# ── Internal hostnames ────────────────────────────────────────────────────────
# UNC path host:  \\fileserver01\share   (IPs already masked, so the char class
# below — must start alphanumeric — never matches a leading "[" of [INTERNAL-IP]).
_UNC_HOST = re.compile(r"(\\\\)([A-Za-z0-9_][A-Za-z0-9_.\-]*)")
# Internal DNS suffixes (Active Directory / corp conventions). base64 has no
# dots so payload blobs are safe; public TLDs (.com/.net/...) are not listed.
_INTERNAL_DNS = re.compile(
    r"\b(?:[A-Za-z0-9\-]+\.)+(?:corp|local|internal|intranet|intra|lan|ad|"
    r"domain|home|lab|test|dmz|priv|private)\b",
    re.IGNORECASE,
)
# Explicit remote-target flags whose value is a hostname.
_HOST_FLAG = re.compile(
    r"(?i)((?:-ComputerName|-CN|-Server|/node:|-r:|-h\s|--host\s|-ComputerName:)\s*)"
    r"([A-Za-z_][A-Za-z0-9_.\-]*)"
)


def redact(command: str) -> tuple[str, bool]:
    """Return (redacted_command, was_anything_redacted).

    Masks PEM keys, NTLM hashes, private IPv4/IPv6, credentials (flag values,
    bearer/basic tokens, AWS keys, SecureString plaintext, /user:), and
    internal hostnames (UNC, internal DNS suffixes, remote-target flags).
    Base64 payload blobs are left intact — they are what we exist to analyze.
    """
    out = command
    changed = False

    for pattern, repl in (
        (_PEM_KEY, "[REDACTED-KEY]"),
        (_NTLM_HASH, "[NTLM-HASH]"),
        (_PRIVATE_IP, "[INTERNAL-IP]"),
        (_PRIVATE_IP6, "[INTERNAL-IP]"),
        (_CREDENTIAL, r"\1[REDACTED]"),
        (_USER_FLAG, r"\1[REDACTED]"),
        (_AUTH_HEADER, r"\1[REDACTED]"),
        (_BEARER, "Bearer [REDACTED]"),
        (_AWS_KEY, "[REDACTED-AWS-KEY]"),
        (_SECURE_STRING, r"\1[REDACTED]"),
        (_UNC_HOST, r"\1[INTERNAL-HOST]"),
        (_INTERNAL_DNS, "[INTERNAL-HOST]"),
        (_HOST_FLAG, r"\1[INTERNAL-HOST]"),
    ):
        out, n = pattern.subn(repl, out)
        if n:
            changed = True

    return out, changed
