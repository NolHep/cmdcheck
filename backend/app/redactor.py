"""Redact sensitive data from command strings before public storage.

Privacy is load-bearing (CLAUDE.md invariant #4): analysts paste real
incident command lines. We err on the side of over-redacting — a masked
internal hostname is recoverable from context; a leaked one is not.

Order matters: structural secrets (PEM blocks) and unambiguous tokens
(NTLM hashes, IPs) are masked before the looser host/credential heuristics
so the heuristics never see — or double-mask — an already-redacted value.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# ── Private / internal IPv4 (including loopback) ─────────────────────────────
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# ── Private IPv6: link-local (fe80::/10), ULA (fc/fd), IPv4-mapped private ───
# Require ≥2 colon-separated groups so we only hit real addresses, never a
# stray hex token (base64 has no colons; NTLM hashes are masked earlier).
_PRIVATE_IP6 = re.compile(
    r"\b(?:fe80|f[cd][0-9a-fA-F]{2})(?::[0-9a-fA-F]{0,4}){2,}\b"
    r"|::ffff:(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)"
    r"\.\d{1,3}\.\d{1,3}",
    re.IGNORECASE,
)

# ── PEM private key blocks (multi-line) ───────────────────────────────────────
_PEM_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# ── X.509 certificate blocks — contain org name, CN, SAN entries ─────────────
_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

# Counts opens vs closes to detect truncation mid-block (used before truncation).
_PEM_OPEN_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)-----"
)
_PEM_CLOSE_RE = re.compile(
    r"-----END [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)-----"
)

# ── NTLM hash (LM:NT) ─────────────────────────────────────────────────────────
_NTLM_HASH = re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")

# ── Credentials ───────────────────────────────────────────────────────────────
# keyword=value — requires = or : separator.
# Value stops at whitespace, quotes, and structural chars so we never eat through
# JSON ("key":"val1","key2":"val2") or PowerShell ('val') structure.
_CREDENTIAL = re.compile(
    r"(?i)((?<![A-Za-z])(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token"
    r"|client[_\-]?secret|aws_secret_access_key)\s*[=:]\s*)[^\s\"'<>,;=]+"
)

# CLI flag-value form: --password MySecret / -token abc123
# Separate from _CREDENTIAL so we can safely require a non-quote value token
# without interfering with JSON = or : separator parsing.
_CREDENTIAL_FLAG = re.compile(
    r"(?i)((?<!\S)--?(?:password|passwd|pwd|secret|token|api[_\-]?key"
    r"|access[_\-]?token|client[_\-]?secret)[ \t]+)[^\s\"'<>,;=]+"
)

# net use / runas style:  /user:DOMAIN\user  (and the value after it)
_USER_FLAG = re.compile(r"(?i)(/user:)\S+")

# HTTP Basic auth header (Bearer is covered by _BEARER below)
_BASIC_AUTH = re.compile(
    r"(?i)(Authorization\s*:\s*Basic\s+)[A-Za-z0-9+/=]+"
)

# HTTP bearer tokens — standalone (not anchored to Authorization header)
# so it catches tokens in curl -H, Invoke-WebRequest headers, etc.
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{12,}=*")

# AWS access key id
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

# Modern cloud / SaaS secret tokens with unambiguous vendor prefixes
_MODERN_TOKEN = re.compile(
    r"(?:"
    r"ghp_[A-Za-z0-9]{36}"                    # GitHub PAT (classic)
    r"|github_pat_[A-Za-z0-9_]{36,}"          # GitHub PAT (fine-grained)
    r"|glpat-[A-Za-z0-9_\-]{20}"             # GitLab PAT
    r"|xox[bpars]-[0-9A-Za-z\-]+"            # Slack tokens
    r"|npm_[A-Za-z0-9]{36}"                   # npm token
    r"|sk_live_[A-Za-z0-9]{24,}"             # Stripe secret key
    r"|rk_live_[A-Za-z0-9]{24,}"             # Stripe restricted key
    r"|SK[0-9a-f]{32}"                        # Twilio auth token
    r")"
)

# PowerShell plaintext secure strings
_SECURE_STRING = re.compile(
    r"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)('[^']*'|\"[^\"]*\"|\S+)"
)

# ── Internal hostnames ────────────────────────────────────────────────────────
# UNC path host:  \\fileserver01\share   (IPs already masked, so the char class
# below — must start alphanumeric — never matches a leading "[" of [INTERNAL-IP]).
_UNC_HOST = re.compile(r"(\\\\)([A-Za-z0-9_][A-Za-z0-9_.\-]*)")

# Internal DNS suffixes (Active Directory / corp conventions). Deliberately
# excludes generic short labels (.ad, .home, .lab, .test) that appear in
# decoded payload content as JSON keys or development hostnames.
_INTERNAL_DNS = re.compile(
    r"\b(?:[A-Za-z0-9\-]+\.)+(?:corp|local|internal|intranet|intra|lan|ad|"
    r"domain|dmz|priv|private)\b",
    re.IGNORECASE,
)

# Explicit remote-target flags whose value is a hostname.
# --host accepts both space and = forms (--host myserver / --host=myserver).
# -h omitted: collides with curl/wget header semantics.
_HOST_FLAG = re.compile(
    r"(?i)((?:-ComputerName|-CN|-Server|/node:|-r:|--host[\s=]|-ComputerName:)\s*)"
    r"([A-Za-z_][A-Za-z0-9_.\-]*)"
)

# Same DNS-suffix set as _INTERNAL_DNS, used in is_internal_url() against a
# clean host token from urlparse (no word-boundary needed).
_INTERNAL_DNS_SUFFIX = re.compile(
    r"\.(?:corp|local|internal|intranet|intra|lan|ad|domain|dmz|priv|private)$",
    re.IGNORECASE,
)


def has_unclosed_pem(text: str) -> bool:
    """Return True if *text* starts a PEM key/cert block with no matching END marker.

    Used before truncation: if a decoded layer opens a PEM block that would be
    cut off, we redact the full block from the pre-truncation text rather than
    storing partial key material.
    """
    return len(_PEM_OPEN_RE.findall(text)) > len(_PEM_CLOSE_RE.findall(text))


def is_internal_url(url: str) -> bool:
    """Predicate: does this URL point at a non-public host?

    Used to keep internal infrastructure out of the public corpus and out of
    third-party lookups (VT, AbuseIPDB, OTX). Returns True for private IPs
    (any of v4/v6 private/loopback/link-local/reserved), internal DNS
    suffixes (.corp/.local/.internal/…), and single-label NetBIOS-style
    hostnames (no dot — `\\\\SERVER01` and `http://fileserver` shapes).
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return False
    if not host:
        return False
    # IPv4 / IPv6 — stdlib handles every reserved range correctly.
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass
    if _INTERNAL_DNS_SUFFIX.search(host):
        return True
    # Single-label hostname (no dot) — almost always internal NetBIOS naming.
    if "." not in host:
        return True
    return False


def redact(command: str) -> tuple[str, bool]:
    """Return (redacted_command, was_anything_redacted).

    Masks PEM keys/certs, NTLM hashes, private IPv4/IPv6, credentials
    (flag values, bearer/basic tokens, AWS keys, modern SaaS tokens,
    SecureString plaintext, /user:), and internal hostnames (UNC, internal
    DNS suffixes, remote-target flags).
    Base64 payload blobs are left intact — they are what we exist to analyze.
    """
    out = command
    changed = False

    for pattern, repl in (
        (_PEM_KEY,          "[REDACTED-KEY]"),
        (_PEM_CERT,         "[REDACTED-CERT]"),
        (_NTLM_HASH,        "[NTLM-HASH]"),
        (_PRIVATE_IP,       "[INTERNAL-IP]"),
        (_PRIVATE_IP6,      "[INTERNAL-IP]"),
        (_MODERN_TOKEN,     "[REDACTED-TOKEN]"),
        (_AWS_KEY,          "[REDACTED-AWS-KEY]"),
        (_CREDENTIAL,       r"\1[REDACTED]"),
        (_CREDENTIAL_FLAG,  r"\1[REDACTED]"),
        (_USER_FLAG,        r"\1[REDACTED]"),
        (_BASIC_AUTH,       r"\1[REDACTED]"),
        (_BEARER,           "Bearer [REDACTED]"),
        (_SECURE_STRING,    r"\1[REDACTED]"),
        (_UNC_HOST,         r"\1[INTERNAL-HOST]"),
        (_INTERNAL_DNS,     "[INTERNAL-HOST]"),
        (_HOST_FLAG,        r"\1[INTERNAL-HOST]"),
    ):
        out, n = pattern.subn(repl, out)
        if n:
            changed = True

    return out, changed
