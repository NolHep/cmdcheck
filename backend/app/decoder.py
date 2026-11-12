"""Multi-encoding decode pipeline.

Handles (in order of attempt per layer):
- Standard base64 / PowerShell -EncodedCommand (UTF-16LE base64)
- gzip-compressed payloads (H4sI prefix after decode); lenient fallback
  recovers content when the CRC32/ISIZE trailer is corrupt (common in
  adversarial / truncated samples — strict `gzip.decompress` would reject)
- zlib/deflate-compressed payloads ([IO.Compression.DeflateStream])
- Hex escape sequences  (\x41\x42\x43)
- Pure hex strings      (4142434445...) — UTF-8 and UTF-16LE
- URL-encoded strings   (%41%42%43)
- PowerShell [char] concatenation  ([char]0x41+[char]66)
- PowerShell backtick obfuscation  (`p`o`w`e`r`s`h`e`l`l → powershell)
- PowerShell string concatenation  ('p'+'ow'+'er'+'shell')
- PowerShell format operator       ('{0}{1}' -f 'po','wershell')
- Literal .replace() / -replace    ('i?e?x'.replace('?',''))
- -replace operator                ('iEX' -replace 'X','x')
- Array reverse of char literal    ([array]::Reverse([char[]]'xei'))
- Char-slice reverse / reorder     ('llehsrewop'[-1..-10] -join '')
- Hex byte array                   ((0x41,0x42,0x43))
- cmd.exe caret escapes            (p^o^w^e^r^s^h^e^l^l)
- cmd.exe in-token quotes          (cert""util, po"w"ershell)
- cmd.exe set-variable expansion   (set x=pow&& call %x%ershell, %COMSPEC:~-7,1%)
- PowerShell known-variable index  ($env:ComSpec[4,24,25]-join'' -> iex)
- Shell `echo ... | rev`
Decoding is a breadth-first tree: every candidate found in a text becomes its
own layer and is itself decoded, up to MAX_LAYERS deep and MAX_TOTAL_LAYERS
in total. A command carrying two encoded blobs yields both.
"""

from __future__ import annotations

import base64
import re
import unicodedata
import zlib
from typing import Any
from urllib.parse import unquote

MAX_LAYERS = 5
# Hard cap on layers returned, so a blob-stuffed paste cannot fan out unbounded.
MAX_TOTAL_LAYERS = 16

# Markers for known encoding types after initial b64 decode
_GZIP_MAGIC = b"\x1f\x8b"
# UTF-16LE BOM or common PowerShell start bytes
_UTF16LE_BOM = b"\xff\xfe"
# zlib/deflate headers: default (0x78 0x9C), no-compression (0x78 0x01),
# best-compression (0x78 0xDA), fast-compression (0x78 0x5E)
_ZLIB_HEADERS = (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e")


def _try_b64_decode(s: str) -> bytes | None:
    """Return decoded bytes if *s* is valid base64, else None.

    Strips ALL whitespace (not just leading/trailing) before attempting decode
    so that base64 blobs split across multiple lines in scripts still work.
    """
    s = re.sub(r"\s+", "", s)
    if not s:
        return None
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def _try_urlsafe_b64_decode(s: str) -> bytes | None:
    """Return decoded bytes if *s* is URL-safe base64 (uses - and _), else None."""
    s = re.sub(r"\s+", "", s)
    if not s or not re.search(r"[-_]", s):
        return None
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


# Ceiling on decompressed output. A few kilobytes of gzip can inflate to
# hundreds of megabytes; nothing an analyst pastes legitimately needs more
# than this, and the classifier only reads the first and last few KB anyway.
MAX_DECOMPRESSED_BYTES = 256 * 1024


def _inflate(raw: bytes, wbits: int) -> bytes:
    """zlib-inflate *raw*, stopping at MAX_DECOMPRESSED_BYTES. Raises zlib.error on bad data."""
    return zlib.decompressobj(wbits).decompress(raw, MAX_DECOMPRESSED_BYTES)


def _gunzip(raw: bytes) -> bytes:
    """Strict gzip decode (header + CRC checked unless output was truncated at the cap)."""
    obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = obj.decompress(raw, MAX_DECOMPRESSED_BYTES)
    if not obj.eof and len(out) < MAX_DECOMPRESSED_BYTES:
        raise zlib.error("incomplete or truncated gzip stream")
    return out


def _lenient_gzip_decompress(raw: bytes) -> bytes | None:
    """Decompress a gzip stream tolerating corrupt CRC32/ISIZE trailers.

    Real-world adversarial samples (pasted from sandboxed/snipped logs) often
    have busted gzip trailers — `gzip.decompress` rejects on CRC mismatch even
    though the deflate body itself is intact. We try strict gzip first, then
    fall back to parsing the header to locate the raw deflate stream and
    decompress with zlib's raw mode (no CRC validation).
    """
    if raw[:2] != _GZIP_MAGIC or len(raw) < 10:
        return None
    try:
        return _gunzip(raw)
    except Exception:
        pass
    # Header parse: skip optional FEXTRA/FNAME/FCOMMENT/FHCRC fields.
    flags = raw[3]
    pos = 10
    try:
        if flags & 0x04:  # FEXTRA
            xlen = int.from_bytes(raw[pos:pos + 2], "little")
            pos += 2 + xlen
        if flags & 0x08:  # FNAME (null-terminated)
            pos = raw.index(b"\x00", pos) + 1
        if flags & 0x10:  # FCOMMENT
            pos = raw.index(b"\x00", pos) + 1
        if flags & 0x02:  # FHCRC
            pos += 2
        # Drop the 8-byte trailer (CRC32 + ISIZE) if the remaining body is long
        # enough that stripping it won't eat actual deflate content. A minimal
        # non-compressed deflate block is 5 bytes, so we need at least 13 bytes
        # total; 18 gives a safe margin for the smallest compressed blocks.
        body = raw[pos:-8] if len(raw) - pos >= 18 else raw[pos:]
        return _inflate(body, -zlib.MAX_WBITS)
    except Exception:
        try:
            return _inflate(raw[pos:], -zlib.MAX_WBITS)
        except Exception:
            return None


def _bytes_to_text(decompressed: bytes, encoding_label: str) -> tuple[str, str] | None:
    """Interpret decompressed bytes as text via UTF-8 → UTF-16LE → latin-1."""
    try:
        return decompressed.decode("utf-8"), encoding_label
    except UnicodeDecodeError:
        pass
    if len(decompressed) % 2 == 0 and len(decompressed) >= 4:
        try:
            text = decompressed.decode("utf-16-le")
            # Use ASCII-range check (same as no-BOM path) — Unicode isprintable()
            # counts emoji/CJK as printable, masking garbage UTF-16LE decodes.
            ascii_printable = sum(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in text)
            if ascii_printable / len(text) > 0.75:
                return text, encoding_label
        except UnicodeDecodeError:
            pass
    return decompressed.decode("latin-1"), encoding_label


def _decode_bytes(raw: bytes) -> tuple[str, str] | None:
    """Try to interpret *raw* as a known encoding. Returns (text, encoding_label) or None."""
    # gzip — with lenient fallback for corrupt-trailer samples
    if raw[:2] == _GZIP_MAGIC:
        # Strict path
        try:
            return _bytes_to_text(_gunzip(raw), "base64-gzip")
        except Exception:
            pass
        # Lenient path: header parse + raw deflate, ignores CRC/ISIZE
        recovered = _lenient_gzip_decompress(raw)
        if recovered is not None:
            return _bytes_to_text(recovered, "base64-gzip (recovered)")
        # Both paths failed — show the hex preview so an analyst can hand-decode.
        hex_preview = raw[:48].hex(" ")
        return (
            f"[gzip header confirmed — decompression failed (truncated/corrupt payload)]\nhex: {hex_preview}...",
            "base64-gzip (truncated)",
        )

    # zlib/deflate — PowerShell [IO.Compression.DeflateStream] payloads
    if raw[:2] in _ZLIB_HEADERS:
        try:
            decompressed = _inflate(raw, zlib.MAX_WBITS)
            try:
                return decompressed.decode("utf-8"), "base64-zlib"
            except UnicodeDecodeError:
                pass
            if len(decompressed) % 2 == 0 and len(decompressed) >= 4:
                try:
                    text = decompressed.decode("utf-16-le")
                    ascii_printable = sum(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in text)
                    if ascii_printable / len(text) > 0.75:
                        return text, "base64-zlib"
                except UnicodeDecodeError:
                    pass
            return decompressed.decode("latin-1"), "base64-zlib"
        except Exception:
            pass

    # UTF-16LE (PowerShell encoded commands — starts with FF FE BOM or produces valid text)
    if raw[:2] == _UTF16LE_BOM:
        try:
            return raw[2:].decode("utf-16-le"), "base64-utf16le"
        except UnicodeDecodeError:
            pass

    # Try UTF-16LE without BOM (common for PS -EncodedCommand)
    # Uses ASCII-range printable ratio, not Unicode isprintable(), because CJK
    # and other non-ASCII chars are "printable" in Python but are a sign of garbage.
    if len(raw) % 2 == 0 and len(raw) >= 4:
        try:
            text = raw.decode("utf-16-le")
            ascii_printable = sum(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in text)
            if ascii_printable / len(text) > 0.75:
                return text, "base64-utf16le"
        except UnicodeDecodeError:
            pass

    # Plain UTF-8
    try:
        return raw.decode("utf-8"), "base64"
    except UnicodeDecodeError:
        pass

    return None


def _is_readable(text: str, threshold: float = 0.85) -> bool:
    if not text:
        return False
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
    return printable / len(text) >= threshold


# ── Hex escape: \x41\x42\x43 ──────────────────────────────────────────────────

_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_ANSI_C_QUOTED = re.compile(r"\$'((?:\\x[0-9a-fA-F]{2})+)'")


def _unhex(seq: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), seq)


def _try_hex_escape(text: str) -> list[tuple[str, str]]:
    """Decode \\x41\\x42 sequences. Returns list of (decoded, label) tuples."""
    results: list[tuple[str, str]] = []
    # Whole-command form first: `$'\x63\x75\x72\x6c' -s http://…` -> `curl -s http://…`
    if _HEX_RUN.search(text):
        whole = _ANSI_C_QUOTED.sub(lambda m: _unhex(m.group(1)), text)
        whole = _HEX_RUN.sub(lambda m: _unhex(m.group(0)), whole)
        if whole != text and _is_readable(whole):
            results.append((whole, "hex-escape"))
    for seq in re.findall(r"(?:\\x[0-9a-fA-F]{2}){3,}", text):
        try:
            decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), seq)
            if _is_readable(decoded):
                results.append((decoded, "hex-escape"))
        except Exception:
            pass
    return results


# ── Pure hex string: 4142434445... ────────────────────────────────────────────

def _try_hex_string(text: str) -> list[tuple[str, str]]:
    """Decode standalone hex strings of 32+ chars (16+ bytes). Tries UTF-8 then UTF-16LE.

    The 20-char minimum (10 bytes) was too short and caused false positives on
    NTLM hashes, timestamps, and other structured hex values that happen to decode
    to printable ASCII. 32 chars (16 bytes) is a more conservative threshold.
    """
    results: list[tuple[str, str]] = []
    for blob in re.findall(r"\b([0-9a-fA-F]{32,})\b", text):
        if len(blob) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(blob)
            # UTF-8 first
            try:
                decoded = raw.decode("utf-8")
                if _is_readable(decoded, threshold=0.9):
                    results.append((decoded, "hex-string"))
                    continue
            except UnicodeDecodeError:
                pass
            # UTF-16LE — common for hex-encoded PowerShell commands
            if len(raw) % 2 == 0 and len(raw) >= 4:
                try:
                    decoded = raw.decode("utf-16-le")
                    ascii_printable = sum(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in decoded)
                    if len(decoded) > 0 and ascii_printable / len(decoded) > 0.75:
                        results.append((decoded, "hex-string-utf16le"))
                except UnicodeDecodeError:
                    pass
        except Exception:
            pass
    return results


# ── URL encoding: %41%42%43 ───────────────────────────────────────────────────

def _try_url_decode(text: str) -> list[tuple[str, str]]:
    """Decode URL-encoded strings. Requires at least 3 encoded sequences to avoid
    false positives on strings that happen to contain a single %XX pattern."""
    encoded_seqs = re.findall(r"%[0-9a-fA-F]{2}", text)
    if len(encoded_seqs) < 3:
        return []
    decoded = unquote(text)
    if decoded == text:
        return []
    return [(decoded, "url-encoded")]


# ── PowerShell [char] concatenation: [char]0x41+[char]66 ─────────────────────

_CHAR_CONCAT_RE = re.compile(
    r"(?:\[\s*[Cc]har\s*\]\s*(?:0x[0-9a-fA-F]+|\d+)\s*[+,]?\s*){3,}"
)


def _try_char_concat(text: str) -> list[tuple[str, str]]:
    """Decode PowerShell [char]N + [char]M sequences."""
    results: list[tuple[str, str]] = []
    for m in _CHAR_CONCAT_RE.finditer(text):
        values = re.findall(r"\[\s*[Cc]har\s*\]\s*(0x[0-9a-fA-F]+|\d+)", m.group(0))
        if len(values) < 3:
            continue
        try:
            decoded = "".join(
                chr(int(v, 16) if v.lower().startswith("0x") else int(v))
                for v in values
            )
            if _is_readable(decoded):
                results.append((decoded, "char-concat"))
        except Exception:
            pass
    return results


def _extract_b64_candidates(text: str) -> list[str]:
    """Pull base64 blobs out of a command string."""
    candidates: list[str] = []

    # PowerShell -EncodedCommand and all valid abbreviations down to -e
    # (any unambiguous prefix of -EncodedCommand is accepted by PS)
    ps_enc = re.findall(
        r"(?:-EncodedCommand|-[Ee][Nn][Cc](?:[Oo][Dd][Ee][Dd](?:[Cc][Oo][Mm][Mm][Aa][Nn][Dd])?)?|-[Ee][Nn]\b|-[Ee][Cc]\b|-[Ee]\b)\s+([A-Za-z0-9+/=]{20,})",
        text,
    )
    candidates.extend(ps_enc)

    # .NET [Convert]::FromBase64String('...') / [System.Convert]::FromBase64String('...')
    dotnet = re.findall(
        r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]",
        text, re.IGNORECASE,
    )
    for d in dotnet:
        if d not in candidates:
            candidates.append(d)

    # Shell / scripting idioms that carry a blob too short for the standalone
    # rule below: `echo <b64> | base64 -d`, `base64 -d <<< <b64>`,
    # python `b64decode('<b64>')`, JS `atob('<b64>')`.
    for pat in (
        r"echo\s+(?:-[ne]+\s+)?['\"]?([A-Za-z0-9+/]{12,}={0,2})['\"]?\s*\|\s*base64\s+-(?:d|D|-decode)\b",
        r"base64\s+-(?:d|D|-decode)\s*<<<\s*['\"]?([A-Za-z0-9+/]{12,}={0,2})",
        r"echo\s+(?:-[ne]+\s+)?['\"]?([A-Za-z0-9+/]{12,}={0,2})['\"]?\s*\|\s*openssl\s+(?:base64|enc\s+-base64)\s+-d\b",
        r"(?:b64decode|atob|decode64|base64_decode)\s*\(\s*b?['\"]([A-Za-z0-9+/]{12,}={0,2})['\"]",
    ):
        for d in re.findall(pat, text, re.IGNORECASE):
            if d not in candidates:
                candidates.append(d)

    # Standalone large base64 blobs (not already captured)
    blobs = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    for blob in blobs:
        if blob not in candidates:
            candidates.append(blob)

    return candidates


def _extract_urlsafe_b64_candidates(text: str) -> list[str]:
    """Pull URL-safe base64 blobs (using - and _) out of a command string."""
    candidates: list[str] = []
    # Must contain at least one - or _ to distinguish from standard base64.
    # Require 40+ chars so short tokens (UUIDs, flags) don't trigger decodes.
    for blob in re.findall(r"[A-Za-z0-9\-_]{40,}={0,2}", text):
        if re.search(r"[-_]", blob):
            candidates.append(blob)
    return candidates


# ── $env: variable substitution ───────────────────────────────────────────────

# Known Windows environment variables → typical resolved values.
# Used to partially normalise obfuscated commands before further analysis.
_ENV_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\$env:ComSpec", re.IGNORECASE),             "cmd.exe"),
    (re.compile(r"\$env:SystemRoot\\?", re.IGNORECASE),       "C:\\Windows"),
    (re.compile(r"\$env:WinDir\\?", re.IGNORECASE),           "C:\\Windows"),
    (re.compile(r"\$env:Temp\\?", re.IGNORECASE),             "C:\\Windows\\Temp"),
    (re.compile(r"\$env:Tmp\\?", re.IGNORECASE),              "C:\\Windows\\Temp"),
    (re.compile(r"\$env:Public\\?", re.IGNORECASE),           "C:\\Users\\Public"),
    (re.compile(r"\$env:ProgramFiles\b", re.IGNORECASE),      "C:\\Program Files"),
    (re.compile(r"\$env:SystemDrive\\?", re.IGNORECASE),      "C:"),
    (re.compile(r"\$env:APPDATA\\?", re.IGNORECASE),          "C:\\Users\\User\\AppData\\Roaming"),
    (re.compile(r"\$env:LOCALAPPDATA\\?", re.IGNORECASE),     "C:\\Users\\User\\AppData\\Local"),
    (re.compile(r"\$env:USERPROFILE\\?", re.IGNORECASE),      "C:\\Users\\User"),
    (re.compile(r"\$env:USERNAME", re.IGNORECASE),            "User"),
    (re.compile(r"\$env:COMPUTERNAME", re.IGNORECASE),        "WORKSTATION"),
]


# `$env:ComSpec[4,24,25]` is an index trick, handled by _try_ps_index — leave it.
_INDEX_FOLLOWS = re.compile(r"\s*\[")


def _try_env_resolve(text: str) -> list[tuple[str, str]]:
    """Partially resolve known $env: variables. Returns [(resolved_text, label)] or []."""
    resolved = text
    for pattern, replacement in _ENV_SUBS:
        # Use a lambda so backslashes in the replacement are treated as literals,
        # not regex backreference escape sequences.
        resolved = pattern.sub(
            lambda m, r=replacement: m.group(0) if _INDEX_FOLLOWS.match(m.string, m.end()) else r,
            resolved,
        )
    if resolved == text:
        return []
    return [(resolved, "env-variable-substitution")]


# ── String obfuscation (PowerShell layer-0) ───────────────────────────────────
# Lumma, Latrodectus, and ClickFix payloads routinely hide commands in
# string concatenation, format-operator, and .replace() expressions that survive
# encoding decoders. These resolve those literal-string expressions only — we
# never evaluate variables or unknown function calls.

# 'p'+'o'+'w' …  (≥3 quoted literals joined with +)
_CONCAT_RE = re.compile(r"(?:['\"][^'\"]*['\"]\s*\+\s*){2,}['\"][^'\"]*['\"]")
_STR_LIT_RE = re.compile(r"['\"]([^'\"]*)['\"]")

# When the concatenated result contains one of these tokens the join is almost
# certainly obfuscation, not benign string-building — bypass the piece-length
# cap so `'Invoke-' + 'Expr' + 'ession'` (7-char piece) still fires.
_CONCAT_ATTACK_KEYWORDS = frozenset({
    "invoke-expression", "iex", "downloadstring", "downloadfile", "downloaddata",
    "webrequest", "webclient", "net.webclient",
    "amsi", "amsiinitfailed", "amsiscanbypass",
    "encodedcommand", "noprofile", "bypass", "hidden",
    "reflection.assembly", "frombase64string",
    "shellcode", "createremotethread", "virtualalloc",
    "mimikatz", "sekurlsa", "rubeus", "kerberoast",
})


def _try_string_concat(text: str) -> list[tuple[str, str]]:
    """Resolve 'a' + 'b' + 'c' chains of three or more quoted string literals.

    Real PowerShell obfuscation splits identifiers into very short fragments
    ('p'+'ow'+'er'+'shell'); benign string-building joins whole words
    ('hello' + 'world' + '!'). Capping max piece length at 6 cleanly
    separates the two without losing real obfuscation patterns.
    """
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _CONCAT_RE.finditer(text):
        parts = _STR_LIT_RE.findall(m.group(0))
        if len(parts) < 3:
            continue
        decoded = "".join(parts)
        if not decoded or not _is_readable(decoded):
            continue
        # Bypass the piece-length cap when the result contains a known attack
        # token — obfuscation can split 'Invoke-' (7 chars) across fragments.
        # Apply the cap only for results that don't match any attack keyword.
        decoded_lower = decoded.lower()
        is_attack = any(kw in decoded_lower for kw in _CONCAT_ATTACK_KEYWORDS)
        if not is_attack and any(len(p) > 6 for p in parts):
            continue
        if decoded not in seen:
            seen.add(decoded)
            results.append((decoded, "string-concat"))
    return results


# ('{0}{1}…' -f 'a','b',…)  — PowerShell format operator with literal args only
_FORMAT_RE = re.compile(
    r"\(\s*['\"]([^'\"]*\{\d+(?::[^{}]*)?\}[^'\"]*)['\"]\s*-f\s+([^)]+)\)",
    re.IGNORECASE,
)


def _try_format_op(text: str) -> list[tuple[str, str]]:
    """Resolve ('{0}{1}' -f 'a','b'). Only fires when all args are literals."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _FORMAT_RE.finditer(text):
        fmt, args_blob = m.group(1), m.group(2)
        args = _STR_LIT_RE.findall(args_blob)
        if not args:
            continue
        try:
            decoded = fmt.format(*args)
        except (IndexError, KeyError, ValueError):
            continue
        if decoded and decoded not in seen and _is_readable(decoded):
            seen.add(decoded)
            results.append((decoded, "format-op"))
    return results


# 'string'.replace('x','y')  — literal-only .replace() chains (common: strip a char)
_REPLACE_RE = re.compile(
    r"['\"]([^'\"]*)['\"]\s*\.\s*replace\s*\(\s*['\"]([^'\"]*)['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)",
    re.IGNORECASE,
)


def _try_dot_replace(text: str) -> list[tuple[str, str]]:
    """Resolve 'haystack'.replace('needle','rep') when all three are literals."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _REPLACE_RE.finditer(text):
        s, old, new = m.group(1), m.group(2), m.group(3)
        if not old:
            continue
        decoded = s.replace(old, new)
        if decoded != s and decoded not in seen and _is_readable(decoded):
            seen.add(decoded)
            results.append((decoded, "dot-replace"))
    return results


# PowerShell backtick obfuscation: `p`o`w`e`r`s`h`e`l`l → powershell
# The PS engine treats `` ` `` as an escape that's a no-op before normal letters,
# so attackers sprinkle backticks inside tokens to hide them from naive string
# matching (and break `bashlex` parsing too). The lookahead `(?=[A-Za-z0-9])`
# only matches backticks that precede an alphanumeric, so line-continuation
# backticks (`` ` `` followed by a newline / whitespace) are preserved.
_BACKTICK_OBFUSC = re.compile(r"`(?=[A-Za-z0-9])")


def _try_backtick_strip(text: str) -> list[tuple[str, str]]:
    """Strip PowerShell backtick obfuscation. Requires 3+ in-token backticks
    so a single legitimate backtick-escape doesn't trigger a decode layer."""
    if len(_BACKTICK_OBFUSC.findall(text)) < 3:
        return []
    decoded = _BACKTICK_OBFUSC.sub("", text)
    if decoded == text or not _is_readable(decoded):
        return []
    return [(decoded, "powershell-backtick")]


# 'string' -replace 'pat','rep'  (operator form, sibling of .replace() method)
# -replace is regex by default; we try regex first and fall back to literal
# replacement so a pattern containing a regex metachar still resolves.
_REPLACE_OP_RE = re.compile(
    r"['\"]([^'\"]+)['\"]\s*-c?replace\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]*)['\"])?",
    re.IGNORECASE,
)


def _try_replace_op(text: str) -> list[tuple[str, str]]:
    """Resolve 'haystack' -replace 'pat','rep' / 'haystack' -creplace 'pat'."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _REPLACE_OP_RE.finditer(text):
        s, old, new = m.group(1), m.group(2), m.group(3) or ""
        if not old:
            continue
        try:
            decoded = re.sub(old, new, s)
        except re.error:
            decoded = s.replace(old, new)
        if decoded != s and decoded not in seen and _is_readable(decoded):
            seen.add(decoded)
            results.append((decoded, "replace-op"))
    return results


# Hex byte array: (0x41,0x42,0x43,…) — common shellcode/payload representation.
# Require ≥4 bytes to suppress benign 2-tuple usage like (0x1F,0x8B) for magic
# bytes; an actual hidden payload is always many bytes.
_HEX_ARRAY_RE = re.compile(r"(?:0x[0-9a-fA-F]{1,2}\s*,\s*){3,}0x[0-9a-fA-F]{1,2}")


def _try_hex_array(text: str) -> list[tuple[str, str]]:
    """Decode (0x41,0x42,0x43,…) byte arrays as UTF-8 text where readable."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _HEX_ARRAY_RE.finditer(text):
        try:
            byte_vals = [int(b.strip(), 16) for b in m.group(0).split(",")]
            if any(b > 0xFF for b in byte_vals):
                continue
            raw_bytes = bytes(byte_vals)
        except ValueError:
            continue
        try:
            decoded = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Latin-1 always succeeds but produces garbage for non-text arrays;
            # _is_readable() below will reject non-printable results.
            decoded = raw_bytes.decode("latin-1")
        if decoded and decoded not in seen and _is_readable(decoded):
            seen.add(decoded)
            results.append((decoded, "hex-array"))
    return results


# 'literal'[-1..-N] -join '' (PowerShell character-slice obfuscation).
# When start > end, the slice walks the string backwards — the canonical
# string-reverse idiom that doesn't need [array]::Reverse.
_SLICE_JOIN_RE = re.compile(
    r"['\"]([^'\"]{3,})['\"]\s*\[\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\]\s*-join\s*['\"]['\"]"
)


def _try_slice_join(text: str) -> list[tuple[str, str]]:
    """Resolve 'literal'[start..end] -join '' — covers reverse and reorder."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _SLICE_JOIN_RE.finditer(text):
        s = m.group(1)
        start, end = int(m.group(2)), int(m.group(3))
        n = len(s)
        # PowerShell: negative index = from end (-1 == last char)
        a = n + start if start < 0 else start
        b = n + end if end < 0 else end
        if not (0 <= a < n and 0 <= b < n):
            continue
        step = 1 if a <= b else -1
        decoded = "".join(s[i] for i in range(a, b + step, step))
        if decoded and decoded != s and decoded not in seen and _is_readable(decoded):
            seen.add(decoded)
            results.append((decoded, "slice-join"))
    return results


# [array]::Reverse([char[]]'literal')  /  -join 'literal'[-1..-N]
_ARRAY_REVERSE_RE = re.compile(
    r"\[\s*array\s*\]\s*::\s*reverse\s*\(\s*\[\s*char\s*\[\s*\]\s*\]\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def _try_array_reverse(text: str) -> list[tuple[str, str]]:
    """Resolve [array]::Reverse([char[]]'literal') by reversing the literal."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _ARRAY_REVERSE_RE.finditer(text):
        decoded = m.group(1)[::-1]
        if decoded and decoded not in seen and _is_readable(decoded):
            seen.add(decoded)
            results.append((decoded, "array-reverse"))
    return results


# ── cmd.exe obfuscation ───────────────────────────────────────────────────────
# cmd treats ^ as an escape that vanishes before ordinary characters, and
# drops quote pairs inside a token — both are used to split a binary or flag
# name so string matching misses it (Invoke-DOSfuscation).

_CARET_IN_TOKEN = re.compile(r"(?<=[A-Za-z0-9])\^(?=[A-Za-z0-9])")


# A caret inside the token at command position (`r^eg add`, `s^c stop`) is
# never accidental, however few there are.
_CARET_IN_COMMAND = re.compile(r"(?:^|[&|(;]\s*)[A-Za-z]+\^[A-Za-z]")


def _try_cmd_caret(text: str) -> list[tuple[str, str]]:
    """Strip cmd.exe caret escapes: 2+ in-token carets, or one in a command name."""
    if len(_CARET_IN_TOKEN.findall(text)) < 2 and not _CARET_IN_COMMAND.search(text):
        return []
    decoded = re.sub(r"\^(?!\^)", "", text)
    if decoded == text:
        return []
    return [(decoded, "cmd-caret")]


# "" or "x" wedged between letters of one token: cert""util, po"w"ershell
_QUOTE_IN_TOKEN = re.compile(r"(?<=[A-Za-z])([\"'])([A-Za-z]{0,4})\1(?=[A-Za-z])")


def _try_cmd_quote_split(text: str) -> list[tuple[str, str]]:
    """Remove quote pairs embedded inside a token."""
    if not _QUOTE_IN_TOKEN.search(text):
        return []
    decoded = _QUOTE_IN_TOKEN.sub(lambda m: m.group(2), text)
    if decoded == text:
        return []
    return [(decoded, "cmd-quote-split")]


# Values cmd.exe would expand; used only for substring (%VAR:~a,b%) tricks.
_CMD_KNOWN_VARS: dict[str, str] = {
    "comspec": r"C:\WINDOWS\system32\cmd.exe",
    "systemroot": r"C:\WINDOWS",
    "windir": r"C:\WINDOWS",
    "programfiles": r"C:\Program Files",
    "commonprogramfiles": r"C:\Program Files\Common Files",
    "public": r"C:\Users\Public",
    "allusersprofile": r"C:\ProgramData",
    "programdata": r"C:\ProgramData",
    "systemdrive": "C:",
    "homedrive": "C:",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "os": "Windows_NT",
}
_CMD_SET_RE = re.compile(
    r"(?:^|[\s&|(\"])set\s+\"?([A-Za-z_][A-Za-z0-9_]*)=([^&|\"\r\n]*)", re.IGNORECASE
)
_CMD_VAR_RE = re.compile(r"([%!])([A-Za-z_][A-Za-z0-9_]*)(?::~(-?\d+)(?:,(-?\d+))?)?\1")


def _cmd_substring(value: str, start: str | None, length: str | None) -> str:
    if start is None:
        return value
    a = int(start)
    if a < 0:
        a = max(len(value) + a, 0)
    if length is None:
        return value[a:]
    n = int(length)
    return value[a:a + n] if n >= 0 else value[a:len(value) + n]


def _try_cmd_vars(text: str) -> list[tuple[str, str]]:
    """Expand `set x=…` variables and %VAR:~a,b% substrings of known variables."""
    user_vars = {m.group(1).lower(): m.group(2).rstrip() for m in _CMD_SET_RE.finditer(text)}
    used_substring = False

    def _sub(m: re.Match[str]) -> str:
        nonlocal used_substring
        name = m.group(2).lower()
        if name in user_vars:
            value = user_vars[name]
        elif m.group(3) is not None and name in _CMD_KNOWN_VARS:
            value = _CMD_KNOWN_VARS[name]
        else:
            return m.group(0)
        if m.group(3) is not None:
            used_substring = True
        return _cmd_substring(value, m.group(3), m.group(4))

    decoded = _CMD_VAR_RE.sub(_sub, text)
    if decoded == text:
        return []
    # Plain %x% expansion is ordinary batch scripting; carving characters out
    # of a variable with :~ is deliberate obfuscation and is labelled as such.
    return [(decoded, "cmd-substring" if used_substring else "cmd-variable-substitution")]


# ── PowerShell known-variable indexing ────────────────────────────────────────
# `$env:ComSpec[4,24,25]-join''` spells "Iex" out of a path every Windows box
# has. Only variables with a fixed, well-known value are resolved.
_PS_KNOWN_VARS: dict[str, str] = {
    "$env:comspec": r"C:\WINDOWS\system32\cmd.exe",
    "$pshome": r"C:\Windows\System32\WindowsPowerShell\v1.0",
    "$shellid": "Microsoft.PowerShell",
    "$env:public": r"C:\Users\Public",
    "$env:systemroot": r"C:\WINDOWS",
    "$env:windir": r"C:\WINDOWS",
    "$env:programfiles": r"C:\Program Files",
    "$verbosepreference.tostring()": "SilentlyContinue",
}
_PS_INDEX_RE = re.compile(
    r"(" + "|".join(re.escape(k) for k in _PS_KNOWN_VARS) + r")\s*\[\s*(-?\d+(?:\s*,\s*-?\d+)*)\s*\]"
    r"(?:\s*-join\s*['\"]['\"])?",
    re.IGNORECASE,
)
_ADJACENT_LITERALS = re.compile(r"'([^']*)'\s*\+\s*'([^']*)'")


def _try_ps_index(text: str) -> list[tuple[str, str]]:
    """Resolve indexing into well-known PowerShell variables to a string literal."""

    def _sub(m: re.Match[str]) -> str:
        value = _PS_KNOWN_VARS[m.group(1).lower()]
        try:
            chars = "".join(value[int(i)] for i in m.group(2).split(","))
        except (IndexError, ValueError):
            return m.group(0)
        return f"'{chars}'"

    decoded = _PS_INDEX_RE.sub(_sub, text)
    if decoded == text:
        return []
    prev = None
    while prev != decoded:
        prev = decoded
        decoded = _ADJACENT_LITERALS.sub(lambda m: f"'{m.group(1)}{m.group(2)}'", decoded)
    return [(decoded, "powershell-index")]


# ── Unicode look-alikes ───────────────────────────────────────────────────────
# PowerShell accepts en dash, em dash and horizontal bar as the parameter
# prefix; word processors turn straight quotes and hyphens into typographic
# ones; zero-width characters split a keyword invisibly; fullwidth letters
# render like ASCII. All of it defeats naive matching, and all of it also
# happens innocently when a command is pasted out of a document — so this is a
# normalisation layer, never counted as obfuscation.
_UNICODE_MAP = str.maketrans({
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-",
    "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'",
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"',
    "\u00a0": " ", "\u2007": " ", "\u202f": " ", "\u3000": " ",
    "\u200b": None, "\u200c": None, "\u200d": None, "\u2060": None, "\ufeff": None, "\u00ad": None,
})


def _try_unicode_normalize(text: str) -> list[tuple[str, str]]:
    """Fold typographic dashes/quotes, zero-width characters and fullwidth forms to ASCII."""
    if text.isascii():
        return []
    decoded = unicodedata.normalize("NFKC", text.translate(_UNICODE_MAP)).translate(_UNICODE_MAP)
    if decoded == text:
        return []
    return [(decoded, "unicode-normalization")]


# ── POSIX shell word tricks ───────────────────────────────────────────────────
# `w\get`, `a=cu;b=rl;$a$b`, `${IFS}` — the shell reassembles these before
# running them; string matching sees nothing.
_WINDOWS_PATH_HINT = re.compile(r"[A-Za-z]:\\|\\\\|%\w+%")
_BACKSLASH_IN_COMMAND = re.compile(r"(?:^|[|;&(]\s*)[a-z]+\\[a-z]")
_BACKSLASH_LETTER = re.compile(r"(?<=[a-z])\\(?=[a-z])")


def _try_bash_backslash(text: str) -> list[tuple[str, str]]:
    r"""Drop backslashes inside a command word (`w\get` -> `wget`). POSIX text only."""
    if _WINDOWS_PATH_HINT.search(text) or not _BACKSLASH_IN_COMMAND.search(text):
        return []
    decoded = _BACKSLASH_LETTER.sub("", text)
    return [(decoded, "shell-backslash")] if decoded != text else []


_IFS_RE = re.compile(r"\$\{IFS\}|\$IFS(?![A-Za-z0-9_])|\{IFS\}")


def _try_shell_ifs(text: str) -> list[tuple[str, str]]:
    """Replace ${IFS} / $IFS word separators with a space."""
    if len(_IFS_RE.findall(text)) < 2:
        return []
    return [(_IFS_RE.sub(" ", text), "shell-ifs")]


_SH_ASSIGN_RE = re.compile(
    r"(?:^|[;&|\s])([A-Za-z_][A-Za-z0-9_]{0,30})=(?:'([^']{0,60})'|\"([^\"$`]{0,60})\"|([^\s;&|'\"$`()]{1,60}))(?=[;&\s]|$)"
)
_SH_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_SH_ADJACENT_REFS = re.compile(r"(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?){2,}")


def _try_shell_vars(text: str) -> list[tuple[str, str]]:
    """Expand `a=cu;b=rl;$a$b`. Only variables assigned a literal in the same text."""
    if _WINDOWS_PATH_HINT.search(text):
        return []
    assigned = {
        m.group(1): next(g for g in m.groups()[1:] if g is not None)
        for m in _SH_ASSIGN_RE.finditer(text)
    }
    if not assigned:
        return []
    assembled = any(
        all(name in assigned for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", m.group(0)))
        for m in _SH_ADJACENT_REFS.finditer(text)
    )

    def _sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return assigned.get(name, m.group(0))

    decoded = _SH_REF_RE.sub(_sub, text)
    if decoded == text:
        return []
    # Gluing two variables into one word is assembly (obfuscation); using a
    # variable where a word goes is just scripting.
    return [(decoded, "shell-variable-assembly" if assembled else "shell-variable-substitution")]


# ── PowerShell variables and char arrays ─────────────────────────────────────
_PS_ASSIGN_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]{0,30})\s*=\s*'([^']{0,200})'")
_PS_CONCAT_REFS = re.compile(r"\$[A-Za-z_]\w*\s*\+\s*\$[A-Za-z_]\w*|'\s*\+\s*\$[A-Za-z_]\w*|\$[A-Za-z_]\w*\s*\+\s*'")


def _try_ps_vars(text: str) -> list[tuple[str, str]]:
    """Substitute `$a='IE';$b='X';&($a+$b)` -> `&('IEX')`. Literal string assignments only."""
    assigned = {m.group(1).lower(): m.group(2) for m in _PS_ASSIGN_RE.finditer(text)}
    if not assigned or not _PS_CONCAT_REFS.search(text):
        return []

    def _sub(m: re.Match[str]) -> str:
        value = assigned.get(m.group(1).lower())
        return m.group(0) if value is None else f"'{value}'"

    # Leave the assignments themselves (`$a=`) untouched.
    decoded = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_])(?!\s*=)", _sub, text)
    prev = None
    while prev != decoded:
        prev = decoded
        decoded = _ADJACENT_LITERALS.sub(lambda m: f"'{m.group(1)}{m.group(2)}'", decoded)
    return [(decoded, "powershell-variable-assembly")] if decoded != text else []


_CHAR_ARRAY_RE = re.compile(
    r"\[\s*char\s*\[\s*\]\s*\]\s*\(?\s*((?:0x[0-9a-fA-F]{1,4}|\d{1,5})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})){2,})\s*\)?"
    r"(?:\s*-join\s*['\"]['\"])?",
    re.IGNORECASE,
)


def _try_char_array(text: str) -> list[tuple[str, str]]:
    """Resolve `[char[]](73,69,88)-join''` to `'IEX'` in place."""

    def _sub(m: re.Match[str]) -> str:
        try:
            chars = "".join(chr(int(v, 0)) for v in re.split(r"\s*,\s*", m.group(1)))
        except (ValueError, OverflowError):
            return m.group(0)
        return f"'{chars}'" if _is_readable(chars) and "'" not in chars else m.group(0)

    decoded = _CHAR_ARRAY_RE.sub(_sub, text)
    return [(decoded, "char-array")] if decoded != text else []


# ── Shell `echo '…' | rev` ────────────────────────────────────────────────────
_REV_RE = re.compile(r"echo\s+(?:-[ne]+\s+)?(['\"])(.{4,}?)\1\s*\|\s*rev\b")


def _try_shell_rev(text: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for m in _REV_RE.finditer(text):
        decoded = m.group(2)[::-1]
        if _is_readable(decoded):
            results.append((decoded, "shell-rev"))
    return results


def _all_candidates(text: str) -> list[tuple[str, str]]:
    """Return all (decoded_text, encoding_label) candidates from all strategies."""
    results: list[tuple[str, str]] = []

    # Base64 (highest priority — most common in real malware)
    for blob in _extract_b64_candidates(text):
        raw = _try_b64_decode(blob)
        if raw is not None:
            decoded = _decode_bytes(raw)
            if decoded:
                results.append(decoded)

    # URL-safe base64 (JWTs, some C2 frameworks use - and _ alphabet)
    for blob in _extract_urlsafe_b64_candidates(text):
        raw = _try_urlsafe_b64_decode(blob)
        if raw is not None:
            decoded = _decode_bytes(raw)
            if decoded:
                results.append(decoded)

    # Hex escape sequences
    results.extend(_try_hex_escape(text))

    # Pure hex strings
    results.extend(_try_hex_string(text))

    # URL encoding
    results.extend(_try_url_decode(text))

    # PowerShell [char] concatenation
    results.extend(_try_char_concat(text))

    # $env: variable substitution
    results.extend(_try_env_resolve(text))

    # String obfuscation (PowerShell layer-0)
    results.extend(_try_backtick_strip(text))
    results.extend(_try_string_concat(text))
    results.extend(_try_format_op(text))
    results.extend(_try_dot_replace(text))
    results.extend(_try_replace_op(text))
    results.extend(_try_array_reverse(text))
    results.extend(_try_slice_join(text))
    results.extend(_try_hex_array(text))

    # cmd.exe / known-variable / shell tricks
    results.extend(_try_unicode_normalize(text))
    results.extend(_try_bash_backslash(text))
    results.extend(_try_shell_ifs(text))
    results.extend(_try_shell_vars(text))
    results.extend(_try_ps_vars(text))
    results.extend(_try_char_array(text))
    results.extend(_try_cmd_caret(text))
    results.extend(_try_cmd_quote_split(text))
    results.extend(_try_cmd_vars(text))
    results.extend(_try_ps_index(text))
    results.extend(_try_shell_rev(text))

    return results


def decode_layers(command: str) -> list[dict[str, Any]]:
    """Return decode layers as a breadth-first tree flattened in discovery order.

    `layer` is the depth at which a value was revealed (1 = decoded straight
    from the pasted command). `parent` is the 1-based position in the returned
    list of the layer it was decoded from, or 0 for the command itself. Every
    candidate in a text is followed, not just the first, so two independent
    blobs in one command both surface.
    """
    layers: list[dict[str, Any]] = []
    seen: set[str] = {command}
    frontier: list[tuple[str, int]] = [(command, 0)]
    hit_limit = False

    for depth in range(1, MAX_LAYERS + 1):
        next_frontier: list[tuple[str, int]] = []
        for source, parent in frontier:
            for text, encoding in _all_candidates(source):
                if text in seen or not text.strip():
                    continue
                if len(layers) >= MAX_TOTAL_LAYERS:
                    hit_limit = True
                    break
                seen.add(text)
                layers.append({"layer": depth, "encoding": encoding, "value": text, "parent": parent})
                next_frontier.append((text, len(layers)))
            if hit_limit:
                break
        if hit_limit or not next_frontier:
            break
        frontier = next_frontier
        if depth == MAX_LAYERS:
            hit_limit = True

    if hit_limit:
        layers.append({
            "layer": MAX_LAYERS + 1,
            "encoding": "limit-reached",
            "value": (
                f"[Maximum decode depth reached ({MAX_LAYERS} layers). "
                "Complex obfuscation detected — manual review recommended. "
                "Additional encoding layers likely remain."
            ),
            "parent": 0,
        })

    return layers


# Layers that tidy the text rather than unwrap something hidden: env-var
# expansion, plain batch-variable expansion, Unicode folding, the limit marker,
# and string templating that also fires on benign string-building. They are
# classified like any other layer but earn no obfuscation credit.
NORMALIZATION_ENCODINGS = frozenset({
    "env-variable-substitution", "cmd-variable-substitution", "unicode-normalization",
    "shell-variable-substitution",
    "limit-reached", "format-op", "dot-replace",
})


def obfuscation_depths(layers: list[dict[str, Any]]) -> list[int]:
    """Return, per layer, how many *real* decode steps separate it from the command.

    A normalisation layer inherits its parent's depth; every other layer adds
    one. Hand-built layer lists without `parent` (older rows, unit tests) fall
    back to the stored `layer` number.
    """
    depths: list[int] = []
    for layer in layers:
        if "parent" not in layer:
            depths.append(int(layer.get("layer", 1) or 1))
            continue
        parent = int(layer.get("parent", 0) or 0)
        base = depths[parent - 1] if 0 < parent <= len(depths) else 0
        depths.append(base + (0 if layer.get("encoding") in NORMALIZATION_ENCODINGS else 1))
    return depths


def deepest_chain(layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the layers on the path from the command to the deepest decode.

    Layers form a tree; the UI headline and the narrative want the single
    longest unwrapping (base64 -> gzip -> ...). Ties go to the first found.
    Rows stored before `parent` existed are a plain chain and returned as is.
    """
    real = [layer for layer in layers if layer.get("encoding") != "limit-reached"]
    if not real:
        return []
    if any("parent" not in layer for layer in real):
        return real
    leaf = max(real, key=lambda layer: int(layer.get("layer", 1) or 1))
    chain = [leaf]
    while int(chain[-1].get("parent", 0) or 0) > 0:
        chain.append(layers[int(chain[-1]["parent"]) - 1])
    chain.reverse()
    return chain
