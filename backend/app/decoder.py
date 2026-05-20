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
Recurses up to MAX_LAYERS deep.
"""

from __future__ import annotations

import base64
import gzip
import re
import zlib
from typing import Any
from urllib.parse import unquote

MAX_LAYERS = 5

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
        return gzip.decompress(raw)
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
        # Drop the 8-byte trailer if it looks present; otherwise feed it all.
        body = raw[pos:-8] if len(raw) - pos >= 8 else raw[pos:]
        return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        try:
            return zlib.decompress(raw[pos:], -zlib.MAX_WBITS)
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
            printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
            if printable / len(text) > 0.85:
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
            return _bytes_to_text(gzip.decompress(raw), "base64-gzip")
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
            decompressed = zlib.decompress(raw)
            try:
                return decompressed.decode("utf-8"), "base64-zlib"
            except UnicodeDecodeError:
                pass
            if len(decompressed) % 2 == 0 and len(decompressed) >= 4:
                try:
                    text = decompressed.decode("utf-16-le")
                    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
                    if printable / len(text) > 0.85:
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

def _try_hex_escape(text: str) -> list[tuple[str, str]]:
    """Decode \\x41\\x42 sequences. Returns list of (decoded, label) tuples."""
    results: list[tuple[str, str]] = []
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
    """Decode standalone hex strings of 20+ chars. Tries UTF-8 then UTF-16LE."""
    results: list[tuple[str, str]] = []
    for blob in re.findall(r"\b([0-9a-fA-F]{20,})\b", text):
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

    # Standalone large base64 blobs (not already captured)
    blobs = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    for blob in blobs:
        if blob not in candidates:
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


def _try_env_resolve(text: str) -> list[tuple[str, str]]:
    """Partially resolve known $env: variables. Returns [(resolved_text, label)] or []."""
    resolved = text
    for pattern, replacement in _ENV_SUBS:
        # Use a lambda so backslashes in the replacement are treated as literals,
        # not regex backreference escape sequences.
        resolved = pattern.sub(lambda _m, r=replacement: r, resolved)
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
        if any(len(p) > 6 for p in parts):
            continue
        decoded = "".join(parts)
        if decoded and decoded not in seen and _is_readable(decoded):
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
            decoded = bytes(byte_vals).decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            continue
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

    return results


def decode_layers(command: str) -> list[dict[str, Any]]:
    """Return a list of decode layer dicts, up to MAX_LAYERS deep."""
    layers: list[dict[str, Any]] = []
    current = command
    seen: set[str] = {command}
    hit_limit = False

    for layer_num in range(1, MAX_LAYERS + 1):
        decoded_this_round = False

        for text, encoding in _all_candidates(current):
            if text in seen:
                continue
            seen.add(text)
            layers.append({"layer": layer_num, "encoding": encoding, "value": text})
            current = text
            decoded_this_round = True
            break  # one decode per layer; recurse with the new text

        if not decoded_this_round:
            break

        if layer_num == MAX_LAYERS and decoded_this_round:
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
        })

    return layers
