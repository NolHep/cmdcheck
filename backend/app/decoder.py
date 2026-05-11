"""Multi-encoding decode pipeline.

Handles (in order of attempt per layer):
- Standard base64 / PowerShell -EncodedCommand (UTF-16LE base64)
- gzip-compressed payloads (H4sI prefix after decode)
- Hex escape sequences  (\x41\x42\x43)
- Pure hex strings      (4142434445...)
- URL-encoded strings   (%41%42%43)
- PowerShell [char] concatenation  ([char]0x41+[char]66)
Recurses up to MAX_LAYERS deep.
"""

from __future__ import annotations

import base64
import gzip
import re
from typing import Any
from urllib.parse import unquote

MAX_LAYERS = 5

# Markers for known encoding types after initial b64 decode
_GZIP_MAGIC = b"\x1f\x8b"
# UTF-16LE BOM or common PowerShell start bytes
_UTF16LE_BOM = b"\xff\xfe"


def _try_b64_decode(s: str) -> bytes | None:
    """Return decoded bytes if *s* is valid base64, else None."""
    s = s.strip()
    # Pad if necessary
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def _decode_bytes(raw: bytes) -> tuple[str, str] | None:
    """Try to interpret *raw* as a known encoding. Returns (text, encoding_label) or None."""
    # gzip
    if raw[:2] == _GZIP_MAGIC:
        try:
            decompressed = gzip.decompress(raw)
            # UTF-8 first — most PS/shell scripts are UTF-8
            try:
                return decompressed.decode("utf-8"), "base64-gzip"
            except UnicodeDecodeError:
                pass
            # UTF-16LE with printability guard (PS -EncodedCommand inside gzip)
            if len(decompressed) % 2 == 0 and len(decompressed) >= 4:
                try:
                    text = decompressed.decode("utf-16-le")
                    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
                    if printable / len(text) > 0.85:
                        return text, "base64-gzip"
                except UnicodeDecodeError:
                    pass
            return decompressed.decode("latin-1"), "base64-gzip"
        except Exception:
            # Gzip header confirmed but decompression failed — truncated or corrupt payload.
            hex_preview = raw[:48].hex(" ")
            return f"[gzip header confirmed — decompression failed (truncated/corrupt payload)]\nhex: {hex_preview}...", "base64-gzip (truncated)"

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
    """Decode standalone hex strings of 20+ chars."""
    results: list[tuple[str, str]] = []
    for blob in re.findall(r"\b([0-9a-fA-F]{20,})\b", text):
        if len(blob) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8")
            if _is_readable(decoded, threshold=0.9):
                results.append((decoded, "hex-string"))
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

    # PowerShell -EncodedCommand / -enc / -en
    ps_enc = re.findall(
        r"(?:-EncodedCommand|-[Ee][Nn][Cc](?:[Oo][Dd][Ee][Dd](?:[Cc][Oo][Mm][Mm][Aa][Nn][Dd])?)?)\s+([A-Za-z0-9+/=]{20,})",
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
