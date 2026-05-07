"""Base64 / encoding decode pipeline.

Handles:
- Standard base64
- PowerShell -EncodedCommand (UTF-16LE base64)
- gzip-compressed payloads (H4sI prefix after decode)
Recurses up to MAX_LAYERS deep.
"""

from __future__ import annotations

import base64
import gzip
import re
from typing import Any

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
            # After gzip, try UTF-16LE then UTF-8
            for enc in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    return decompressed.decode(enc), f"base64-gzip"
                except UnicodeDecodeError:
                    continue
        except Exception:
            pass

    # UTF-16LE (PowerShell encoded commands — starts with FF FE BOM or produces valid text)
    if raw[:2] == _UTF16LE_BOM:
        try:
            return raw[2:].decode("utf-16-le"), "base64-utf16le"
        except UnicodeDecodeError:
            pass

    # Try UTF-16LE without BOM (common for PS -EncodedCommand)
    if len(raw) % 2 == 0 and len(raw) >= 4:
        try:
            text = raw.decode("utf-16-le")
            # Sanity: decoded text should be mostly printable
            printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
            if printable / len(text) > 0.85:
                return text, "base64-utf16le"
        except UnicodeDecodeError:
            pass

    # Plain UTF-8
    try:
        return raw.decode("utf-8"), "base64"
    except UnicodeDecodeError:
        pass

    return None


def _extract_b64_candidates(text: str) -> list[str]:
    """Pull base64 blobs out of a command string."""
    candidates: list[str] = []

    # PowerShell -EncodedCommand / -enc / -en
    ps_enc = re.findall(
        r"(?:-EncodedCommand|-[Ee][Nn][Cc](?:[Oo][Dd][Ee][Dd](?:[Cc][Oo][Mm][Mm][Aa][Nn][Dd])?)?)\s+([A-Za-z0-9+/=]{20,})",
        text,
    )
    candidates.extend(ps_enc)

    # Standalone large base64 blobs (not already captured)
    blobs = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    for blob in blobs:
        if blob not in candidates:
            candidates.append(blob)

    return candidates


def decode_layers(command: str) -> list[dict[str, Any]]:
    """Return a list of decode layer dicts, up to MAX_LAYERS deep."""
    layers: list[dict[str, Any]] = []
    current = command
    seen: set[str] = {command}

    for layer_num in range(1, MAX_LAYERS + 1):
        candidates = _extract_b64_candidates(current)
        decoded_this_round = False

        for candidate in candidates:
            raw = _try_b64_decode(candidate)
            if raw is None:
                continue
            result = _decode_bytes(raw)
            if result is None:
                continue
            text, encoding = result
            if text in seen:
                continue
            seen.add(text)
            layers.append({"layer": layer_num, "encoding": encoding, "value": text})
            current = text
            decoded_this_round = True
            break  # one decode per layer pass; recurse with the new text

        if not decoded_this_round:
            break

    return layers
