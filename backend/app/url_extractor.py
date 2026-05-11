"""Extract URLs and other indicators from command strings and decoded layers."""

from __future__ import annotations

import re
from typing import Any

# Matches both live (http/https) and analyst-defanged (hxxp/hxxps) URLs.
_URL_RE = re.compile(r'h(?:xx|tt)ps?://[^\s\'"<>()\[\]&|;,]+', re.IGNORECASE)


def _normalize_url(url: str) -> str:
    """Restore defanged URLs to live form for external lookups."""
    return re.sub(r"^hxxp", "http", url, count=1, flags=re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    raw = _URL_RE.findall(text)
    return [_normalize_url(u.rstrip(".,;:")) for u in raw]


def extract_urls_from_analysis(command: str, decoded_layers: list[dict[str, Any]]) -> list[str]:
    """Return deduplicated normalized URLs found in the command and decoded layers."""
    sources = [command] + [layer.get("value", "") for layer in decoded_layers]
    seen: set[str] = set()
    out: list[str] = []
    for source in sources:
        for url in extract_urls(source):
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out
