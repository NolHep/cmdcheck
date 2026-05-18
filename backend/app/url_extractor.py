"""Extract URLs and other indicators from command strings and decoded layers."""

from __future__ import annotations

import re
from typing import Any

# Matches both live (http/https) and analyst-defanged (hxxp/hxxps) URLs.
# Brackets and parens are allowed inside the URL to capture [.] and (.) defanging;
# they are stripped from the trailing end and refanged in _normalize_url.
_URL_RE = re.compile(r'h(?:xx|tt)ps?://[^\s\'"<>&|;,]+', re.IGNORECASE)


def _normalize_url(url: str) -> str:
    """Restore defanged URLs to live form for external lookups."""
    url = re.sub(r"^hxxp", "http", url, count=1, flags=re.IGNORECASE)
    url = re.sub(r"\[\.\]", ".", url)
    url = re.sub(r"\(\.\)", ".", url)
    url = re.sub(r"\[dot\]", ".", url, flags=re.IGNORECASE)
    url = re.sub(r"\[/\]", "/", url)
    return url


def extract_urls(text: str) -> list[str]:
    raw = _URL_RE.findall(text)
    return [_normalize_url(u.rstrip(".,;:)[]")) for u in raw]


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
