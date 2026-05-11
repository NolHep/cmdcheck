"""Read-only VirusTotal URL reputation lookups.

Only performs GET lookups against existing VT data — never submits new URLs.
This means we only see VT verdicts for URLs VT has already seen independently.
Requires VIRUSTOTAL_API_KEY environment variable; silently skips if not set.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
_VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 8.0
_MAX_URLS = 5


def _url_to_id(url: str) -> str:
    """VT v3 URL identifier: base64url-encoded URL without padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def _lookup_one(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    try:
        r = await client.get(
            f"{_VT_BASE}/urls/{_url_to_id(url)}",
            headers={"x-apikey": _API_KEY},
            timeout=_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        logger.debug("VT timeout/error for %s", url)
        return None

    if r.status_code == 404:
        return None
    if not r.is_success:
        logger.debug("VT non-success %s for %s", r.status_code, url)
        return None

    stats = (
        r.json()
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    total = sum(stats.values())
    return {
        "url": url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total": total,
    }


async def lookup_urls(urls: list[str]) -> list[dict[str, Any]]:
    """Look up up to _MAX_URLS in VT in parallel. Returns [] if no API key."""
    if not _API_KEY or not urls:
        return []

    candidates = urls[:_MAX_URLS]
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[_lookup_one(client, u) for u in candidates],
            return_exceptions=True,
        )

    return [r for r in results if isinstance(r, dict)]
