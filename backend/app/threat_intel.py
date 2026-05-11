"""Multi-source threat intelligence enrichment for extracted IPs and URLs.

Sources (all called concurrently, all fail-safe):
  URLhaus  — URL reputation database (abuse.ch). No API key required.
  ThreatFox — IP/URL/domain IOC database (abuse.ch). No API key required.
  GreyNoise — IP classification: malicious / benign / scanner. No key required.
  AbuseIPDB — IP abuse confidence score. Requires ABUSEIPDB_API_KEY (free tier).
  OTX       — AlienVault Open Threat Exchange. Requires OTX_API_KEY (free).

VT results (already looked up separately) are merged in by the caller so every
indicator appears in one unified list.

Privacy note: only extracted IOCs (IPs, URLs) are sent to external services —
never the raw command string.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 6.0
_MAX_INDICATORS = 5  # per type (IPs and URLs each capped separately)

_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
_OTX_KEY = os.getenv("OTX_API_KEY", "")


# ── URLhaus ───────────────────────────────────────────────────────────────────

async def _urlhaus(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    try:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=_TIMEOUT,
        )
        if not r.is_success:
            return None
        data = r.json()
        if data.get("query_status") not in ("is_url", "blacklisted"):
            return None
        return {
            "status": data.get("url_status", "unknown"),
            "threat": data.get("threat"),
            "tags": data.get("tags") or [],
            "reference": data.get("urlhaus_reference"),
        }
    except Exception:
        return None


# ── ThreatFox ─────────────────────────────────────────────────────────────────

async def _threatfox(client: httpx.AsyncClient, ioc: str) -> dict[str, Any] | None:
    try:
        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            timeout=_TIMEOUT,
        )
        if not r.is_success:
            return None
        data = r.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            return None
        best = data["data"][0]
        return {
            "threat_type": best.get("threat_type"),
            "malware": best.get("malware"),
            "confidence": best.get("confidence_level", 0),
            "first_seen": best.get("first_seen"),
        }
    except Exception:
        return None


# ── GreyNoise Community ───────────────────────────────────────────────────────

async def _greynoise(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    try:
        r = await client.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {"classification": "unknown", "noise": False, "riot": False, "name": None}
        if not r.is_success:
            return None
        data = r.json()
        return {
            "classification": data.get("classification", "unknown"),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "name": data.get("name"),
        }
    except Exception:
        return None


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def _abuseipdb(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    if not _ABUSEIPDB_KEY:
        return None
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if not r.is_success:
            return None
        d = r.json().get("data", {})
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "total_reports": d.get("totalReports", 0),
            "usage_type": d.get("usageType"),
        }
    except Exception:
        return None


# ── OTX AlienVault ────────────────────────────────────────────────────────────

async def _otx_ip(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    if not _OTX_KEY:
        return None
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": _OTX_KEY},
            timeout=_TIMEOUT,
        )
        if not r.is_success:
            return None
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        malware = [m["display_name"] for m in data.get("malware_families", [])][:5]
        return {"pulses": pulse_count, "malware_families": malware}
    except Exception:
        return None


async def _otx_url(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    if not _OTX_KEY:
        return None
    try:
        import urllib.parse
        encoded = urllib.parse.quote(url, safe="")
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general",
            headers={"X-OTX-API-KEY": _OTX_KEY},
            timeout=_TIMEOUT,
        )
        if not r.is_success:
            return None
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        malware = [m["display_name"] for m in data.get("malware_families", [])][:5]
        return {"pulses": pulse_count, "malware_families": malware}
    except Exception:
        return None


# ── Orchestration ─────────────────────────────────────────────────────────────

async def enrich(
    urls: list[str],
    ips: list[str],
    vt_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return a unified list of enriched indicators (IPs + URLs).

    VT results already computed are merged in so the frontend receives one
    consistent structure per indicator.
    """
    vt_by_url = {r["url"]: r for r in vt_results}
    results: list[dict[str, Any]] = []

    url_batch = urls[:_MAX_INDICATORS]
    ip_batch = ips[:_MAX_INDICATORS]

    if not url_batch and not ip_batch:
        return []

    async with httpx.AsyncClient() as client:
        url_tasks = [
            asyncio.gather(
                _urlhaus(client, u),
                _threatfox(client, u),
                _otx_url(client, u),
                return_exceptions=True,
            )
            for u in url_batch
        ]
        ip_tasks = [
            asyncio.gather(
                _threatfox(client, ip),
                _greynoise(client, ip),
                _abuseipdb(client, ip),
                _otx_ip(client, ip),
                return_exceptions=True,
            )
            for ip in ip_batch
        ]

        all_url_res, all_ip_res = await asyncio.gather(
            asyncio.gather(*url_tasks, return_exceptions=True),
            asyncio.gather(*ip_tasks, return_exceptions=True),
        )

    def _safe(v: Any) -> dict[str, Any] | None:
        return v if isinstance(v, dict) else None

    for url, res in zip(url_batch, all_url_res):
        if isinstance(res, Exception):
            res = (None, None, None)
        urlhaus, threatfox, otx = res
        vt = vt_by_url.get(url)
        results.append({
            "indicator": url,
            "type": "url",
            "virustotal": vt,
            "urlhaus": _safe(urlhaus),
            "threatfox": _safe(threatfox),
            "greynoise": None,
            "abuseipdb": None,
            "otx": _safe(otx),
        })

    for ip, res in zip(ip_batch, all_ip_res):
        if isinstance(res, Exception):
            res = (None, None, None, None)
        threatfox, greynoise, abuseipdb, otx = res
        results.append({
            "indicator": ip,
            "type": "ip",
            "virustotal": None,
            "urlhaus": None,
            "threatfox": _safe(threatfox),
            "greynoise": _safe(greynoise),
            "abuseipdb": _safe(abuseipdb),
            "otx": _safe(otx),
        })

    return results
