"""Extract public IPv4 addresses from command strings and decoded layers."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _is_public(ip: str) -> bool:
    """Return True if ip is a globally routable address.

    Uses the same stdlib ranges as redactor.is_internal_url, so an address and
    a URL on that address are always treated alike: private, loopback,
    link-local, carrier-grade NAT, documentation and reserved ranges are never
    listed as indicators or sent to third-party lookups.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def extract_ips(command: str, decoded_layers: list[dict[str, Any]]) -> list[str]:
    """Return deduplicated public IPv4 addresses from the command and decoded layers."""
    sources = [command] + [layer.get("value", "") for layer in decoded_layers]
    seen: set[str] = set()
    out: list[str] = []
    for source in sources:
        for ip in _IPV4_RE.findall(source):
            if ip not in seen and _is_public(ip):
                seen.add(ip)
                out.append(ip)
    return out
