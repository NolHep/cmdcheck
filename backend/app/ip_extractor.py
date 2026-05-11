"""Extract public IPv4 addresses from command strings and decoded layers."""

from __future__ import annotations

import re
from typing import Any

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _is_public(ip: str) -> bool:
    """Return True if ip is a routable public address."""
    try:
        a, b, c, _ = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 127:
        return False  # loopback
    if a == 169 and b == 254:
        return False  # link-local
    if a == 0:
        return False
    if a >= 224:
        return False  # multicast + reserved
    return True


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
