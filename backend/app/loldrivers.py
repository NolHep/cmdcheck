"""Match driver filenames in commands against the LOLDrivers known-vulnerable catalog.

LOLDrivers catalogs vulnerable and malicious Windows kernel drivers used in
Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks.

The catalog is fetched from https://www.loldrivers.io/api/drivers.json at build time
and stored as backend/data/loldrivers.json. At request time we do a filename lookup only.

Source: https://www.loldrivers.io — Creative Commons Attribution 4.0
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Compact index: lowercase filename -> metadata dict
_catalog: dict[str, dict[str, Any]] = {}

LOLDRIVERS_FILE = Path(__file__).parent.parent / "data" / "loldrivers.json"

# Matches .sys filenames anywhere in a command
_SYS_RE = re.compile(r"\b([A-Za-z0-9_\-]+\.sys)\b", re.IGNORECASE)


def load_catalog() -> None:
    """Load the compact LOLDrivers index from the baked-in JSON file."""
    if not LOLDRIVERS_FILE.exists():
        logger.warning(
            "loldrivers.json not found at %s — LOLDrivers matching disabled. "
            "Fetch it with: python backend/scripts/fetch_loldrivers.py",
            LOLDRIVERS_FILE,
        )
        return

    try:
        data = json.loads(LOLDRIVERS_FILE.read_text(encoding="utf-8"))
        global _catalog
        _catalog = {entry["filename"].lower(): entry for entry in data}
        logger.info("LOLDrivers catalog loaded: %d entries", len(_catalog))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load loldrivers.json: %s", exc)


def extract_driver_names(command: str) -> list[str]:
    """Return lowercase .sys filenames found anywhere in the command string."""
    return [m.group(1).lower() for m in _SYS_RE.finditer(command)]


def match(command: str) -> dict[str, Any] | None:
    """Return the first LOLDrivers match found in the command, or None."""
    if not _catalog:
        return None

    for driver_filename in extract_driver_names(command):
        entry = _catalog.get(driver_filename)
        if entry:
            return entry

    return None
