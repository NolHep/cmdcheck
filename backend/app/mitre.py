"""Shared MITRE ATT&CK technique catalog.

Loaded once at startup from backend/data/attack_techniques.json.
Run backend/scripts/fetch_attack_stix.py to regenerate the catalog.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CATALOG_PATH = Path(__file__).parent.parent / "data" / "attack_techniques.json"

_catalog: dict[str, dict[str, Any]] = {}


def load_catalog() -> None:
    global _catalog
    if not CATALOG_PATH.exists():
        logger.warning(
            "attack_techniques.json not found at %s — "
            "run: python backend/scripts/fetch_attack_stix.py",
            CATALOG_PATH,
        )
        return
    try:
        _catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        logger.info("MITRE ATT&CK catalog loaded: %d techniques", len(_catalog))
    except Exception as exc:
        logger.warning("Failed to load MITRE catalog: %s", exc)


def lookup(technique_id: str) -> dict[str, Any] | None:
    return _catalog.get(technique_id)


def enrich(technique_ids: list[str]) -> list[dict[str, Any]]:
    """Return enriched technique details for a list of ATT&CK IDs."""
    out: list[dict[str, Any]] = []
    for tid in technique_ids:
        t = _catalog.get(tid, {})
        out.append({
            "id": tid,
            "name": t.get("name"),
            "tactic": t.get("tactic"),
            "url": t.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"),
        })
    return out
