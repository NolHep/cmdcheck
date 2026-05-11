"""Load and query the LOLBAS catalog from the vendored git submodule."""

from __future__ import annotations

import difflib
import logging
from pathlib import Path
from typing import Any

import yaml

from . import mitre

logger = logging.getLogger(__name__)

# Loaded once at startup
_catalog: dict[str, dict[str, Any]] = {}

SIMILARITY_THRESHOLD = 0.7
LOLBAS_DIR = Path(__file__).parent.parent / "data" / "LOLBAS" / "yml"


def load_catalog() -> None:
    """Walk LOLBAS/yml/, parse every YAML file, index by lowercase binary name."""

    if not LOLBAS_DIR.exists():
        logger.warning("LOLBAS submodule not found at %s — LOLBAS matching disabled", LOLBAS_DIR)
        return

    count = 0
    for yml_file in LOLBAS_DIR.rglob("*.yml"):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "Name" not in data:
                continue
            name = data["Name"].lower()
            _catalog[name] = data
            count += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping %s: %s", yml_file, exc)

    logger.info("LOLBAS catalog loaded: %d entries", count)


def _extract_techniques(entry: dict[str, Any]) -> list[str]:
    """Return unique MITRE technique IDs from all Commands in a LOLBAS entry.

    MitreID in the YAML is always a plain string (e.g. "T1059.001"), never a
    list — iterating a string yields characters, which is the bug this fixes.
    """
    techniques: list[str] = []
    for cmd in entry.get("Commands", []) or []:
        mitre = cmd.get("MitreID")
        if isinstance(mitre, str) and mitre and mitre not in techniques:
            techniques.append(mitre)
        elif isinstance(mitre, list):
            for t in mitre:
                if isinstance(t, str) and t and t not in techniques:
                    techniques.append(t)
    return techniques


def _extract_functions(entry: dict[str, Any]) -> list[str]:
    """Return unique abuse categories (Execute, Download, …) from Commands."""
    seen: list[str] = []
    for cmd in entry.get("Commands", []) or []:
        cat = cmd.get("Category")
        if isinstance(cat, str) and cat and cat not in seen:
            seen.append(cat)
    return seen


def match(binary_name: str) -> dict[str, Any] | None:
    """Return the best-matching LOLBAS entry for *binary_name*, or None."""
    if not _catalog:
        return None

    needle = binary_name.lower().removesuffix(".exe")
    best_score = 0.0
    best_entry: dict[str, Any] | None = None

    for catalog_name, entry in _catalog.items():
        # Strip .exe from the catalog key before comparing so short names like
        # "cmd" (score 0.6 vs "cmd.exe") don't fall below the 0.7 threshold.
        score = difflib.SequenceMatcher(None, needle, catalog_name.removesuffix(".exe")).ratio()
        if score > best_score:
            best_score = score
            best_entry = entry

    if best_entry is None or best_score < SIMILARITY_THRESHOLD:
        return None

    raw_techniques = _extract_techniques(best_entry)
    technique_details = mitre.enrich(raw_techniques)

    return {
        "name": best_entry.get("Name"),
        "description": best_entry.get("Description"),
        "url": best_entry.get("URL"),
        "techniques": raw_techniques,
        "technique_details": technique_details,
        "functions": _extract_functions(best_entry),
        "similarity": round(best_score, 4),
    }
