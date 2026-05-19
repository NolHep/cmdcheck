"""Load and query the GTFOBins catalog from the vendored git submodule.

GTFOBins covers Linux/Unix binaries abused for privilege escalation, file read/write,
shell spawning, etc. It is the Linux equivalent of the LOLBAS catalog.

Files live at backend/data/GTFOBins/_gtfobins/<name>.md with YAML frontmatter.
Matching is exact (case-insensitive) on the binary name — no fuzzy similarity needed
because GTFOBins file names are canonical Unix binary names.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_catalog: dict[str, dict[str, Any]] = {}

GTFOBINS_DIR = Path(__file__).parent.parent / "data" / "GTFOBins" / "_gtfobins"
GTFOBINS_BASE_URL = "https://gtfobins.github.io/gtfobins"


def _parse_frontmatter(text: str) -> dict[str, Any] | None:
    """Parse YAML from a GTFOBins file.

    Files are pure YAML (optionally preceded by a bare '---' document-start marker).
    Older versions of the submodule used Jekyll frontmatter (open+close ---); newer
    local clones contain just the YAML body.  We handle both.
    """
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def load_catalog() -> None:
    """Parse every .md file in the GTFOBins submodule, index by binary name."""
    if not GTFOBINS_DIR.exists():
        logger.warning(
            "GTFOBins submodule not found at %s — GTFOBins matching disabled. "
            "Run: git submodule add https://github.com/GTFOBins/GTFOBins.github.io backend/data/GTFOBins",
            GTFOBINS_DIR,
        )
        return

    count = 0
    for md_file in GTFOBINS_DIR.glob("*"):
        if not md_file.is_file():
            continue
        try:
            fm = _parse_frontmatter(md_file.read_text(encoding="utf-8"))
            if not fm or "functions" not in fm:
                continue
            name = md_file.stem.lower()
            _catalog[name] = fm
            count += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping %s: %s", md_file, exc)

    logger.info("GTFOBins catalog loaded: %d entries", count)


def match(binary_name: str) -> dict[str, Any] | None:
    """Return GTFOBins metadata for a binary, or None if not catalogued."""
    if not _catalog:
        return None

    name = binary_name.lower().removesuffix(".exe")
    entry = _catalog.get(name)
    if entry is None:
        return None

    functions = [fn for fn in (entry.get("functions") or {}).keys()]
    return {
        "name": name,
        "functions": functions,
        "url": f"{GTFOBINS_BASE_URL}/{name}/",
        "description": (entry.get("description") or "").strip() or None,
    }
