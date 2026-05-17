"""Match detected MITRE techniques against known threat actor TTPs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_catalog: list[dict[str, Any]] = []
_ACTOR_FILE = Path(__file__).parent.parent / "data" / "threat_actors.json"

# Minimum overlapping techniques to surface a match at all
_MIN_OVERLAP = 1
# Thresholds for confidence tiers
_HIGH_OVERLAP = 4
_MED_OVERLAP = 2


def load_catalog() -> None:
    if not _ACTOR_FILE.exists():
        logger.warning("threat_actors.json not found — actor attribution disabled")
        return
    try:
        data = json.loads(_ACTOR_FILE.read_text(encoding="utf-8"))
        _catalog.clear()
        _catalog.extend(data)
        logger.info("Threat actor catalog loaded: %d actors", len(_catalog))
    except Exception as exc:
        logger.error("Failed to load threat_actors.json: %s", exc)


def match_actors(technique_ids: list[str]) -> list[dict[str, Any]]:
    """Return top-5 ranked threat actor matches for the given technique IDs.

    Scoring rationale: we reward actors where the detected techniques represent
    a meaningful portion of *what was detected* (precision), not a large portion
    of the actor's full TTP repertoire (recall). This avoids over-crediting
    actors with very large technique lists on weak evidence.
    """
    if not _catalog or not technique_ids:
        return []

    detected = set(technique_ids)
    results: list[dict[str, Any]] = []

    for actor in _catalog:
        actor_techs = set(actor.get("techniques", []))
        overlap = detected & actor_techs
        n = len(overlap)

        if n < _MIN_OVERLAP:
            continue

        # Precision score: what fraction of detected techniques does this actor use?
        precision = n / max(len(detected), 1)

        if n >= _HIGH_OVERLAP and precision >= 0.30:
            confidence = "high"
        elif n >= _MED_OVERLAP or precision >= 0.25:
            confidence = "medium"
        else:
            confidence = "low"

        results.append({
            "id": actor.get("id", ""),
            "name": actor.get("name", ""),
            "aliases": actor.get("aliases", [])[:3],
            "country": actor.get("country", ""),
            "motivation": actor.get("motivation", ""),
            "description": actor.get("description", ""),
            "url": f"https://attack.mitre.org/groups/{actor.get('id', '')}/",
            "matched_techniques": sorted(overlap),
            "overlap_count": n,
            "confidence": confidence,
        })

    conf_order = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda r: (-r["overlap_count"], conf_order[r["confidence"]]))
    return results[:5]


def collect_techniques(result: dict[str, Any]) -> list[str]:
    """Gather all unique MITRE technique IDs from a full analysis result."""
    seen: set[str] = set()
    ids: list[str] = []

    def _add(tid: str) -> None:
        if tid and tid not in seen:
            seen.add(tid)
            ids.append(tid)

    for tc in result.get("threat_classes", []) or []:
        for t in tc.get("techniques", []) or []:
            _add(t.get("id", ""))

    for b in result.get("binaries_in_command", []) or []:
        for t in b.get("techniques", []) or []:
            _add(t.get("id", ""))

    for m in result.get("lolbas_matches", []) or []:
        for tid in m.get("techniques", []) or []:
            if isinstance(tid, str):
                _add(tid)

    return ids
