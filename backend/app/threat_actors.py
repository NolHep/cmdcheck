"""Match detected MITRE techniques against known threat actor TTPs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_catalog: list[dict[str, Any]] = []
_ACTOR_FILE = Path(__file__).parent.parent / "data" / "threat_actors.json"

# A technique used by more than this share of catalogued groups (PowerShell,
# ingress tool transfer, Run keys…) says nothing about *who*; only rarer,
# distinctive techniques count toward a match.
_COMMON_SHARE = 0.4
# Distinctive overlaps needed for "medium". Technique overlap alone never
# earns "high": a command line cannot identify an actor.
_MED_DISTINCTIVE = 3
# How many groups use each technique, filled by load_catalog().
_technique_df: dict[str, int] = {}


def load_catalog() -> None:
    if not _ACTOR_FILE.exists():
        logger.warning("threat_actors.json not found — actor attribution disabled")
        return
    try:
        data = json.loads(_ACTOR_FILE.read_text(encoding="utf-8"))
        _catalog.clear()
        _catalog.extend(data)
        _technique_df.clear()
        for actor in _catalog:
            for tid in set(actor.get("techniques", [])):
                _technique_df[tid] = _technique_df.get(tid, 0) + 1
        logger.info("Threat actor catalog loaded: %d actors", len(_catalog))
    except Exception as exc:
        logger.error("Failed to load threat_actors.json: %s", exc)


def match_actors(technique_ids: list[str]) -> list[dict[str, Any]]:
    """Return up to five groups whose known TTPs overlap the detected techniques.

    Nearly every group uses PowerShell, cmd and ingress tool transfer, so raw
    overlap counts attribute every download cradle to APT29. Only techniques
    used by a minority of groups are treated as evidence, each weighted by its
    rarity, and a group with no distinctive overlap is not listed at all.
    """
    if not _catalog or not technique_ids:
        return []

    detected = set(technique_ids)
    common_cutoff = max(1, int(len(_catalog) * _COMMON_SHARE))
    results: list[dict[str, Any]] = []

    for actor in _catalog:
        overlap = detected & set(actor.get("techniques", []))
        distinctive = {t for t in overlap if _technique_df.get(t, 1) <= common_cutoff}
        if not distinctive:
            continue
        score = sum(1.0 / _technique_df.get(t, 1) for t in distinctive)
        confidence = "medium" if len(distinctive) >= _MED_DISTINCTIVE else "low"

        results.append({
            "id": actor.get("id", ""),
            "name": actor.get("name", ""),
            "aliases": actor.get("aliases", [])[:3],
            "country": actor.get("country", ""),
            "motivation": actor.get("motivation", ""),
            "description": actor.get("description", ""),
            "url": f"https://attack.mitre.org/groups/{actor.get('id', '')}/",
            "matched_techniques": sorted(distinctive) + sorted(overlap - distinctive),
            "overlap_count": len(overlap),
            "confidence": confidence,
            "_score": score,
        })

    results.sort(key=lambda r: -r["_score"])
    for r in results:
        del r["_score"]
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
