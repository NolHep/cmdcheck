"""The pure detection pipeline: command string in, structured findings out.

No database, network, or request state — everything here is a deterministic
function of the command text (CLAUDE.md invariant #1). `main.analyze` wraps
this with storage, redaction and threat-intel enrichment; the benchmark in
`tests/test_benchmark.py` calls it directly so that what we measure is exactly
what the product ships.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .classifier import ThreatClass, classify, known_installer, search_query
from .decoder import NORMALIZATION_ENCODINGS, decode_layers, obfuscation_depths
from .gtfobins import match as gtfobins_match
from .lolbas import match as lolbas_match
from .loldrivers import match as loldrivers_match
from .parser import extract_binaries
from .scoring import compute_verdict
from .tuning import Tuning, get_active

@dataclass
class Detection:
    layers: list[dict[str, Any]]
    binaries: list[str]
    lolbas_matches: list[dict[str, Any]]
    lolbas_by_name: dict[str, dict[str, Any]]
    gtfobins_matches: list[dict[str, Any]]
    gtfobins_by_name: dict[str, dict[str, Any]]
    loldrivers: dict[str, Any] | None
    threat_classes: list[ThreatClass]
    verdict: dict[str, Any]
    encoding_depth: int = 0
    sources: list[str] = field(default_factory=list)


def detect(command: str, tuning: Tuning | None = None) -> Detection:
    """Run decode → binary extraction → catalog matching → classify → score.

    `tuning` overrides the active configuration for this call only — used by
    the admin tuner to preview a candidate without activating it.
    """
    tuning = tuning or get_active()
    layers = decode_layers(command)
    sources = [command, *(str(layer["value"]) for layer in layers)]

    binaries: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for binary in extract_binaries(source):
            if binary.lower() not in seen:
                seen.add(binary.lower())
                binaries.append(binary)

    # A binary can be hidden inside an encoded layer, so its arguments are
    # compared against every source and the best abuse-pattern match is kept.
    lolbas_matches: list[dict[str, Any]] = []
    lolbas_by_name: dict[str, dict[str, Any]] = {}
    seen_lolbas: set[str] = set()
    for binary in binaries:
        best: dict[str, Any] | None = None
        for source in sources:
            hit = lolbas_match(binary, source)
            if hit is None:
                break
            if best is None or hit.get("arg_similarity", 0) > best.get("arg_similarity", 0):
                best = hit
        if best is not None and best["name"] not in seen_lolbas:
            seen_lolbas.add(best["name"])
            lolbas_matches.append(best)
            lolbas_by_name[binary.lower()] = best
            lolbas_by_name[best["name"].lower()] = best

    gtfobins_matches: list[dict[str, Any]] = []
    gtfobins_by_name: dict[str, dict[str, Any]] = {}
    seen_gtfobins: set[str] = set()
    for binary in binaries:
        hit = gtfobins_match(binary)
        if hit is not None and hit["name"] not in seen_gtfobins:
            seen_gtfobins.add(hit["name"])
            gtfobins_matches.append(hit)
            gtfobins_by_name[binary.lower()] = hit
            gtfobins_by_name[hit["name"].lower()] = hit

    loldrivers: dict[str, Any] | None = None
    for source in sources:
        hit = loldrivers_match(source)
        if hit is not None:
            loldrivers = hit
            break

    threat_classes = classify(command, layers, tuning)
    encoding_depth = max(
        (
            depth
            for layer, depth in zip(layers, obfuscation_depths(layers), strict=True)
            if layer.get("encoding") not in NORMALIZATION_ENCODINGS
        ),
        default=0,
    )
    verdict = compute_verdict(
        threat_classes,
        has_lolbas=bool(lolbas_matches),
        has_gtfobins=bool(gtfobins_matches),
        has_loldrivers=loldrivers is not None,
        encoding_depth=encoding_depth,
        lolbas_abuse=[
            m["name"] for m in lolbas_matches
            if m.get("arg_similarity", 0) >= tuning.lolbas_abuse_similarity
        ],
        installer=known_installer(command, layers),
        search_only=search_query(command),
        tuning=tuning,
    )

    return Detection(
        layers=layers,
        binaries=binaries,
        lolbas_matches=lolbas_matches,
        lolbas_by_name=lolbas_by_name,
        gtfobins_matches=gtfobins_matches,
        gtfobins_by_name=gtfobins_by_name,
        loldrivers=loldrivers,
        threat_classes=threat_classes,
        verdict=verdict,
        encoding_depth=encoding_depth,
        sources=sources,
    )
