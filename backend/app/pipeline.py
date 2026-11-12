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

from .classifier import ThreatClass, classify, known_installer
from .decoder import decode_layers
from .gtfobins import match as gtfobins_match
from .lolbas import match as lolbas_match
from .loldrivers import match as loldrivers_match
from .parser import extract_binaries
from .scoring import compute_verdict

# Layers that are normalisation rather than evidence of hiding intent: env-var
# expansion, the limit marker, and string templating that also fires on benign
# string-building. They are still classified, they just earn no encoding bonus.
NON_ENCODING_LAYERS = frozenset({
    "env-variable-substitution", "limit-reached", "format-op", "dot-replace",
    "cmd-variable-substitution",
})


# The UI badges an invocation as "abuse-pattern" at lolbas.ARG_SIMILARITY_THRESHOLD
# (0.6). Points are only awarded above this stricter bar: on the benchmark
# corpus benign dual-use tops out at 0.60 and real abuse starts around 0.64.
LOLBAS_ABUSE_SCORE_THRESHOLD = 0.68


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


def detect(command: str) -> Detection:
    """Run decode → binary extraction → catalog matching → classify → score."""
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

    threat_classes = classify(command, layers)
    encoding_depth = len({
        int(layer.get("layer", 1) or 1)
        for layer in layers
        if layer.get("encoding") not in NON_ENCODING_LAYERS
    })
    verdict = compute_verdict(
        threat_classes,
        has_lolbas=bool(lolbas_matches),
        has_gtfobins=bool(gtfobins_matches),
        has_loldrivers=loldrivers is not None,
        encoding_depth=encoding_depth,
        lolbas_abuse=[
            m["name"] for m in lolbas_matches
            if m.get("arg_similarity", 0) >= LOLBAS_ABUSE_SCORE_THRESHOLD
        ],
        installer=known_installer(command, layers),
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
