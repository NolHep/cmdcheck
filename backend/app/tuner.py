"""Admin tuner support: preview a candidate tuning and score it on the benchmark.

Nothing here stores or activates anything — these are read-only "what would
happen" computations. Activation is a separate, explicit save in main.py.
"""

from __future__ import annotations

from typing import Any

from .pipeline import Detection, detect
from .tuning import Tuning, get_active

SEV_RANK: dict[str, int] = {"clean": 0, "low": 1, "notable": 2, "suspicious": 3, "malicious": 4}


def _summary(det: Detection) -> dict[str, Any]:
    return {
        "severity": det.verdict["severity"],
        "label": det.verdict["label"],
        "detail": det.verdict["detail"],
        "score": det.verdict["score"],
        "breakdown": det.verdict["breakdown"],
        "classes": [
            {
                "name": tc.name,
                "label": tc.label,
                "confidence": tc.confidence,
                "precision": tc.precision,
                "max_depth": tc.max_depth,
                "signals": tc.signals,
                "rule_ids": tc.rule_ids,
            }
            for tc in det.threat_classes
        ],
        "layers": [str(layer.get("encoding")) for layer in det.layers],
        "lolbas": [
            {"name": m.get("name"), "arg_similarity": m.get("arg_similarity")}
            for m in det.lolbas_matches
        ],
    }


def preview(command: str, candidate: Tuning) -> dict[str, Any]:
    """Score one command under the active tuning and under *candidate*."""
    return {
        "active": _summary(detect(command, get_active())),
        "candidate": _summary(detect(command, candidate)),
    }


def _load_corpus() -> list[tuple[str, list[Any], list[Any]]] | None:
    """The labelled corpus ships with the test suite; absent in a slim image."""
    try:
        from tests import benchmark_corpus as corpus  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return None
    return [
        ("Tuning set", corpus.ATTACKS, corpus.BENIGN),
        ("Hold-out set", corpus.HOLDOUT_ATTACKS, corpus.HOLDOUT_BENIGN),
        ("Edge set", corpus.EDGE_ATTACKS, corpus.EDGE_BENIGN),
    ]


def benchmark(candidate: Tuning) -> dict[str, Any]:
    """Run the labelled corpus under the active tuning and under *candidate*.

    Returns per-set recall / false-positive counts for both, every case whose
    outcome differs between them, every case the candidate gets wrong, and how
    often each rule fired on attack versus benign commands.
    """
    corpus = _load_corpus()
    if corpus is None:
        return {"available": False}

    active = get_active()
    sets: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    failing: list[dict[str, Any]] = []
    rule_hits: dict[str, dict[str, int]] = {}

    def run(case: Any, *, attack: bool, set_name: str) -> tuple[bool, bool]:
        before = detect(case.command, active)
        after = detect(case.command, candidate)
        sev_before, sev_after = before.verdict["severity"], after.verdict["severity"]
        want = SEV_RANK[case.tier]
        ok_before = SEV_RANK[sev_before] >= want if attack else SEV_RANK[sev_before] <= want
        ok_after = SEV_RANK[sev_after] >= want if attack else SEV_RANK[sev_after] <= want
        for tc in after.threat_classes:
            for rid in tc.rule_ids:
                hit = rule_hits.setdefault(rid, {"attack": 0, "benign": 0})
                hit["attack" if attack else "benign"] += 1
        row = {
            "id": case.id,
            "set": set_name,
            "kind": "attack" if attack else "benign",
            "command": case.command[:240],
            "tier": case.tier,
            "active": sev_before,
            "candidate": sev_after,
            "active_score": before.verdict["score"],
            "candidate_score": after.verdict["score"],
            "ok_active": ok_before,
            "ok_candidate": ok_after,
        }
        if sev_before != sev_after:
            changes.append(row)
        if not ok_after:
            failing.append(row)
        return ok_before, ok_after

    for name, attacks, benign in corpus:
        caught_before = caught_after = over_before = over_after = 0
        for case in attacks:
            ok_b, ok_a = run(case, attack=True, set_name=name)
            caught_before += ok_b
            caught_after += ok_a
        for case in benign:
            ok_b, ok_a = run(case, attack=False, set_name=name)
            over_before += not ok_b
            over_after += not ok_a
        sets.append({
            "name": name,
            "attacks": len(attacks),
            "benign": len(benign),
            "active": {"caught": caught_before, "over": over_before},
            "candidate": {"caught": caught_after, "over": over_after},
        })

    return {
        "available": True,
        "sets": sets,
        "changes": changes,
        "failing": failing,
        "rule_hits": rule_hits,
    }
