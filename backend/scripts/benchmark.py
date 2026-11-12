#!/usr/bin/env python3
"""Run the detection pipeline over the labelled benchmark corpus and report.

Usage (from backend/):
    python scripts/benchmark.py            # summary + every failing case
    python scripts/benchmark.py --all      # every case
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import gtfobins, lolbas, loldrivers  # noqa: E402
from app.pipeline import detect  # noqa: E402
from tests.benchmark_corpus import (  # noqa: E402
    ATTACKS, BENIGN, EDGE_ATTACKS, EDGE_BENIGN, FIELD_ATTACKS, FIELD_BENIGN,
    HOLDOUT_ATTACKS, HOLDOUT_BENIGN, Case,
)

SEV_RANK = {"clean": 0, "low": 1, "notable": 2, "suspicious": 3, "malicious": 4}


def load_catalogs() -> None:
    lolbas.load_catalog()
    gtfobins.load_catalog()
    loldrivers.load_catalog()


def evaluate(case: Case, *, attack: bool) -> tuple[bool, str]:
    det = detect(case.command)
    sev = det.verdict["severity"]
    ok = SEV_RANK[sev] >= SEV_RANK[case.tier] if attack else SEV_RANK[sev] <= SEV_RANK[case.tier]
    classes = ",".join(f"{t.name}:{t.confidence[0]}" for t in det.threat_classes) or "-"
    layers = ",".join(str(layer["encoding"]) for layer in det.layers) or "-"
    want = f"{'>=' if attack else '<='}{case.tier}"
    line = (f"{'ok  ' if ok else 'FAIL'} {case.id:26} {sev:10} {det.verdict['score']:6} "
            f"want {want:13} [{classes}] layers[{layers}]")
    return ok, line


def score_set(
    attacks: list[Case], benign: list[Case], show_all: bool = False
) -> tuple[float, float, list[str]]:
    out: list[str] = []
    hits = 0
    for case in attacks:
        ok, line = evaluate(case, attack=True)
        hits += ok
        if show_all or not ok:
            out.append(line)
    clean = 0
    for case in benign:
        ok, line = evaluate(case, attack=False)
        clean += ok
        if show_all or not ok:
            out.append(line)
    recall = hits / len(attacks)
    fp_rate = 1 - clean / len(benign)
    out.append(f"  attacks at or above minimum tier : {hits}/{len(attacks)}  ({recall:.1%})")
    out.append(f"  benign above maximum tier        : {len(benign) - clean}/{len(benign)}  ({fp_rate:.1%})")
    return recall, fp_rate, out


def run(show_all: bool = False) -> dict[str, tuple[float, float]]:
    load_catalogs()
    results: dict[str, tuple[float, float]] = {}
    for name, attacks, benign in (
        ("tuning set", ATTACKS, BENIGN),
        ("hold-out set", HOLDOUT_ATTACKS, HOLDOUT_BENIGN),
        ("edge set", EDGE_ATTACKS, EDGE_BENIGN),
        ("field set", FIELD_ATTACKS, FIELD_BENIGN),
    ):
        recall, fp_rate, lines = score_set(attacks, benign, show_all)
        print(f"== {name} ==")
        for line in lines:
            print(line)
        print()
        results[name] = (recall, fp_rate)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="print every case, not just failures")
    run(parser.parse_args().all)
