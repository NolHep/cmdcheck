#!/usr/bin/env python3
"""Robustness checks for the detection pipeline: evasion mutations and timing.

Usage (from backend/):
    python scripts/stress.py              # mutation summary + slowest inputs
    python scripts/stress.py --failures   # also list every failing mutation
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import gtfobins, lolbas, loldrivers  # noqa: E402
from app.pipeline import detect  # noqa: E402
from tests.benchmark_corpus import ATTACKS, BENIGN, HOLDOUT_ATTACKS, HOLDOUT_BENIGN  # noqa: E402
from tests.benchmark_mutations import MUTATIONS, mutate  # noqa: E402

SEV_RANK = {"clean": 0, "low": 1, "notable": 2, "suspicious": 3, "malicious": 4}


def mutation_report(show_failures: bool) -> float:
    total: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    lines: list[str] = []
    for name, case in mutate([*ATTACKS, *HOLDOUT_ATTACKS]):
        total[name] += 1
        sev = detect(case.command).verdict["severity"]
        if SEV_RANK[sev] < SEV_RANK[case.tier]:
            failed[name] += 1
            lines.append(f"  FAIL {case.id:44} got {sev:10} want >= {case.tier}")
    print("== evasion mutations (attack must keep its minimum tier) ==")
    for name in MUTATIONS:
        if total[name]:
            ok = total[name] - failed[name]
            print(f"  {name:20} {ok:4}/{total[name]:<4} ({ok / total[name]:.1%})")
    all_total, all_failed = sum(total.values()), sum(failed.values())
    survival = 1 - all_failed / all_total
    print(f"  {'TOTAL':20} {all_total - all_failed:4}/{all_total:<4} ({survival:.1%})")
    if show_failures:
        print("\n".join(lines))
    return survival


def timing_report() -> float:
    samples: list[tuple[float, str]] = []
    corpus = [*ATTACKS, *BENIGN, *HOLDOUT_ATTACKS, *HOLDOUT_BENIGN]
    for case in corpus:
        t0 = time.perf_counter()
        detect(case.command)
        samples.append((time.perf_counter() - t0, case.id))
    # Pathological shapes: long junk, repeated separators, deep nesting bait.
    synthetic = {
        "64KB-of-a": "a" * 65536,
        "64KB-spaces": "cmd /c " + " " * 65536 + "whoami",
        "20KB-b64ish": "powershell -enc " + "QUJD" * 5000,
        "5K-pipes": " | ".join(["echo x"] * 5000),
        "5K-carets": "c" + "^a" * 5000,
        "5K-quotes": 'a""b' * 5000,
        "5K-percent": "%a%" * 5000,
        "nested-parens": "(" * 3000 + ")" * 3000,
        "5K-urls": " ".join(f"http://203.0.113.{i % 255}/a.exe" for i in range(5000)),
        "long-path": "rundll32 " + "\\".join(["C:"] + ["dir"] * 4000) + "\\x.dll,Start",
        "regex-bait-dotstar": "curl " + "http://x/ " * 3000 + "| " * 3000,
        "set-chain": "&& ".join(f"set v{i}=x{i}" for i in range(2000)) + "&& " + "".join(f"%v{i}%" for i in range(2000)),
    }
    for name, command in synthetic.items():
        t0 = time.perf_counter()
        detect(command)
        samples.append((time.perf_counter() - t0, f"synthetic:{name}"))
    samples.sort(reverse=True)
    times = sorted(t for t, _ in samples)
    print("\n== timing ==")
    print(f"  median {times[len(times) // 2] * 1000:.1f} ms   p95 {times[int(len(times) * 0.95)] * 1000:.1f} ms"
          f"   max {times[-1] * 1000:.0f} ms")
    for t, name in samples[:8]:
        print(f"  {t * 1000:8.0f} ms  {name}")
    return times[-1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--failures", action="store_true")
    args = parser.parse_args()
    lolbas.load_catalog()
    gtfobins.load_catalog()
    loldrivers.load_catalog()
    mutation_report(args.failures)
    timing_report()
