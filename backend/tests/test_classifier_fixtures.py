"""Parametrized classifier regression tests driven by JSON fixture files.

Each fixture file in tests/fixtures/*.json contains an array of test cases.
Every case specifies a command, expected classes/techniques, and classes that
must NOT fire (true-negative assertions).

Run all fixture tests:
    pytest tests/test_classifier_fixtures.py -v

Run a specific fixture file:
    pytest tests/test_classifier_fixtures.py -v -k real_world

Run a specific case:
    pytest tests/test_classifier_fixtures.py -v -k conti-backup-destruction
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.classifier import classify
from app.scoring import compute_verdict

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CONF_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}
SEV_RANK: dict[str, int] = {
    "clean": 0, "low": 1, "notable": 2, "suspicious": 3, "malicious": 4,
}


def _load_fixtures() -> list[pytest.param]:
    cases: list[pytest.param] = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        items: list[dict] = json.loads(path.read_text(encoding="utf-8"))
        for item in items:
            cases.append(pytest.param(item, id=f"{path.stem}/{item['id']}"))
    return cases


@pytest.mark.parametrize("fx", _load_fixtures())
def test_classifier_fixture(fx: dict) -> None:
    command: str = fx["command"]
    result = classify(command, [])
    by_name = {tc.name: tc for tc in result}

    expect = fx.get("expect", {})
    reject = fx.get("reject", {})

    # Required classes must be present
    for cls in expect.get("classes", []):
        assert cls in by_name, (
            f"Expected class {cls!r} to fire.\n"
            f"  Command: {command[:120]!r}\n"
            f"  Got: {sorted(by_name)}"
        )

    # Each listed class must meet or exceed its minimum confidence
    for cls, min_conf in expect.get("min_confidence", {}).items():
        assert cls in by_name, (
            f"Class {cls!r} did not fire (needed for confidence check).\n"
            f"  Command: {command[:120]!r}"
        )
        actual = by_name[cls].confidence
        assert CONF_RANK[actual] >= CONF_RANK[min_conf], (
            f"Class {cls!r}: expected >= {min_conf!r}, got {actual!r}.\n"
            f"  Command: {command[:120]!r}"
        )

    # Required technique IDs must appear somewhere in the result
    all_tids = {t["id"] for tc in result for t in tc.techniques}
    for tid in expect.get("techniques", []):
        assert tid in all_tids, (
            f"Technique {tid!r} not found.\n"
            f"  Command: {command[:120]!r}\n"
            f"  Got: {sorted(all_tids)}"
        )

    # Minimum aggregate severity (the actual product output). Behavior-only —
    # LOLBAS/encoding context isn't available at fixture level.
    min_sev = expect.get("verdict")
    max_sev = expect.get("max_verdict")
    if min_sev or max_sev:
        v = compute_verdict(result)
        if min_sev:
            assert SEV_RANK[v["severity"]] >= SEV_RANK[min_sev], (
                f"Verdict: expected >= {min_sev!r}, got {v['severity']!r} "
                f"(score {v['score']}).\n  Command: {command[:120]!r}"
            )
        if max_sev:
            assert SEV_RANK[v["severity"]] <= SEV_RANK[max_sev], (
                f"Verdict: expected <= {max_sev!r} (false-positive gate), got "
                f"{v['severity']!r} (score {v['score']}).\n"
                f"  Command: {command[:120]!r}\n"
                f"  Classes: {[(tc.name, tc.confidence) for tc in result]}"
            )

    # Rejected classes must be absent
    for cls in reject.get("classes", []):
        assert cls not in by_name, (
            f"Class {cls!r} fired but should not have.\n"
            f"  Command: {command[:120]!r}\n"
            f"  Signals: {by_name[cls].signals}"
        )
