#!/usr/bin/env python3
"""
Live endpoint test script for ShellHawk backend.

Loads all fixture JSON files from tests/fixtures/, POSTs each command to
{url}/analyze, and checks threat_classes in the response against fixture
expectations.

Usage:
    python scripts/check_live.py [--url http://localhost:8000] [--timeout 30]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures"

_CONF_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def load_fixtures() -> list[tuple[str, dict[str, Any]]]:
    """Load all fixture cases from JSON files in the fixtures directory."""
    cases: list[tuple[str, dict[str, Any]]] = []
    for fixture_file in sorted(FIXTURES_DIR.glob("*.json")):
        if fixture_file.name == "README.md":
            continue
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"WARNING: could not parse {fixture_file.name}: {e}", file=sys.stderr)
            continue
        if not isinstance(data, list):
            continue
        for case in data:
            label = f"{fixture_file.stem}/{case.get('id', '?')}"
            cases.append((label, case))
    return cases


def post_analyze(base_url: str, command: str, timeout: int) -> dict[str, Any] | None:
    """POST command to /analyze endpoint, return parsed JSON or None on error."""
    url = f"{base_url.rstrip('/')}/analyze"
    payload = json.dumps({"command": command}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  HTTP {e.code}: {body[:200]}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"  Connection error: {e.reason}", file=sys.stderr)
        return None
    except Exception as e:  # noqa: BLE001
        print(f"  Unexpected error: {e}", file=sys.stderr)
        return None


def check_case(
    label: str,
    case: dict[str, Any],
    response: dict[str, Any],
) -> list[str]:
    """
    Validate a fixture case against the live response.
    Returns a list of failure reasons (empty = pass).
    """
    failures: list[str] = []
    threat_classes: dict[str, Any] = {}

    # Response shape: list of {name, confidence, ...} or dict keyed by name
    raw = response.get("threat_classes", [])
    if isinstance(raw, list):
        for tc in raw:
            if isinstance(tc, dict) and "name" in tc:
                threat_classes[tc["name"]] = tc
    elif isinstance(raw, dict):
        threat_classes = raw

    got_names = set(threat_classes.keys())

    expect = case.get("expect", {})
    reject = case.get("reject", {})

    # Check expected classes are present
    for cls in expect.get("classes", []):
        if cls not in got_names:
            failures.append(f"expected class '{cls}' missing (got: {sorted(got_names)})")

    # Check minimum confidence levels
    for cls, min_conf in expect.get("min_confidence", {}).items():
        if cls not in threat_classes:
            # Already reported above if in expect.classes
            continue
        tc = threat_classes[cls]
        got_conf = tc.get("confidence", "low")
        if _CONF_RANK.get(got_conf, 0) < _CONF_RANK.get(min_conf, 0):
            failures.append(
                f"class '{cls}' confidence too low: expected >={min_conf}, got {got_conf}"
            )

    # Check expected techniques
    all_techniques: set[str] = set()
    for tc in threat_classes.values():
        for t in tc.get("techniques", []):
            if isinstance(t, dict):
                all_techniques.add(t.get("id", ""))
            elif isinstance(t, str):
                all_techniques.add(t)

    for tid in expect.get("techniques", []):
        if tid not in all_techniques:
            failures.append(f"expected technique {tid} not found in {sorted(all_techniques)}")

    # Check rejected classes are absent
    for cls in reject.get("classes", []):
        if cls in got_names:
            failures.append(f"rejected class '{cls}' was unexpectedly detected")

    return failures


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run fixture cases against a live ShellHawk /analyze endpoint."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the backend (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--stop-on-fail",
        action="store_true",
        help="Stop after the first failure",
    )
    args = parser.parse_args()

    cases = load_fixtures()
    if not cases:
        print("No fixture cases found.", file=sys.stderr)
        sys.exit(1)

    print(f"Running {len(cases)} fixture cases against {args.url}")
    print()

    passed = 0
    failed = 0
    errored = 0
    failure_details: list[str] = []

    for label, case in cases:
        command = case.get("command", "")
        if not command:
            print(f"  SKIP {label} — no command field")
            continue

        t0 = time.monotonic()
        response = post_analyze(args.url, command, args.timeout)
        elapsed = time.monotonic() - t0

        if response is None:
            errored += 1
            line = f"  ERROR {label} — request failed ({elapsed:.1f}s)"
            print(line)
            failure_details.append(f"ERROR {label} — request failed")
            if args.stop_on_fail:
                break
            continue

        issues = check_case(label, case, response)
        if issues:
            failed += 1
            print(f"  FAIL  {label} ({elapsed:.1f}s)")
            for issue in issues:
                print(f"         {issue}")
            failure_details.append(f"FAIL {label}: {'; '.join(issues)}")
            if args.stop_on_fail:
                break
        else:
            passed += 1
            print(f"  PASS  {label} ({elapsed:.1f}s)")

    total = passed + failed + errored
    print()
    print(f"Results: {passed}/{total} passed ({failed} failed, {errored} errored)")

    if failure_details:
        print()
        print("Failures:")
        for detail in failure_details:
            print(f"  {detail}")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
