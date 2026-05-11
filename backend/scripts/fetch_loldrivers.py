#!/usr/bin/env python3
"""Fetch the LOLDrivers API and bake a compact index into backend/data/loldrivers.json.

Run from the repo root:
    python backend/scripts/fetch_loldrivers.py

Refresh quarterly (or after major Windows threat actor campaigns).
Source: https://www.loldrivers.io — CC BY 4.0
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

API_URL = "https://www.loldrivers.io/api/drivers.json"
OUT_FILE = Path(__file__).parent.parent / "data" / "loldrivers.json"


def fetch_and_compact() -> None:
    print(f"Fetching {API_URL} ...")
    with urllib.request.urlopen(API_URL, timeout=30) as resp:  # noqa: S310
        raw: list[dict] = json.loads(resp.read())

    print(f"  {len(raw)} entries received — compacting ...")

    compact: list[dict] = []
    seen_filenames: set[str] = set()

    for entry in raw:
        samples = entry.get("KnownVulnerableSamples") or []
        tags = entry.get("Tags") or []
        resources = entry.get("Resources") or []
        category = entry.get("Category", "")

        for sample in samples:
            filename = (sample.get("Filename") or "").strip()
            if not filename or not filename.lower().endswith(".sys"):
                continue
            key = filename.lower()
            if key in seen_filenames:
                continue
            seen_filenames.add(key)
            compact.append({
                "filename": filename,
                "category": category,
                "tags": tags[:5],
                "resources": resources[:3],
            })

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps(compact, indent=2), encoding="utf-8")
    print(f"  Saved {len(compact)} driver entries -> {OUT_FILE}")


if __name__ == "__main__":
    fetch_and_compact()
