#!/usr/bin/env python3
"""
Fetch the MITRE ATT&CK enterprise-attack STIX bundle and regenerate
backend/data/attack_techniques.json with a complete, authoritative dataset.

Usage:
    python backend/scripts/fetch_attack_stix.py

Pins to the STIX bundle at the mitre/cti main branch. Re-run quarterly
per CLAUDE.md policy ("refresh quarterly").

Source: https://github.com/mitre/cti
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUT_FILE = Path(__file__).parent.parent / "data" / "attack_techniques.json"

# Map STIX kill_chain phase_name -> human-readable tactic label
_TACTIC_MAP: dict[str, str] = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "resource-development": "Resource Development",
    "reconnaissance": "Reconnaissance",
}


def fetch_bundle() -> dict:
    print(f"Fetching STIX bundle from {STIX_URL} ...")
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        r = client.get(STIX_URL)
        r.raise_for_status()
    print(f"Downloaded {len(r.content) / 1024 / 1024:.1f} MB")
    return r.json()


def parse_techniques(bundle: dict) -> dict[str, dict]:
    techniques: dict[str, dict] = {}
    objects = bundle.get("objects", [])
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Extract technique ID from external references
        ext_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not ext_id:
            continue

        # Primary tactic (first kill chain phase)
        tactic = None
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = _TACTIC_MAP.get(phase.get("phase_name", ""), phase.get("phase_name", ""))
                break

        # Truncate description to avoid bloating the JSON
        description: str = obj.get("description", "")
        if description:
            # Take first sentence / 300 chars
            first_sentence = description.split(".")[0]
            description = (first_sentence[:300] + "...") if len(first_sentence) > 300 else first_sentence

        techniques[ext_id] = {
            "name": obj.get("name", ext_id),
            "tactic": tactic or "Unknown",
            "description": description,
            "url": url or f"https://attack.mitre.org/techniques/{ext_id.replace('.', '/')}",
        }

    return techniques


def main() -> None:
    bundle = fetch_bundle()
    techniques = parse_techniques(bundle)
    print(f"Parsed {len(techniques)} active techniques/sub-techniques")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps(techniques, indent=2, sort_keys=True))
    print(f"Written -> {OUT_FILE}  ({OUT_FILE.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
