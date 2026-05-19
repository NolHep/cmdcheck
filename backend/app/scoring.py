"""Aggregate threat classes into a single persisted verdict.

This is the *one* place a headline verdict is computed. It runs in the backend
and the result is stored on the analysis row, so a permalink renders the same
verdict forever even if this logic later changes (CLAUDE.md invariant #2).

Severity is a weighted additive score, not a max() over classes:
  - each class contributes base(confidence) x class_weight
  - a class whose signal only appears after N decode layers is multiplied up
    (nobody accidentally gzip+base64-encodes a benign command)
  - >=2 independent classes firing earns a correlation bonus (multi-stage
    behavior is the strongest real-world malice indicator)
"""

from __future__ import annotations

from typing import Any, Literal

from .classifier import _CLASS_WEIGHTS, ThreatClass

Severity = Literal["malicious", "suspicious", "notable", "low", "clean"]

_CONF_BASE: dict[str, float] = {"low": 1.0, "medium": 4.0, "high": 10.0}

# Score -> severity tier. Tuned against backend/tests/fixtures/*.json.
_MALICIOUS = 14.0
_SUSPICIOUS = 7.0
_NOTABLE = 3.0


def _depth_multiplier(max_depth: int) -> float:
    """A signal hidden under obfuscation is far stronger evidence of malice."""
    return 1.0 + 0.4 * min(max(max_depth, 0), 5)


def compute_verdict(
    threat_classes: list[ThreatClass],
    *,
    has_lolbas: bool = False,
    has_gtfobins: bool = False,
    has_loldrivers: bool = False,
    encoding_depth: int = 0,
) -> dict[str, Any]:
    """Return {severity, label, detail, score, breakdown}."""
    breakdown: list[dict[str, Any]] = []
    score = 0.0

    classes_ge_medium = 0
    high_labels: list[str] = []
    medium_labels: list[str] = []

    for tc in threat_classes:
        base = _CONF_BASE.get(tc.confidence, 1.0)
        weight = _CLASS_WEIGHTS.get(tc.name, 1.0)
        mult = _depth_multiplier(tc.max_depth)
        pts = base * weight * mult
        score += pts
        breakdown.append({
            "class": tc.name,
            "confidence": tc.confidence,
            "max_depth": tc.max_depth,
            "points": round(pts, 2),
        })
        if tc.confidence in ("high", "medium"):
            classes_ge_medium += 1
        if tc.confidence == "high":
            high_labels.append(tc.label)
        elif tc.confidence == "medium":
            medium_labels.append(tc.label)

    # Multi-stage behavior: each independent medium+ class beyond the first.
    correlation_bonus = max(0, classes_ge_medium - 1) * 5.0
    if correlation_bonus:
        score += correlation_bonus
        breakdown.append({"class": "_correlation", "points": round(correlation_bonus, 2)})

    # BYOVD — kernel-level privilege escalation, severe on its own.
    if has_loldrivers:
        score += 12.0
        breakdown.append({"class": "_loldrivers", "points": 12.0})

    # An encoded payload is notable even with no behavioral detection.
    if encoding_depth >= 1:
        enc_pts = 3.0 + 1.0 * min(encoding_depth - 1, 4)
        score += enc_pts
        breakdown.append({"class": "_encoding", "points": round(enc_pts, 2)})

    # A known-abusable binary alone is weak signal, not an alarm.
    if (has_lolbas or has_gtfobins) and not threat_classes:
        score += 2.0
        breakdown.append({"class": "_lolbin", "points": 2.0})

    score = round(score, 2)

    if has_loldrivers:
        severity: Severity = "malicious" if score >= _MALICIOUS else "suspicious"
        label = "Suspicious — known-vulnerable driver (BYOVD)"
        detail = (
            "A Bring-Your-Own-Vulnerable-Driver pattern was detected — a "
            "kernel-level privilege-escalation technique."
        )
        return {"severity": severity, "label": label, "detail": detail,
                "score": score, "breakdown": breakdown}

    if score >= _MALICIOUS:
        severity = "malicious"
        sigs = high_labels or medium_labels
        label = "Malicious — high-confidence attack behavior"
        detail = f"Multiple corroborating attack signals: {', '.join(sigs)}."
    elif score >= _SUSPICIOUS:
        severity = "suspicious"
        sigs = high_labels or medium_labels
        label = "Suspicious — likely attack behavior"
        detail = (
            f"Threat behavior detected: {', '.join(sigs)}."
            if sigs else "Encoded payload via a known-abused binary."
        )
    elif score >= _NOTABLE:
        severity = "notable"
        if medium_labels or high_labels:
            detail = f"Medium-confidence signals: {', '.join(medium_labels or high_labels)}."
        elif encoding_depth >= 1:
            detail = "The command contains an encoded payload. Review the decoded layers."
        else:
            detail = "A known-abused binary was used. Review with context."
        label = "Notable — review recommended"
    elif score > 0:
        severity = "low"
        label = "Low signal — weak indicators present"
        detail = "Only weak/low-confidence indicators were found. May be benign — use context."
    else:
        severity = "clean"
        label = "Low signal"
        detail = "No known-abused binary, encoding, or threat behavior detected. May still be malicious — use context."

    return {"severity": severity, "label": label, "detail": detail,
            "score": score, "breakdown": breakdown}
