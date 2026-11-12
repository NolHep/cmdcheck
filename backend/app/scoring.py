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

from .classifier import ThreatClass
from .tuning import Tuning, get_active

Severity = Literal["malicious", "suspicious", "notable", "low", "clean"]

# Every number used below comes from tuning.Tuning (defaults there, overrides
# from the admin tuner). Fixture expectations in backend/tests/ are written
# against the defaults.


def compute_verdict(
    threat_classes: list[ThreatClass],
    *,
    has_lolbas: bool = False,
    has_gtfobins: bool = False,
    has_loldrivers: bool = False,
    encoding_depth: int = 0,
    lolbas_abuse: list[str] | None = None,
    installer: str | None = None,
    search_only: bool = False,
    tuning: Tuning | None = None,
) -> dict[str, Any]:
    """Return {severity, label, detail, score, breakdown}."""
    t = tuning or get_active()
    _MALICIOUS, _SUSPICIOUS, _NOTABLE = t.threshold_malicious, t.threshold_suspicious, t.threshold_notable
    breakdown: list[dict[str, Any]] = []
    score = 0.0

    high_labels: list[str] = []
    medium_labels: list[str] = []

    for tc in threat_classes:
        base = t.confidence_points(tc.confidence)
        weight = t.class_weights.get(tc.name, 1.0)
        # A signal hidden under obfuscation is far stronger evidence of malice.
        mult = 1.0 + t.depth_step * min(max(tc.max_depth, 0), 5)
        precision = getattr(tc, "precision", 1.0)
        pts = base * weight * mult * precision
        score += pts
        breakdown.append({
            "class": tc.name,
            "confidence": tc.confidence,
            "max_depth": tc.max_depth,
            "precision": precision,
            "points": round(pts, 2),
        })
        if getattr(tc, "chain", False) and t.recon_chain_bonus:
            score += t.recon_chain_bonus
            breakdown.append({"class": "_recon_chain", "points": t.recon_chain_bonus})
        if tc.confidence == "high":
            high_labels.append(tc.label)
        elif tc.confidence == "medium":
            medium_labels.append(tc.label)

    # Multi-stage behavior is the strongest real-world malice signal, but two
    # *medium* classes are often just benign admin work (e.g. Enter-PSSession +
    # schtasks). Count high-confidence classes fully and medium at half, so the
    # bonus only kicks in for genuine multi-stage chains, not admin combos.
    corr_units = len(high_labels) + 0.5 * len(medium_labels)
    correlation_bonus = max(0.0, corr_units - 1.0) * t.correlation_bonus
    if correlation_bonus:
        score += correlation_bonus
        breakdown.append({"class": "_correlation", "points": round(correlation_bonus, 2)})

    # BYOVD — kernel-level privilege escalation, severe on its own.
    if has_loldrivers:
        score += t.loldrivers_points
        breakdown.append({"class": "_loldrivers", "points": t.loldrivers_points})

    # An encoded payload is notable even with no behavioral detection.
    if encoding_depth >= 1:
        enc_pts = t.encoding_base + t.encoding_step * min(encoding_depth - 1, 4)
        score += enc_pts
        breakdown.append({"class": "_encoding", "points": round(enc_pts, 2)})

    # The arguments resemble a documented LOLBAS abuse example. This is real
    # evidence (unlike the binary's mere presence): worth "notable" by itself
    # and enough to lift a medium behavioural hit to "suspicious".
    if lolbas_abuse:
        score += t.lolbas_abuse_points
        breakdown.append({"class": "_lolbas_abuse", "points": t.lolbas_abuse_points,
                          "binaries": lolbas_abuse})
    # A known-abusable binary alone is weak signal, not an alarm.
    elif (has_lolbas or has_gtfobins) and not threat_classes:
        score += t.lolbin_presence_points
        breakdown.append({"class": "_lolbin", "points": t.lolbin_presence_points})

    score = round(min(score, 100.0), 2)

    # A documented installer one-liner (rustup, Chocolatey, …) is shaped
    # exactly like a dropper. When the URL is an exact known-installer URL and
    # nothing but download-and-run rules fired, say so instead of crying wolf.
    if (
        installer
        and threat_classes
        and not has_loldrivers
        and score >= _SUSPICIOUS
        and all(getattr(tc, "installer_only", False) for tc in threat_classes)
    ):
        capped = round(_SUSPICIOUS - 0.5, 2)
        breakdown.append({"class": "_known_installer", "points": round(capped - score, 2)})
        return {
            "severity": "notable",
            "label": "Notable — matches a well-known installer",
            "detail": (
                f"This is the download-and-run pattern attackers use, but the only URL is "
                f"the documented installer at {installer}. Confirm the URL character by "
                f"character — look-alike domains are a common lure."
            ),
            "score": capped,
            "breakdown": breakdown,
        }

    # `grep -i mimikatz edr.log` names an attack tool without using it.
    if search_only and threat_classes and not has_loldrivers and score >= _SUSPICIOUS:
        capped = round(_SUSPICIOUS - 0.5, 2)
        breakdown.append({"class": "_search_query", "points": round(capped - score, 2)})
        return {
            "severity": "notable",
            "label": "Notable — indicator terms inside a search",
            "detail": (
                "This command searches text for attack-related terms rather than running them — "
                "typical of an analyst or a detection script. Check what is being searched and why."
            ),
            "score": capped,
            "breakdown": breakdown,
        }

    if has_loldrivers:
        severity: Severity = "malicious" if score >= _MALICIOUS else "suspicious"
        label = f"{'Malicious' if severity == 'malicious' else 'Suspicious'} — known-vulnerable driver (BYOVD)"
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
        detail = (
            f"Attack signal: {sigs[0]}." if len(sigs) == 1
            else f"Multiple corroborating attack signals: {', '.join(sigs)}."
        )
    elif score >= _SUSPICIOUS:
        severity = "suspicious"
        sigs = high_labels or medium_labels
        label = "Suspicious — likely attack behavior"
        detail = (
            f"Threat behavior detected: {', '.join(sigs)}."
            if sigs else "Multiple low-confidence indicators detected. Review with context."
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
        label = "No signal"
        detail = "No known-abused binary, encoding, or threat behavior detected. May still be malicious — use context."

    return {"severity": severity, "label": label, "detail": detail,
            "score": score, "breakdown": breakdown}
