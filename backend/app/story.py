"""Generate a human-readable analyst narrative from a structured analysis result."""

from __future__ import annotations

from typing import Any


def generate_story(result: dict[str, Any]) -> str:
    """Return a 2–4 paragraph analyst narrative for the given analysis result."""
    paragraphs: list[str] = []

    threat_classes: list[dict] = result.get("threat_classes", []) or []
    decoded_layers: list[dict] = result.get("decoded_layers", []) or []
    lolbas_matches: list[dict] = result.get("lolbas_matches", []) or []
    gtfobins_matches: list[dict] = result.get("gtfobins_matches", []) or []
    loldrivers: dict | None = result.get("loldrivers_match")
    parent_verdict: dict | None = result.get("parent_verdict")
    threat_intel: list[dict] = result.get("threat_intel", []) or []
    extracted_ips: list[str] = result.get("extracted_ips", []) or []
    extracted_urls: list[str] = result.get("extracted_urls", []) or []

    high_classes = [tc for tc in threat_classes if tc.get("confidence") == "high"]
    med_classes = [tc for tc in threat_classes if tc.get("confidence") == "medium"]

    # ── Paragraph 1: classification and key signals ──────────────────────────
    if high_classes:
        names = _join([tc["label"] for tc in high_classes])
        p1 = f"This command exhibits high-confidence indicators of {names}."
    elif med_classes:
        names = _join([tc["label"] for tc in med_classes])
        p1 = f"This command shows medium-confidence patterns consistent with {names}."
    elif threat_classes:
        names = _join([tc.get("label", "") for tc in threat_classes])
        p1 = f"This command contains low-confidence signals that may indicate {names}."
    elif lolbas_matches or gtfobins_matches or loldrivers:
        p1 = "This command invokes known-abused system binaries without exhibiting overt malicious behavior patterns."
    elif decoded_layers:
        # Obfuscation alone is a deliberate evasion signal even with no
        # behavioral rule match — saying "no malicious patterns detected"
        # here would contradict the verdict banner above (which counts
        # encoding as a notable signal).
        n = len([l for l in decoded_layers if l.get("encoding") != "limit-reached"])
        p1 = (
            f"This command is obfuscated ({n} decode layer{'s' if n != 1 else ''}) "
            "but does not match any current behavioral threat rule. "
            "Obfuscation is itself an evasion technique — review the decoded content."
        )
    else:
        p1 = "No malicious behavioral patterns were detected in this command."

    # Surface the top signal from each high/med class for context
    top_signals: list[str] = []
    for tc in (high_classes or med_classes or threat_classes)[:2]:
        sigs = tc.get("signals", [])
        if sigs:
            top_signals.append(sigs[0].rstrip(".").lower())

    if top_signals:
        p1 += f" Key indicators: {'; '.join(top_signals[:3])}."

    paragraphs.append(p1)

    # ── Paragraph 2: binary and obfuscation analysis ─────────────────────────
    parts2: list[str] = []

    lolbas_names = [m["name"] for m in lolbas_matches if m.get("name")]
    if lolbas_names:
        funcs = list({f for m in lolbas_matches for f in (m.get("functions") or [])})
        func_str = f" — known abuse categories: {_join(funcs[:3])}" if funcs else ""
        parts2.append(
            f"The command leverages {_join(lolbas_names)}, a Windows "
            f"{'binary' if len(lolbas_names) == 1 else 'set of binaries'} "
            f"catalogued in LOLBAS as commonly abused for living-off-the-land attacks{func_str}."
        )

    gtfo_names = [m["name"] for m in gtfobins_matches if m.get("name")]
    if gtfo_names:
        funcs = list({f for m in gtfobins_matches for f in (m.get("functions") or [])})
        func_str = f" ({_join(funcs[:3])})" if funcs else ""
        parts2.append(
            f"It also uses {_join(gtfo_names)}, a Unix binary listed in GTFOBins"
            f" with known privilege-escalation or execution abuse vectors{func_str}."
        )

    if loldrivers:
        fn = loldrivers.get("filename", "a kernel driver")
        cat = loldrivers.get("category", "")
        parts2.append(
            f"A known-vulnerable kernel driver ({fn}"
            f"{f', category: {cat}' if cat else ''}) is referenced — "
            f"a hallmark of Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks, "
            f"used to disable endpoint security products or escalate to kernel-level privilege."
        )

    if decoded_layers:
        n = len(decoded_layers)
        encodings = [layer.get("encoding", "unknown") for layer in decoded_layers]
        # Drop the limit-reached marker from the display chain
        display_encodings = [e for e in encodings if e != "limit-reached"]
        chain = " → ".join(display_encodings) if display_encodings else "unknown"
        hit_limit = any(layer.get("encoding") == "limit-reached" for layer in decoded_layers)

        if n == 1 or (n == 2 and hit_limit):
            parts2.append(
                f"The payload uses {chain} encoding — a common obfuscation technique "
                f"to bypass signature-based detection and inline script-block logging."
            )
        else:
            depth = len(display_encodings)
            parts2.append(
                f"The command uses {depth}-layer chained encoding ({chain}), "
                f"indicating deliberate multi-stage obfuscation. "
                f"Deep encoding stacks are strongly associated with mature malware loaders "
                f"such as Lumma, Latrodectus, and ClickFix-style initial access payloads."
            )

        if hit_limit:
            parts2.append(
                "The decoder reached its maximum depth without fully unwrapping the payload. "
                "This level of obfuscation warrants manual analysis or sandbox detonation."
            )

    if parts2:
        paragraphs.append(" ".join(parts2))

    # ── Paragraph 3: threat intelligence and process context ─────────────────
    parts3: list[str] = []

    malicious = [
        r for r in threat_intel
        if (r.get("virustotal") and r["virustotal"].get("malicious", 0) > 0)
        or (r.get("urlhaus") and r["urlhaus"].get("status") == "online")
        or r.get("threatfox")
        or (r.get("greynoise") and r["greynoise"].get("classification") == "malicious")
        or (r.get("abuseipdb") and r["abuseipdb"].get("score", 0) >= 50)
    ]

    if malicious:
        snippets: list[str] = []
        for r in malicious[:3]:
            ind = r.get("indicator", "")
            flags: list[str] = []
            vt = r.get("virustotal")
            if vt and vt.get("malicious", 0) > 0:
                flags.append(f"VirusTotal ({vt['malicious']}/{vt['total']} engines)")
            ub = r.get("urlhaus")
            if ub and ub.get("status") == "online":
                flags.append("URLhaus (live malware URL)")
            tf = r.get("threatfox")
            if tf:
                label = tf.get("malware") or tf.get("threat_type") or "IOC"
                flags.append(f"ThreatFox ({label})")
            gn = r.get("greynoise")
            if gn and gn.get("classification") == "malicious":
                flags.append("GreyNoise (malicious scanner)")
            ab = r.get("abuseipdb")
            if ab and ab.get("score", 0) >= 50:
                flags.append(f"AbuseIPDB ({ab['score']}% abuse confidence)")
            snippets.append(f"{ind} flagged by {_join(flags)}")
        parts3.append(f"Threat intelligence hits: {'; '.join(snippets)}.")
    elif extracted_ips or extracted_urls:
        n_ind = len(extracted_ips) + len(extracted_urls)
        parts3.append(
            f"{n_ind} network indicator{'s' if n_ind != 1 else ''} were extracted "
            f"({len(extracted_ips)} IP{'s' if len(extracted_ips) != 1 else ''}, "
            f"{len(extracted_urls)} URL{'s' if len(extracted_urls) != 1 else ''}) "
            f"and returned no hits across queried threat intelligence sources."
        )

    if parent_verdict:
        suspicion = parent_verdict.get("suspicion", "low")
        parent = parent_verdict.get("parent", "")
        child = parent_verdict.get("child", "")
        explanation = parent_verdict.get("explanation", "").rstrip(".")
        if suspicion == "high":
            parts3.append(
                f"The parent-child process relationship ({parent} → {child}) is highly suspicious: "
                f"{explanation}. This process lineage is strongly associated with macro-based or "
                f"drive-by initial access."
            )
        elif suspicion == "medium":
            parts3.append(
                f"The spawning relationship ({parent} → {child}) is unusual: {explanation}."
            )

    if parts3:
        paragraphs.append(" ".join(parts3))

    # ── Paragraph 4: overall verdict ─────────────────────────────────────────
    verdict: str | None = None

    if loldrivers:
        verdict = (
            "The presence of a known-vulnerable driver is a strong indicator of targeted attack "
            "activity. BYOVD is primarily used by sophisticated threat actors — treat this host "
            "as compromised and escalate immediately."
        )
    elif high_classes and (lolbas_matches or decoded_layers):
        verdict = (
            "The combination of high-confidence threat behavior, known-abused binary usage, and "
            "payload obfuscation strongly suggests this is an active attack payload. "
            "Treat this command as malicious and initiate containment procedures."
        )
    elif malicious:
        verdict = (
            "Confirmed threat intelligence hits raise the severity of this command significantly. "
            "The referenced infrastructure is known-malicious — escalate to incident response."
        )
    elif high_classes:
        verdict = (
            "High-confidence threat signals were detected. Treat this command as malicious until "
            "proven otherwise through full investigation of process context, network connections, "
            "and file system changes."
        )
    elif decoded_layers and lolbas_matches:
        verdict = (
            "LOLBin usage combined with encoded payload is a classic living-off-the-land pattern "
            "designed to evade AV and EDR detection. The full decoded payload should be analyzed "
            "for C2 infrastructure, dropped files, or persistence mechanisms."
        )
    elif decoded_layers:
        verdict = (
            "Encoded payloads are rarely present in legitimate administrative commands. "
            "The decoded content should be examined in full — focus on embedded URLs, "
            "download cradles, and any secondary execution commands."
        )
    elif lolbas_matches or gtfobins_matches:
        verdict = (
            "While the detected binaries have legitimate administrative uses, their presence in an "
            "investigation warrants scrutiny of process lineage, network connections made during "
            "execution, and any files created or modified."
        )
    elif not threat_classes:
        verdict = (
            "No malicious patterns were matched. The command may be benign, or it may use "
            "techniques not yet covered by current detection rules. "
            "Always review commands in the context of the broader incident timeline."
        )

    if verdict:
        paragraphs.append(verdict)

    return "\n\n".join(paragraphs)


def _join(items: list[str]) -> str:
    """Natural-language join: 'a', 'a and b', 'a, b, and c'."""
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"
