"""Generate a human-readable analyst narrative from a structured analysis result.

Paragraph 1 is a **mechanics-first** plain-language description ("what this
command actually does") synthesized from the parsed binaries + flag tables
below — written for someone who doesn't yet read shell fluently. Paragraphs
2–4 carry the existing analyst context (LOLBAS / threat intel / verdict).

One panel, two audiences. No AI per request — deterministic, free, fast.
"""

from __future__ import annotations

import re
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Mechanics-first paragraph-1 generator
# ─────────────────────────────────────────────────────────────────────────────
#
# These tables translate a parsed binary + its arguments into a plain-English
# clause. The dictionaries are intentionally small and curated — we cover the
# binaries that show up in 80% of real submissions and fall back to a generic
# "runs X with arguments …" for everything else.

# binary (no .exe) → short noun phrase used after "uses".
_BINARY_PURPOSE: dict[str, str] = {
    "bitsadmin": "the Windows BITS file-transfer utility",
    "certutil":  "the Windows certificate utility",
    "vssadmin":  "the Volume Shadow Copy admin tool",
    "wbadmin":   "the Windows Backup utility",
    "bcdedit":   "the boot configuration editor",
    "diskpart":  "the disk-partition utility",
    "diskshadow": "the shadow-copy management utility",
    "schtasks":  "the Windows task scheduler",
    "reg":       "the registry editor",
    "sc":        "the Service Control Manager utility",
    "net":       "the Windows net command",
    "taskkill":  "the process termination utility",
    "tasklist":  "the running-process enumerator",
    "powershell": "PowerShell",
    "pwsh":      "PowerShell Core",
    "mshta":     "mshta (the HTML-Application host)",
    "regsvr32":  "regsvr32 (the COM object registrar)",
    "rundll32":  "rundll32 (the DLL function runner)",
    "wmic":      "WMIC (the WMI command-line interface)",
    "msiexec":   "the Windows installer (msiexec)",
    "netsh":     "netsh (the network shell)",
    "icacls":    "icacls (the file-permission editor)",
    "attrib":    "attrib (the file-attribute editor)",
    "psexec":    "PsExec (Sysinternals remote execution)",
    "procdump":  "ProcDump (Sysinternals process dumper)",
    "mimikatz":  "Mimikatz (credential theft tool)",
    "ntdsutil":  "ntdsutil (the Active Directory database tool)",
    "curl":      "curl",
    "wget":      "wget",
    "ssh":       "ssh",
    "scp":       "scp",
    "bash":      "bash",
    "iex":       "Invoke-Expression",
    "rubeus":    "Rubeus (Kerberos attack toolkit)",
}

# binary → ordered list of (regex, verb_phrase). First match wins for the
# "primary action"; remaining matches contribute as modifiers. Capture groups
# in the regex are interpolated into the phrase via {1}, {2}, … (str.format).
_BINARY_VERBS: dict[str, list[tuple[str, str]]] = {
    "bitsadmin": [
        (r"/transfer\b", "download a file"),
    ],
    "certutil": [
        (r"-urlcache\b.*?-f\b", "download a file (via the URL cache)"),
        (r"-verifyctl\b",       "download a CTL file"),
        (r"-decode\b",          "decode a base64-encoded file"),
        (r"-encode\b",          "encode a file as base64"),
        (r"-hashfile\b",        "compute a file hash"),
    ],
    "vssadmin": [
        (r"delete\s+shadows", "delete Volume Shadow Copies (blocks System Restore)"),
        (r"create\s+shadow",  "create a Volume Shadow Copy"),
        (r"resize\b",         "resize shadow storage"),
        (r"list\b",           "list shadow copies"),
    ],
    "wbadmin": [
        (r"delete\s+catalog", "delete the Windows Backup catalog"),
        (r"delete\s+systemstatebackup", "delete system-state backups"),
    ],
    "bcdedit": [
        (r"/set\b.*recoveryenabled\s+no",       "disable Windows Recovery Environment"),
        (r"/set\b.*safeboot",                   "configure safe-mode boot"),
        (r"/set\b.*bootstatuspolicy\s+ignore",  "suppress boot-failure prompts"),
    ],
    "diskpart": [
        (r"\bclean\b",   "wipe a disk"),
        (r"\bformat\b",  "format a partition"),
    ],
    "schtasks": [
        (r"/create\b", "create a scheduled task (persistence)"),
        (r"/delete\b", "delete a scheduled task"),
        (r"/run\b",    "run an existing scheduled task"),
        (r"/change\b", "modify a scheduled task"),
    ],
    "reg": [
        (r"\badd\b.*?\\Run(?:Once)?\b",  "add a Windows startup registry key (persistence)"),
        (r"\badd\b.*?Winlogon",          "modify a Winlogon registry key (persistence)"),
        (r"\bsave\b.*?\\SAM\b",          "export the SAM credential hive"),
        (r"\bsave\b.*?\\SYSTEM\b",       "export the SYSTEM registry hive"),
        (r"\bsave\b.*?\\SECURITY\b",     "export the SECURITY registry hive"),
        (r"\badd\b",                     "write a registry value"),
        (r"\bdelete\b",                  "delete a registry value"),
        (r"\bquery\b",                   "query a registry value"),
        (r"\bsave\b",                    "export a registry hive"),
        (r"\bload\b",                    "load a registry hive"),
    ],
    "sc": [
        (r"\\\\\S+",                     "control a service on a remote host"),
        (r"\bcreate\b.*?binpath",        "create a service pointing at a custom binary"),
        (r"\bconfig\b.*?binpath",        "redirect an existing service to a custom binary"),
        (r"\bstop\b",                    "stop a Windows service"),
        (r"\bstart\b",                   "start a Windows service"),
        (r"\bdelete\b",                  "delete a Windows service"),
    ],
    "net": [
        (r"\bstop\s+([A-Za-z0-9_\-\.]+)",  "stop the {1} service"),
        (r"\bstart\s+([A-Za-z0-9_\-\.]+)", "start the {1} service"),
        (r"\buse\s+\\\\",                  "mount a network share"),
        (r"\buser\b",                      "enumerate or modify user accounts"),
        (r"\blocalgroup\b",                "enumerate or modify local groups"),
        (r"\bshare\b",                     "enumerate network shares"),
        (r"\bview\b",                      "enumerate network resources"),
    ],
    "taskkill": [
        (r"/f.*?/im\s+([A-Za-z0-9_\-\.]+)",  "force-terminate {1}"),
        (r"/im\s+([A-Za-z0-9_\-\.]+)",       "terminate {1}"),
        (r"/f\b",                            "force-terminate a process"),
    ],
    "powershell": [
        (r"-(?:e|en|ec|enc|encodedcommand)\b\s+\S{20,}", "execute a base64-encoded PowerShell payload"),
        (r"-(?:c|command)\b",                            "execute an inline PowerShell command"),
        (r"-file\b|-f\s",                                "run a PowerShell script file"),
    ],
    "pwsh": [
        (r"-(?:e|en|ec|enc|encodedcommand)\b\s+\S{20,}", "execute a base64-encoded PowerShell payload"),
        (r"-(?:c|command)\b",                            "execute an inline PowerShell command"),
    ],
    "mshta": [
        (r"javascript:",  "execute inline JavaScript via mshta"),
        (r"vbscript:",    "execute inline VBScript via mshta"),
        (r"h(?:tt|xx)ps?://", "download and execute a remote HTA payload"),
    ],
    "regsvr32": [
        (r"/i:.*?(?:http|hxxp)",  "download and register a remote COM scriptlet (Squiblydoo)"),
        (r"/u\b",                 "unregister a COM scriptlet"),
        (r"\.dll\b",              "register a DLL"),
    ],
    "rundll32": [
        (r"javascript:",       "execute inline JavaScript via rundll32"),
        (r"\S+\.dll,\S+",      "load a DLL and invoke a specific exported function"),
    ],
    "wmic": [
        (r"/node:",                       "execute a command on a remote host via WMI"),
        (r"process\s+call\s+create",      "create a new process via WMI"),
        (r"shadowcopy.*delete",           "delete Volume Shadow Copies via WMI"),
    ],
    "msiexec": [
        (r"/i\s+(?:http|hxxp)",   "download and install a remote MSI package"),
        (r"/i\b",                 "install an MSI package"),
    ],
    "netsh": [
        (r"advfirewall.*disable",                    "disable Windows Firewall"),
        (r"advfirewall.*allow",                      "add a Windows Firewall allow rule"),
        (r"interface\s+portproxy\s+add",             "create a port-proxy tunnel (traffic forwarding)"),
        (r"trace\s+start",                           "start a network packet trace (potential sniffing)"),
    ],
    "icacls": [
        (r"/grant\b",                  "grant file or folder permissions"),
        (r"/deny\b",                   "deny file or folder permissions"),
        (r"/inheritance:[de]\b",       "modify file-inheritance settings"),
    ],
    "attrib": [
        (r"\+[Hh]\b",  "hide a file or folder"),
        (r"-[Hh]\b",   "unhide a file or folder"),
        (r"\+[Ss]\b",  "mark a file as a system file"),
    ],
    "psexec": [
        (r"\\\\\S+",   "execute a command remotely on another host"),
    ],
    "procdump": [
        (r"-ma\s+lsass",  "dump LSASS memory for offline credential extraction"),
        (r"-ma\b",        "dump full process memory"),
    ],
    "mimikatz": [
        (r"sekurlsa::logonpasswords", "dump cleartext credentials from LSASS memory"),
        (r"sekurlsa::pth",            "perform a pass-the-hash attack"),
        (r"kerberos::golden",         "forge a Kerberos Golden Ticket"),
        (r"lsadump::",                "dump credentials from LSA"),
    ],
    "ntdsutil": [
        (r"",  "access the Active Directory credential database"),
    ],
    "curl": [
        (r"\|\s*(?:bash|sh|python3?|perl|ruby|iex|powershell)\b", "download content and pipe it directly to a shell interpreter"),
        (r"-F\s+\S*=@",                                "upload a local file over HTTP"),
        (r"-X\s+POST|--post-data|-d\s",                "send an HTTP POST request"),
        (r"-o\b|-O\b|--output\b",                      "download a file"),
    ],
    "wget": [
        (r"\|\s*(?:bash|sh|python3?|perl|ruby|iex|powershell)\b", "download content and pipe it directly to a shell interpreter"),
        (r"-O\b|--output-document\b",                  "download a file"),
    ],
    "bash": [
        (r"-c\b",  "run an inline shell command"),
        (r"-s\b",  "read commands from standard input (typical of `curl | bash`)"),
    ],
    "ssh": [
        (r"-[RL]\s+\d+:",  "create an SSH port-forward tunnel"),
        (r"\S+@\S+",       "open an SSH session to a remote host"),
    ],
    "scp": [
        (r"",  "copy files between hosts over SSH"),
    ],
    "iex": [
        (r"",  "execute a string as PowerShell code"),
    ],
}

# Plain extensionless name → key in the tables above (so curl.exe and curl
# both resolve, and `iex` / `Invoke-Expression` map to the same entry).
_BINARY_ALIASES: dict[str, str] = {
    "invoke-expression": "iex",
}

# Split on sequential operators only — `|` keeps a pipeline as one logical
# segment ("curl … | bash …" is one action, not two) so a binary's own
# pipe-aware verb rule (e.g. curl's "pipes to shell interpreter") can fire.
_CHAIN_SPLIT = re.compile(r"(?<![|&])\s*(&&|\|\||;|&)\s*(?![&])")
_CHAIN_LABEL = {"&": "then", "&&": "and, if that succeeds,", ";": "then", "||": "or, if that fails,"}

_URL_RE = re.compile(r"h(?:tt|xx)ps?://([^\s'\"<>;|&\\)]+)", re.IGNORECASE)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s'\"<>|&]+\.(?:exe|dll|bat|cmd|ps1|vbs|hta|js)\b", re.IGNORECASE)


def _normalize_binary(name: str) -> str:
    base = name.lower().split("\\")[-1].split("/")[-1].removesuffix(".exe")
    return _BINARY_ALIASES.get(base, base)


def _describe_segment(segment: str, binary_names: list[str]) -> str | None:
    """Build one sentence describing what *segment* does, using the first
    binary in *binary_names* that we have a verb table for. Returns None when
    we can't say anything useful — caller decides whether to fall back."""
    seg = segment.strip()
    if not seg:
        return None

    # Pick the first binary in this segment that we have rules for.
    chosen: str | None = None
    for raw_name in binary_names:
        n = _normalize_binary(raw_name)
        if n in _BINARY_VERBS or n in _BINARY_PURPOSE:
            chosen = n
            break
    if chosen is None:
        # Generic fallback when at least one binary token is in the segment.
        if binary_names:
            # Strip the leading invocation token (path/binary) so we report
            # JUST the arguments — without it, the fallback duplicates the
            # binary name inside its own args field.
            args = re.sub(r"^\S+\s*", "", seg).strip()
            if not args:
                return f"Runs `{binary_names[0]}` with no arguments."
            tail = args[:80].rstrip()
            ellipsis = "…" if len(args) > 80 else ""
            return f"Runs `{binary_names[0]}` with arguments: `{tail}{ellipsis}`."
        return None

    # First matching verb is the primary clause.
    verb_phrase: str | None = None
    for pattern, template in _BINARY_VERBS.get(chosen, []):
        m = re.search(pattern, seg, re.IGNORECASE | re.DOTALL)
        if m:
            try:
                verb_phrase = template.format(*([m.group(0)] + list(m.groups())))
            except (IndexError, KeyError):
                verb_phrase = template
            break

    if verb_phrase is None:
        # Binary is known but no flag pattern matched — use the noun phrase
        # so the reader still learns the binary's purpose.
        purpose = _BINARY_PURPOSE.get(chosen)
        if purpose:
            return f"Invokes {purpose}."
        return f"Runs `{chosen}`."

    # Modifiers: silently / remote URL / target path.
    modifiers: list[str] = []
    if re.search(r"/(?:quiet|silent|q)\b", seg, re.IGNORECASE) and "silently" not in verb_phrase:
        modifiers.append("silently")
    url_match = _URL_RE.search(seg)
    if url_match and "from" not in verb_phrase and "download" in verb_phrase.lower():
        host = url_match.group(1).split("/")[0].replace("[.]", ".")
        modifiers.append(f"from `{host}`")
    path_match = _WIN_PATH_RE.search(seg)
    if path_match and "download" in verb_phrase.lower() and " to " not in verb_phrase:
        path = path_match.group(0)
        modifiers.append(f"to `{path}`")

    purpose = _BINARY_PURPOSE.get(chosen, f"`{chosen}`")
    sentence = f"Uses {purpose} to {verb_phrase}"
    if modifiers:
        sentence += " " + " ".join(modifiers)
    return sentence.rstrip(".") + "."


def _split_chain(command: str) -> list[tuple[str, str]]:
    """Split *command* on top-level chain operators. Returns
    [(segment, leading_operator), …]. The first segment's operator is ""."""
    parts = _CHAIN_SPLIT.split(command)
    out: list[tuple[str, str]] = [(parts[0], "")]
    for i in range(1, len(parts), 2):
        op = parts[i]
        seg = parts[i + 1] if i + 1 < len(parts) else ""
        out.append((seg, op))
    return out


def _describe_mechanics(result: dict[str, Any]) -> str | None:
    """Plain-language description of what the command does. None when we
    couldn't synthesize anything (caller falls back to the threat-class P1)."""
    command = str(result.get("command") or "")
    if not command:
        return None
    binaries = [b.get("name") for b in (result.get("binaries_in_command") or []) if b.get("name")]
    if not binaries:
        return None

    sentences: list[str] = []
    for idx, (segment, op) in enumerate(_split_chain(command)):
        seg_binaries = [b for b in binaries if _normalize_binary(b) in segment.lower()]
        if not seg_binaries:
            # Fall back to global binary list for the first segment (covers
            # commands we couldn't split cleanly).
            seg_binaries = binaries if idx == 0 else []
        s = _describe_segment(segment, seg_binaries)
        if not s:
            continue
        if idx > 0 and sentences:
            connector = _CHAIN_LABEL.get(op, "then")
            # Lowercase the verb so "Uses bitsadmin … then runs patch.exe."
            s = s[0].lower() + s[1:]
            sentences.append(f"{connector} {s}")
        else:
            sentences.append(s)
        # Cap at 3 segments — beyond that the paragraph gets noisy.
        if len(sentences) >= 3:
            break

    if not sentences:
        return None
    # Stitch: first sentence stands alone; subsequent segments comma-joined
    # if we used a connector ("then runs X"), keeping it as one paragraph.
    out = sentences[0]
    for extra in sentences[1:]:
        out = out.rstrip(".") + ", " + extra
    if not out.endswith("."):
        out += "."

    # If the command was obfuscated, append a brief decoded-content pointer so
    # the reader knows there's more to look at below.
    layers = [l for l in (result.get("decoded_layers") or [])
              if l.get("encoding") not in ("limit-reached", "env-variable-substitution")]
    if layers:
        out += f" The payload is obfuscated ({len(layers)} decode layer{'s' if len(layers) != 1 else ''}); see the decoded content below."
    return out


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

    # ── Paragraph 1: what the command does (mechanics-first) ─────────────────
    # Try the plain-language description first — built from per-binary verb
    # tables, the parsed binaries, extracted URLs/paths, and chain operators.
    # Falls back to the classification-first phrasing when we don't have rules
    # for any of the binaries in the command (very rare in practice).
    p1 = _describe_mechanics(result)
    if p1 is None:
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

        # In fallback mode only, surface the top signal from each high/med
        # class — the mechanics description already conveys this when it ran.
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
