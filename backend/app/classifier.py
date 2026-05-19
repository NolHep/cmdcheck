"""Rule-based threat-class identification for command strings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from . import mitre

Confidence = Literal["high", "medium", "low"]

# Matches both live (http://) and analyst-defanged (hxxp://) URLs
_URL = r"h(?:xx|tt)ps?://"


@dataclass
class ThreatClass:
    name: str
    label: str
    confidence: Confidence
    signals: list[str]
    techniques: list[dict[str, Any]]
    # Deepest decode layer at which a signal for this class was found.
    # 0 = present in cleartext; >0 = only revealed after deobfuscation
    # (a strong malice indicator — nobody accidentally encodes a benign command).
    max_depth: int = 0
    # Max precision among the matched rule(s) that set this class's confidence.
    # Scales the score in compute_verdict() without changing displayed confidence.
    precision: float = 1.0


@dataclass
class _Rule:
    pattern: re.Pattern[str]
    signal: str
    confidence: Confidence
    technique_ids: list[str] = field(default_factory=list)
    # When True, this rule's signal only counts if at least one *non*-corroborating
    # rule in the same class also matched. Isolates single-token rules that are
    # noisy on their own (e.g. bare "lsass", a generic "curl <url>").
    requires_corroboration: bool = False
    # Likelihood the match is a true positive, independent of severity. A tool
    # name like "mimikatz" is ~certain (1.0); a heuristic like a bare TcpClient
    # reference is suggestive but weak (~0.6). Scales the score, not the
    # displayed confidence.
    precision: float = 1.0


def _r(
    pattern: str,
    signal: str,
    confidence: Confidence,
    *technique_ids: str,
    corroborate: bool = False,
    precision: float = 1.0,
) -> _Rule:
    return _Rule(
        re.compile(pattern, re.IGNORECASE | re.DOTALL),
        signal,
        confidence,
        list(technique_ids),
        corroborate,
        precision,
    )


@dataclass
class _ClassDef:
    name: str
    label: str
    rules: list[_Rule]
    # Severity weight — how damaging this class is if the detection is true.
    # Used by scoring.compute_verdict(); does not affect per-class confidence.
    weight: float = 1.0


_CLASSES: list[_ClassDef] = [
    # ── Dropper ──────────────────────────────────────────────────────────────────
    _ClassDef("dropper", "Dropper", [
        # .DownloadString( is the IEX-cradle hallmark — almost never benign.
        _r(r"\.DownloadString\s*\(",
           "Downloads a string for in-memory execution (.DownloadString — IEX cradle)", "high", "T1105"),
        # Invoke-WebRequest / iwr / .DownloadFile( is the standard PowerShell HTTP
        # client — routinely benign (downloading a PDF, an installer, an API
        # response). Only counts alongside a stronger dropper signal.
        _r(r"Invoke-WebRequest|\biwr\b|\.DownloadFile\s*\(",
           "Downloads a file via Invoke-WebRequest/WebClient", "medium", "T1105",
           corroborate=True),
        _r(r"certutil\b.*-urlcache",
           "Downloads file via certutil -urlcache (LOLbin)", "high", "T1105", "T1218.001"),
        _r(r"bitsadmin\s+/transfer",
           "Downloads file via BITS job", "high", "T1197"),
        _r(r"Start-BitsTransfer\b",
           "Downloads file via BITS using PowerShell Start-BitsTransfer", "high", "T1197"),
        _r(fr"mshta\b.*{_URL}",
           "Executes remote HTA payload via mshta", "high", "T1218.005"),
        # Pipe-to-shell: curl/wget output piped directly into an interpreter (including PowerShell IEX)
        _r(r"\b(wget|curl)\b.*?\|.*?\b(bash|sh|python3?|perl|ruby|iex|powershell(?:\.exe)?)\b",
           "Downloads and pipes content directly to a shell interpreter", "high", "T1059.004", "T1105"),
        # Any HTTP client pulling a raw executable/script payload from a URL is a
        # strong standalone dropper signal (and corroborates the IWR rule above).
        _r(fr"(?:\b(?:wget|curl|iwr|Invoke-WebRequest|DownloadFile|DownloadData|DownloadString)\b|Net\.WebClient).*?{_URL}\S*\.(?:exe|ps1|bat|vbs|hta|sh|py|rb|pl|dll|scr)\b",
           "Downloads an executable or script payload over HTTP", "high", "T1105"),
        # curl/wget fetching any URL — only counts alongside a stronger dropper
        # signal (pipe-to-shell, malicious extension). Alone it is just a download.
        _r(fr"\b(curl|wget)\b.*?{_URL}",
           "Fetches remote content via curl or wget", "low", "T1105", corroborate=True),
        # Raw TCP socket — PowerShell reverse shell C2 channel
        _r(r"Net\.Sockets\.TcpClient|Net\.Sockets\.TcpListener",
           "Opens raw TCP socket (reverse shell or C2 beacon pattern)", "high", "T1095",
           precision=0.7),
    ]),

    # ── Loader / Code Execution ───────────────────────────────────────────────
    _ClassDef("loader", "Loader", [
        # Unambiguous forms (-EncodedCommand, -enc…) accept a normal-length b64
        # payload. The bare aliases -e/-en/-ec collide with common flags
        # (grep -e, sed -e), so they require a 40+ char b64 run to disambiguate.
        _r(r"(?:-[Ee][Nn][Cc](?:o?d?e?d?)?(?:[Cc]omm?and)?)\s+[A-Za-z0-9+/]{20,}"
           r"|(?:-[Ee][Nn]\b|-[Ee][Cc]\b|-[Ee]\b)\s+[A-Za-z0-9+/]{40,}",
           "Executes base64-encoded PowerShell command", "high", "T1059.001", "T1027.010"),
        _r(r"(Invoke-Expression|IEX)\s*[\(\$]|\|\s*(?:iex|Invoke-Expression)\b",
           "Executes string as code via Invoke-Expression", "high", "T1059.001"),
        # mshta with javascript: scheme (FIN7, ClickFix lures)
        _r(r"mshta\b.*?javascript:",
           "Executes inline JavaScript payload via mshta", "high", "T1218.005"),
        # regsvr32 loading remote scriptlet (Squiblydoo) — handles hxxp:// defanging
        _r(fr"regsvr32\b.*?(?:/s|/i:).*?{_URL}",
           "Loads remote COM scriptlet via regsvr32 (Squiblydoo)", "high", "T1218.010"),
        # regsvr32 silently loading a local DLL from a writable/staging directory
        _r(r"regsvr32\b.*?/s\b.*?(?:temp|public|appdata|downloads|programdata).*?\.dll\b",
           "Silently loads DLL from user-writable staging directory via regsvr32", "medium", "T1218.010"),
        _r(r"rundll32\b.*javascript:",
           "Executes JavaScript payload via rundll32", "high", "T1218.011"),
        _r(fr"msiexec\b.*?/i\s+{_URL}",
           "Installs payload from remote MSI", "high", "T1218.007"),
        _r(r"certutil\b.*-decode",
           "Decodes file using certutil", "medium", "T1140", "T1218.001"),
        _r(r"\b(wscript|cscript)(?:\.exe)?\b.*\.(vbs|js|wsf)\b",
           "Executes script file via Windows Script Host", "medium", "T1059.005", "T1059.007"),
        # Python one-liner execution with suspicious primitives
        _r(r"python\S*\s+-c\s+.*(exec|eval|base64|subprocess|socket|os\.system)",
           "Python one-liner using code execution or network primitives", "medium", "T1059.006"),
        _r(r"python\S*\s+-c\s+.*socket\.connect",
           "Python reverse shell via socket connection", "high", "T1059.006", "T1095"),
        # Process injection patterns (memory allocation + write chains)
        _r(r"(VirtualAlloc|VirtualAllocEx).*WriteProcessMemory",
           "Memory allocation and write pattern consistent with process injection", "high", "T1055.002"),
        _r(r"\b(CreateRemoteThread|QueueUserAPC)\b",
           "Creates thread or queues APC in remote process (process injection)", "high", "T1055"),
        _r(r"(Invoke-ReflectivePEInjection|Invoke-Shellcode|Invoke-ProcessInjection)",
           "Invokes PowerShell process injection module", "high", "T1055"),
        _r(r"CreateProcess.*SUSPENDED|NtUnmapViewOfSection|ZwUnmapViewOfSection",
           "Process hollowing indicators: creates suspended process and unmaps memory", "high", "T1055.012"),
        # Additional LOLbins
        _r(r"\b(regsvcs|regasm)\b.*\.(?:dll|exe)",
           "Executes .NET assembly via regsvcs or regasm (LOLbin)", "high", "T1218.009"),
        # Bare binary name only; Follina (CVE-2022-30190) needs a specific
        # ms-msdt: payload to be a real exploit, so this is suggestive, not certain.
        _r(r"\bmsdt\b",
           "Invokes Microsoft Support Diagnostic Tool (potential CVE-2022-30190 / Follina)", "high", "T1203",
           precision=0.6),
        _r(r"\bforfiles\b.*?/c\b",
           "Uses forfiles /C to proxy-execute arbitrary commands (LOLBin, T1218)", "medium", "T1218"),
        _r(r"\bpcalua(?:\.exe)?\b",
           "Uses pcalua.exe to execute arbitrary binaries (UAC bypass / LOLBin)", "medium", "T1218"),
        _r(r"\bcmstp(?:\.exe)?\b",
           "Invokes cmstp.exe to load a scriptlet (AppLocker bypass, T1218.003)", "high", "T1218.003"),
        _r(r"\bodbcconf(?:\.exe)?\b.*?(/f\b|/a\b|regsvr)",
           "Uses odbcconf.exe to load a DLL or execute code via response file (T1218.008)", "high", "T1218.008"),
        _r(r"\bbash(?:\.exe)?\b.*?-c\b",
           "bash.exe -c on Windows: indirect command execution via WSL binary (LOLBin)", "medium", "T1202"),
        _r(r"\bwsl\b.*?(-e|--exec|bash|-u)",
           "Windows Subsystem for Linux used for indirect command execution", "medium", "T1202"),
        _r(r"\bpwsh\b",
           "PowerShell Core execution via pwsh (may bypass policies targeting powershell.exe)", "low", "T1059.001"),
    ]),

    # ── C2 / Persistence ──────────────────────────────────────────────────────
    _ClassDef("c2_persistence", "C2 / Persistence", [
        _r(r"schtasks\s+/create",
           "Creates scheduled task for persistence", "medium", "T1053.005"),
        _r(r"\bat(?:\.exe)?\s+\d{1,2}:\d{2}",
           "Uses legacy at.exe job scheduler to execute commands on a schedule (T1053.002)", "high", "T1053.002"),
        _r(r"reg\s+add.*\\(Run|RunOnce)\b",
           "Adds startup Run key for persistence", "high", "T1547.001"),
        _r(r"New-ScheduledTask",
           "Creates scheduled task via PowerShell", "high", "T1053.005"),
        _r(r"Set-ItemProperty.*CurrentVersion.*(Run|RunOnce)",
           "Adds Run key via PowerShell", "high", "T1547.001"),
        _r(r"sc\s+(create|config)\s+\S+.*binpath",
           "Creates or modifies Windows service binary path", "high", "T1543.003"),
        _r(r"New-Service\s",
           "Creates Windows service via PowerShell", "high", "T1543.003"),
        _r(r"netsh\s+interface\s+portproxy\s+add",
           "Creates port proxy tunnel for C2 traffic forwarding via netsh", "high", "T1090.001"),
        # WMI event subscription — fileless persistence (Wizard Spider, APT groups)
        _r(r"(__EventFilter|__EventConsumer|FilterToConsumerBinding)",
           "Creates WMI event subscription for fileless persistence", "high", "T1546.003"),
        _r(r"(Register-WmiEvent|Set-WmiInstance.*EventFilter|Set-WmiInstance.*EventConsumer)",
           "Registers WMI event handler for fileless persistence", "high", "T1546.003"),
        _r(r"(CommandLineEventConsumer|ActiveScriptEventConsumer)",
           "WMI event consumer bound to execute code on trigger", "high", "T1546.003"),
        # Registry-based persistence variants
        _r(r"reg\s+add.*\\(Winlogon).*(Notify|Shell|Userinit)",
           "Modifies Winlogon registry keys for logon persistence", "high", "T1547.004"),
        _r(r"reg\s+add.*ActiveSetup",
           "Abuses Active Setup registry key for per-user persistence", "medium", "T1547.001"),
        _r(r"reg\s+add.*Policies.*Scripts.*(Logon|Logoff|Startup|Shutdown)",
           "Sets Group Policy logon/startup script via registry", "high", "T1037.001"),
    ]),

    # ── Credential Theft ──────────────────────────────────────────────────────
    _ClassDef("credential_theft", "Credential Theft", [
        # A bare "lsass" mention is meaningless without a dump/access verb —
        # `Get-Process lsass` is a defender's own command. Needs corroboration.
        _r(r"\blsass\b",
           "References LSASS process (Windows credential store)", "medium", "T1003.001",
           corroborate=True),
        _r(r"\bmimikatz\b",
           "Mimikatz credential theft tool detected", "high", "T1003"),
        _r(r"\bsekurlsa\b",
           "Mimikatz sekurlsa module (dumps credentials from memory)", "high", "T1003.001"),
        _r(r"procdump\b.*lsass",
           "Dumps LSASS memory via ProcDump", "high", "T1003.001"),
        _r(r"comsvcs\b.*MiniDump",
           "Dumps process memory via comsvcs.dll MiniDump", "high", "T1003.001"),
        _r(r"reg\s+(save|export).*(\\SAM|\\SYSTEM|\\SECURITY)\b",
           "Exports credential hive from registry (SAM/SYSTEM/SECURITY)", "high", "T1003.002"),
        _r(r"\bntdsutil\b",
           "Accesses NTDS (Active Directory credential database)", "high", "T1003.003"),
        _r(r"vssadmin\s+create\s+shadow",
           "Creates shadow copy (precursor to NTDS/credential theft)", "medium", "T1003.003"),
        # Kerberos attacks (common in AD environments)
        _r(r"\brubeus\b",
           "Rubeus Kerberos attack framework detected", "high", "T1558.003", "T1550.003"),
        _r(r"sekurlsa::pth|/ntlm:.*\/run:|invoke.*pass.*the.*hash",
           "Pass-the-hash credential reuse — impersonates account using NTLM hash", "high", "T1550.002"),
        _r(r"(golden.ticket|silver.ticket|golden_ticket|silver_ticket|kerberos::golden|kerberos::silver)",
           "Kerberos ticket forgery (golden or silver ticket attack)", "high", "T1558.001"),
        _r(r"(Invoke-Kerberoast|kerberoast|Get-DomainUser.*-SPN.*-TGT)",
           "Kerberoasting — requests service tickets for offline hash cracking", "high", "T1558.003"),
        _r(r"\b(hashcat|john\s+.*\.(hash|txt|lst)|oclHashcat)\b",
           "Offline password / hash cracking tool detected", "medium", "T1110.002"),
        # Credential sniffing / forced auth
        _r(r"\b(responder|inveigh)\b",
           "LLMNR/NBT-NS poisoning tool — captures Net-NTLMv2 hashes on the wire", "high", "T1557.001"),
        _r(r"netsh\s+trace\s+start|tcpdump\b|tshark\b",
           "Network packet capture (potential credential or data sniffing)", "medium", "T1040"),
    ]),

    # ── Lateral Movement ──────────────────────────────────────────────────────
    _ClassDef("lateral_movement", "Lateral Movement", [
        _r(r"\bpsexec\b",
           "Uses PsExec for remote code execution", "high", "T1570", "T1021.002"),
        _r(r"wmic\s+/node:",
           "Executes command on remote host via WMIC", "high", "T1047"),
        _r(r"Invoke-Command.*-ComputerName",
           "Executes command on remote host via PowerShell remoting", "high", "T1021.006"),
        _r(r"\bwinrs\s+-r:",
           "Executes command on remote host via WinRS", "high", "T1021.006"),
        _r(r"Enter-PSSession\b",
           "Opens interactive remote PowerShell session", "medium", "T1021.006"),
        _r(r"net\s+use\s+\\\\[^/]+\\(admin|c|ipc)\$",
           "Accesses administrative network share", "medium", "T1021.002"),
        # RDP lateral movement
        _r(r"mstsc\b.*(/v:|/admin|/shadow)",
           "Initiates or shadows a Remote Desktop (RDP) session", "medium", "T1021.001"),
        _r(r"\b(xfreerdp|rdesktop)\b",
           "Remote Desktop connection via Linux/cross-platform RDP client", "medium", "T1021.001"),
        # SSH/SCP lateral movement — `ssh user@host` alone is routine developer
        # activity; only counts alongside a stronger lateral-movement signal.
        _r(r"\b(ssh|scp|sftp)\s+\S*@\S+",
           "SSH, SCP, or SFTP connection to remote host (potential lateral movement)", "medium", "T1021.004",
           corroborate=True),
        _r(r"\bplink\b.*(-pw|-i|-ssh|-P\s)",
           "PuTTY plink SSH/remote connection", "medium", "T1021.004"),
        # Remote service control (lateral movement via sc.exe over network)
        _r(r"sc\s+\\\\",
           "Remotely controls a Windows service via sc.exe (lateral movement)", "high", "T1021.002", "T1543.003"),
        # Pass-the-ticket and Kerberos delegation abuse
        _r(r"\bptt\b|kerberos.*import|rubeus.*asktgt|rubeus.*s4u",
           "Kerberos pass-the-ticket or delegation abuse (lateral movement)", "high", "T1550.003"),
    ]),

    # ── Defense Evasion ───────────────────────────────────────────────────────
    _ClassDef("defense_evasion", "Defense Evasion", [
        _r(r"\[Ref\].*AMSIUtils|amsi.*bypass|AmsiScanBuffer",
           "Patches AMSI in memory to bypass antivirus scanning", "high", "T1562.001"),
        _r(r"Set-MpPreference\s.*(DisableRealtimeMonitoring|DisableIOAV|False)",
           "Disables Windows Defender real-time protection", "high", "T1562.001"),
        _r(r"Add-MpPreference.*Exclusion(Path|Process|Extension)",
           "Adds Windows Defender exclusion", "high", "T1562.001"),
        _r(r"netsh\s+advfirewall.*disable",
           "Disables Windows Firewall via netsh", "high", "T1562.004"),
        # bcdedit safe-boot modification — handles bcdedit.exe via \b.*?
        _r(r"bcdedit\b.*?/set\b.*safeboot",
           "Modifies boot configuration for safe-mode execution (ransomware precursor)", "high", "T1490"),
        # Both -ExecutionPolicy and its common abbreviation -ep
        _r(r"(?:ExecutionPolicy|-[Ee][Pp])\s+(Bypass|Unrestricted)",
           "Bypasses PowerShell execution policy", "medium", "T1059.001"),
        _r(r"-[Ww]indow[Ss]tyle\s+[Hh]idden|-[Ww]\s+[Hh]idden",
           "Runs PowerShell with hidden window", "low", "T1564.003"),
        # Event log clearing — anti-forensics (T1562.008)
        _r(r"wevtutil\s+(cl|clear-log)\b",
           "Clears Windows event log to destroy forensic evidence", "high", "T1562.008"),
        _r(r"(Clear-EventLog|Remove-EventLog)\b",
           "Clears Windows event log via PowerShell", "high", "T1562.008"),
        # UAC bypass patterns
        _r(r"reg\s+add.*HKCU.*(?:ms-settings|mscfile|Progids).*shell.*open.*command",
           "Sets registry key for fodhelper/shell UAC bypass", "high", "T1548.002"),
        _r(r"\b(fodhelper|computerdefaults|sdclt|eventvwr)\b",
           "Invokes known UAC bypass binary", "medium", "T1548.002"),
        _r(r"powershell\b.*-Version\s+2\b",
           "Downgrades to PowerShell v2 to evade ScriptBlock logging", "medium", "T1548.002"),
        # Hidden file attribute
        _r(r"attrib\s+\+[Hh]\b",
           "Sets hidden attribute on file or directory", "low", "T1564.001"),
        # Disable tamper protection
        _r(r"(DisableTamperProtection|TamperProtection.*0)",
           "Disables Windows Defender Tamper Protection", "high", "T1562.001"),
        # Timestomping
        _r(r"\[IO\.File\]::Set(LastWrite|LastAccess|Creation)Time|Touch\s+-t\b",
           "Modifies file timestamps to evade forensic timeline analysis", "medium", "T1070.006"),
        # FromBase64String explicit .NET decode call
        _r(r"\[System\.Convert\]::FromBase64String|\[Convert\]::FromBase64String",
           "Decodes base64 payload via .NET Convert class (common in fileless PS loaders)", "high", "T1027.010"),
    ]),

    # ── Reconnaissance ────────────────────────────────────────────────────────
    _ClassDef("recon", "Reconnaissance", [
        _r(r"\b(ipconfig|ifconfig)\b",
           "Enumerates network configuration", "low", "T1016"),
        _r(r"\bnet\s+(user|group|localgroup)\b",
           "Enumerates local users/groups", "low", "T1069", "T1087"),
        _r(r"\bwhoami\b",
           "Checks current user context", "low", "T1033"),
        _r(r"\bsysteminfo\b",
           "Gathers system information", "low", "T1082"),
        _r(r"\btasklist\b",
           "Lists running processes", "low", "T1057"),
        _r(r"\bnltest\b",
           "Queries domain trust information via nltest", "medium", "T1482"),
        _r(r"Get-(LocalUser|LocalGroup|ADUser|ADGroupMember)",
           "Enumerates accounts via PowerShell", "low", "T1087"),
        _r(r"net\s+view\s+/domain",
           "Enumerates domain computers", "medium", "T1018"),
        # Network scanning
        _r(r"\b(nmap|masscan)\b",
           "Network port/service scanner detected (active host/service discovery)", "medium", "T1046"),
        # Network share enumeration
        _r(r"net\s+share\b",
           "Enumerates local or remote Windows network shares", "low", "T1135"),
        _r(r"Get-SmbShare\b|Get-NetShare\b",
           "Enumerates SMB/network shares via PowerShell", "low", "T1135"),
        # Active Directory enumeration
        _r(r"\b(dsquery|adfind|adexplorer|ldapsearch)\b",
           "Active Directory enumeration tool detected", "medium", "T1087.002"),
        _r(r"Get-ADComputer\b",
           "Enumerates Active Directory computer objects", "medium", "T1018"),
        _r(r"Get-(ADDomain|ADForest|ADDomainController)\b",
           "Enumerates Active Directory domain/forest structure", "medium", "T1482"),
        # Network state discovery
        _r(r"netstat\s+.*(-an|-ano|-a\b)",
           "Lists active network connections and listening ports", "low", "T1049"),
        _r(r"\barp\s+-[aA]\b",
           "Enumerates ARP table (local network host discovery)", "low", "T1016"),
    ]),

    # ── Ransomware / Impact ───────────────────────────────────────────────────
    _ClassDef("impact", "Ransomware / Impact", [
        # vssadmin delete/resize — handles vssadmin.exe via \b and .*
        _r(r"vssadmin\b.*(delete|resize)\b.*shadow",
           "Deletes or resizes VSS shadow copies (blocks restore points)", "high", "T1490"),
        # wbadmin delete/disable — handles wbadmin.exe via \b and .*
        _r(r"wbadmin\b.*(delete|disable)\b",
           "Deletes or disables Windows Backup catalog", "high", "T1490"),
        # bcdedit recoveryenabled — handles bcdedit.exe /set via \b.*?/set\b
        _r(r"bcdedit\b.*?/set\b.*recoveryenabled\s+no",
           "Disables Windows Recovery Environment via bcdedit", "high", "T1490"),
        # bcdedit bootstatuspolicy — same .exe-safe pattern
        _r(r"bcdedit\b.*?/set\b.*bootstatuspolicy\s+ignore",
           "Suppresses boot failure recovery prompts via bcdedit (ransomware pattern)", "high", "T1490"),
        # wmic shadowcopy delete — handles wmic.exe via \b and .*?
        _r(r"wmic\b.*?shadowcopy\b.*?delete\b",
           "Deletes shadow copies via WMIC (inhibits system recovery)", "high", "T1490"),
        _r(r"\bdiskshadow\b",
           "Invokes diskshadow for shadow copy management or deletion", "medium", "T1490"),
        _r(r"\bsdelete\b",
           "Secure file deletion via Sysinternals SDelete (data destruction)", "medium", "T1485"),
        # MBR/boot record destruction
        _r(r"dd\s+if=/dev/zero\s+of=/dev/(sd|hd)|bootrec\s+/fixmbr",
           "Overwrites MBR or boot record (potential disk wipe)", "high", "T1561.002"),
        # Disk/partition wipe
        _r(r"\bdiskpart\b.*(?:clean|format)",
           "Formats or wipes disk partitions via diskpart", "high", "T1561.002"),
    ]),

    # ── Data Staging / Exfiltration ───────────────────────────────────────────
    _ClassDef("data_staging", "Data Staging / Exfiltration", [
        # Archive creation (staging collected data for exfil)
        _r(r"\b(7z|7za|7zip)(?:\.exe)?\s+a\b",
           "Compresses files with 7-Zip (data staging for exfiltration)", "medium", "T1560", "T1560.001"),
        _r(r"\brar(?:\.exe)?\s+a\b",
           "Compresses files with WinRAR (data staging for exfiltration)", "medium", "T1560", "T1560.001"),
        _r(r"Compress-Archive\b",
           "Creates zip archive via PowerShell (data staging)", "low", "T1560"),
        _r(r"tar\s+.*-[czjJ]*f\b.*\.(tar|tgz|gz|bz2|xz)",
           "Creates compressed tar archive (data staging)", "low", "T1560"),
        # HTTP POST exfiltration
        _r(r"(Invoke-WebRequest|curl|wget)\b.*?(-Method\s+POST|--post-data|-d\s|-F\s)",
           "Uploads data via HTTP POST request (potential exfiltration)", "medium", "T1048", "T1041"),
        # Cloud storage exfiltration
        _r(r"\bazcopy\b",
           "Azure data transfer tool (potential cloud exfiltration)", "medium", "T1537"),
        _r(r"aws\s+s3\s+(cp|sync|mb)\b",
           "AWS S3 data transfer (potential cloud exfiltration)", "medium", "T1537"),
        _r(r"gsutil\s+(cp|rsync|mb)\b",
           "Google Cloud Storage transfer (potential exfiltration)", "medium", "T1537"),
        # DNS tunneling
        _r(r"\b(dnscat|iodine|dns2tcp)\b",
           "DNS tunneling tool detected (covert C2 or data exfiltration channel)", "high", "T1071.004", "T1048.001"),
        # Protocol tunneling
        _r(r"\b(ngrok|localtunnel|serveo)\b",
           "Reverse tunnel service used to expose internal service (C2 infrastructure)", "high", "T1572"),
        _r(r"ssh\b.*-[RL]\s+\d+:",
           "SSH port forwarding/tunneling (covert C2 or exfiltration channel)", "high", "T1572", "T1021.004"),
        _r(r"\bsocat\b",
           "socat network relay tool (reverse shell or tunneling)", "high", "T1095", "T1572"),
    ]),
]

_CONF_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# Severity weight per class — how damaging the behavior is *if the detection is
# true*. Consumed by scoring.compute_verdict(); kept here so weights live next to
# the rules they describe. Independent of per-rule confidence (= likelihood true).
_CLASS_WEIGHTS: dict[str, float] = {
    "impact": 1.8,            # ransomware / disk wipe / recovery destruction
    "credential_theft": 1.6,
    "loader": 1.5,
    "dropper": 1.4,
    "c2_persistence": 1.4,
    "lateral_movement": 1.3,
    "data_staging": 1.2,
    "defense_evasion": 1.2,
    "recon": 0.6,             # noisy, low-severity on its own
}
for _c in _CLASSES:
    _c.weight = _CLASS_WEIGHTS.get(_c.name, 1.0)

# Per-segment scan cap. Regex patterns here use nested `.*?` under DOTALL; on
# adversarial multi-KB input that is a catastrophic-backtracking (ReDoS) risk.
# Python's `re` has no timeout, so we bound the input each pattern sees instead.
_MAX_SCAN_CHARS = 100_000

# A pure help/version query (`ipconfig --help`, `curl -V`) shouldn't look
# suspicious. But a bare substring check is trivially bypassed by appending
# `--help` after a real payload, so we also require the absence of anything
# that makes a command *do* something: chaining/operators, a URL, or a long
# base64-ish blob. Suppression is still limited to low recon/defense_evasion.
_BENIGN_FLAGS = re.compile(r"\s(--help|-h\b|--version|-V\b|/\?|/help)\b", re.IGNORECASE)
_ACTIVE_TOKENS = re.compile(
    r"[;&|`\n]|\$\(|&&|\|\||://|[A-Za-z0-9+/]{40,}",
)
_BENIGN_SUPPRESSIBLE = frozenset({"recon", "defense_evasion"})


def _is_help_query(command: str) -> bool:
    return bool(_BENIGN_FLAGS.search(command)) and not _ACTIVE_TOKENS.search(command)


def classify(command: str, decoded_layers: list[dict[str, Any]]) -> list[ThreatClass]:
    """Return detected threat classes for a command and its decoded layers.

    Rules are matched per-segment (the command at depth 0, then each decoded
    layer at its own depth) rather than against one flattened blob. This stops
    a regex from spanning unrelated content across layers and lets us record
    the obfuscation depth at which each class first appears.
    """
    segments: list[tuple[int, str]] = [(0, command[:_MAX_SCAN_CHARS])]
    for layer in decoded_layers:
        depth = int(layer.get("layer", 1) or 1)
        segments.append((depth, str(layer.get("value", ""))[:_MAX_SCAN_CHARS]))

    is_help_query = _is_help_query(command)

    results: list[ThreatClass] = []
    for cls in _CLASSES:
        # Track core (non-corroborating) vs corroborating matches separately so a
        # class that only matched isolated single-token rules can be suppressed.
        core_signals: list[str] = []
        corrob_signals: list[str] = []
        matched_technique_ids: list[str] = []
        best_conf: Confidence = "low"
        max_depth = 0
        # (confidence, precision) for each matched core rule.
        core_matches: list[tuple[Confidence, float]] = []

        for rule in cls.rules:
            hit_depth: int | None = None
            for depth, text in segments:
                if rule.pattern.search(text):
                    hit_depth = depth if hit_depth is None else min(hit_depth, depth)
            if hit_depth is None:
                continue

            if rule.requires_corroboration:
                corrob_signals.append(rule.signal)
            else:
                core_signals.append(rule.signal)
                core_matches.append((rule.confidence, rule.precision))
            if _CONF_RANK[rule.confidence] > _CONF_RANK[best_conf]:
                best_conf = rule.confidence
            max_depth = max(max_depth, hit_depth)
            for tid in rule.technique_ids:
                if tid not in matched_technique_ids:
                    matched_technique_ids.append(tid)

        # A class backed only by corroboration-required rules is too weak to
        # surface on its own (e.g. bare "lsass", generic "curl <url>").
        if not core_signals:
            continue

        # Class precision = best precision among core rules that reached the
        # class's confidence tier (a strong tool-name match outranks a weak
        # heuristic that happened to hit the same tier).
        at_best = [p for c, p in core_matches if c == best_conf]
        class_precision = max(at_best) if at_best else max(p for _, p in core_matches)

        matched_signals = core_signals + corrob_signals

        # Suppress low-confidence informational hits when the command looks
        # like a help or version query (e.g. `ipconfig --help`, `curl -V`).
        if is_help_query and best_conf == "low" and cls.name in _BENIGN_SUPPRESSIBLE:
            continue
        results.append(ThreatClass(
            name=cls.name,
            label=cls.label,
            confidence=best_conf,
            signals=matched_signals,
            techniques=mitre.enrich(matched_technique_ids),
            max_depth=max_depth,
            precision=class_precision,
        ))

    return results
