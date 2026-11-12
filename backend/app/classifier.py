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
    # Every matched rule is one a legitimate installer one-liner also trips.
    installer_only: bool = False


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
    # True for the handful of download-and-run rules that a legitimate
    # installer one-liner (rustup, Chocolatey, …) also trips. See
    # known_installer(): the verdict is only softened when *every* matched
    # rule carries this flag.
    installer_ok: bool = False


def _r(
    pattern: str,
    signal: str,
    confidence: Confidence,
    *technique_ids: str,
    corroborate: bool = False,
    precision: float = 1.0,
    installer_ok: bool = False,
) -> _Rule:
    return _Rule(
        re.compile(pattern, re.IGNORECASE | re.DOTALL),
        signal,
        confidence,
        list(technique_ids),
        corroborate,
        precision,
        installer_ok,
    )


# User-writable / staging locations. A system binary pointed at one of these
# is the single most reliable context signal we have without tenant data.
_STAGING = (
    r"(?:\\Users\\Public\\|\\ProgramData\\|\\AppData\\|\\Windows\\Temp\\|\\Temp\\|\\Windows\\Tasks\\"
    r"|%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PUBLIC|PROGRAMDATA|ALLUSERSPROFILE)%"
    r"|\$env:(?:temp|tmp|appdata|localappdata|public|programdata)"
    r"|/tmp/|/dev/shm/|/var/tmp/)"
)
# Where a dropped *file* plausibly lives. Narrower than _STAGING on purpose:
# per-user apps (Slack, Teams, VS Code) and vendor tools (Chocolatey) install
# into AppData\Local\<Vendor>\… and ProgramData\<Vendor>\…, whereas implants
# sit in the root of those folders or anywhere under Temp / Public. So the
# roomy locations match at any depth and the shared ones only at depth one.
_DROP_DIR = (
    r"(?:(?:\\Users\\Public\\|\\Windows\\(?:Temp|Tasks)\\|\\AppData\\Local\\Temp\\|\\PerfLogs\\"
    r"|%(?:TEMP|TMP|PUBLIC)%\\|\$env:(?:temp|tmp|public)\\)(?:[^\\\s\"']+\\)*"
    r"|(?:\\ProgramData\\|\\AppData\\(?:Local|Roaming|LocalLow)\\|[A-Za-z]:\\Temp\\"
    r"|%(?:APPDATA|LOCALAPPDATA|PROGRAMDATA|ALLUSERSPROFILE)%\\|\$env:(?:appdata|localappdata|programdata)\\))"
)
_DROP_FILE = _DROP_DIR + r"[^\\\s\"']+(?=[\s\"']|$)"
# Interpreters a payload gets piped or handed to.
_SHELLS = r"(?:ba|z|da|k|a)?sh"


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
           "Downloads a string for in-memory execution (.DownloadString — IEX cradle)", "high", "T1105",
           installer_ok=True),
        # Invoke-WebRequest / iwr / .DownloadFile( is the standard PowerShell HTTP
        # client — routinely benign (downloading a PDF, an installer, an API
        # response). Only counts alongside a stronger dropper signal.
        _r(r"Invoke-WebRequest|\biwr\b|\.DownloadFile\s*\(",
           "Downloads a file via Invoke-WebRequest/WebClient", "medium", "T1105",
           corroborate=True, installer_ok=True),
        _r(r"certutil\b.*-urlcache",
           "Downloads file via certutil -urlcache (LOLbin)", "high", "T1105"),
        _r(fr"certutil\b.*-verifyctl\b.*{_URL}",
           "Downloads file via certutil -verifyctl (LOLbin)", "high", "T1105"),
        # Download straight into a staging directory, or download then mark
        # executable / run — the two halves of every commodity dropper.
        _r(r"\b(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b[^|;&]*?"
           r"(?:\s-o|\s-O|\s--output|\s--output-document|\s-OutFile)\s*=?\s*\"?\S*" + _STAGING,
           "Downloads a file into a temp/staging directory", "high", "T1105"),
        _r(r"\b(?:curl|wget)\b.*?(?:&&|;|\|\|?)\s*(?:sudo\s+)?chmod\s+(?:\+x|a\+x|u\+x|[0-7]*[157][0-7]{2})\b",
           "Downloads a file and marks it executable", "high", "T1105", "T1222.002",
           precision=0.45),
        # …but not over plain HTTP or from a bare IP address.
        _r(r"\b(?:curl|wget)\b[^|]*?(?:http://|h(?:xx|tt)ps://(?:\d{1,3}\.){3}\d{1,3})\S*.*?(?:&&|;|\|\|?)\s*(?:sudo\s+)?chmod\s+(?:\+x|a\+x|u\+x|[0-7]*[157][0-7]{2})\b",
           "Downloads a file over plain HTTP or from a bare IP address and marks it executable",
           "high", "T1105", "T1222.002"),
        _r(r"\bfinger(?:\.exe)?\b[^|]*\|\s*(?:cmd|powershell|" + _SHELLS + r")\b",
           "Pipes finger.exe output into a shell (LOLBin payload delivery)", "high", "T1105"),
        _r(r"\b(?:expand|extrac32|esentutl|replace|xcopy|copy|print|findstr|makecab)(?:\.exe)?\b[^|;&]*\\\\[^\\\s]+@(?:SSL|\d+)\\",
           "Copies a file from a WebDAV share (LOLBin download)", "high", "T1105"),
        _r(r"\bbitsadmin\b.*?/addfile\b.*?" + _URL,
           "Queues a remote file download in a BITS job", "high", "T1197", "T1105"),
        _r(r"\bftp(?:\.exe)?\b[^|&;]*\s-s:\S+",
           "Runs a scripted FTP session (classic download-and-execute dropper)", "high", "T1105",
           precision=0.7),
        _r(r"\b(?:rundll32|regsvr32|mshta|wscript|cscript|msiexec|installutil|msbuild|regasm|regsvcs|odbcconf|cmstp|powershell|pwsh|cmd)"
           r"(?:\.exe)?\b[^|&;]*?\\\\(?:\d{1,3}\.){3}\d{1,3}(?:@(?:SSL|\d+))?\\",
           "Loads a payload from a remote share addressed by IP (SMB/WebDAV delivery)", "high", "T1105", "T1218",
           precision=0.9),
        _r(r"\bdesktopimgdownldr\b|\bCertReq(?:\.exe)?\b.*-Post\b|\bMpCmdRun(?:\.exe)?\b.*-DownloadFile\b"
           r"|\bIMEWDBLD(?:\.exe)?\b.*" + _URL + r"|\bAppInstaller(?:\.exe)?\b.*" + _URL,
           "Downloads a file via a rarely-used signed Windows binary (LOLBin)", "high", "T1105"),
        _r(r"bitsadmin\s+/transfer",
           "Downloads file via BITS job", "high", "T1197"),
        _r(r"Start-BitsTransfer\b",
           "Downloads file via BITS using PowerShell Start-BitsTransfer", "high", "T1197"),
        _r(fr"mshta\b.*{_URL}",
           "Executes remote HTA payload via mshta", "high", "T1218.005"),
        # Pipe-to-shell: curl/wget output piped directly into an interpreter (including PowerShell IEX)
        _r(r"\b(wget|curl)\b.*?\|.*?\b(bash|sh|python3?|perl|ruby|iex|powershell(?:\.exe)?)\b",
           "Downloads and pipes content directly to a shell interpreter", "high", "T1059.004", "T1105",
           installer_ok=True),
        _r(r"\b(?:" + _SHELLS + r"|python3?|perl)\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b",
           "Executes downloaded content via process/command substitution", "high", "T1059.004", "T1105",
           installer_ok=True),
        # Any HTTP client pulling a raw executable/script payload from a URL is a
        # strong standalone dropper signal (and corroborates the IWR rule above).
        _r(r"(?:\b(?:wget|curl|iwr|Invoke-WebRequest|DownloadFile|DownloadData|DownloadString)\b|Net\.WebClient).*?"
           r"(?:hxxps?://|http://|https://(?:\d{1,3}\.){3}\d{1,3})\S*\.(?:exe|ps1|bat|vbs|hta|sh|py|rb|pl|dll|scr|msi|jar)\b",
           "Downloads an executable or script payload over plain HTTP or from a bare IP address", "high", "T1105",
           installer_ok=True),
        _r(r"(?:\b(?:wget|curl|iwr|Invoke-WebRequest|DownloadFile|DownloadData|DownloadString)\b|Net\.WebClient).*?"
           r"https://(?!(?:\d{1,3}\.){3}\d{1,3})\S*\.(?:exe|ps1|bat|vbs|hta|sh|py|rb|pl|dll|scr)\b",
           "Downloads an executable or script payload over HTTPS", "high", "T1105",
           installer_ok=True, precision=0.45),
        # curl/wget fetching any URL — only counts alongside a stronger dropper
        # signal (pipe-to-shell, malicious extension). Alone it is just a download.
        _r(fr"\b(curl|wget)\b.*?{_URL}",
           "Fetches remote content via curl or wget", "low", "T1105", corroborate=True,
           installer_ok=True),
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
           "Executes string as code via Invoke-Expression", "high", "T1059.001",
           installer_ok=True),
        # Call/dot operator on a quoted or rebuilt "iex" — the form left behind
        # once string-splitting and variable-index tricks are resolved.
        _r(r"[.&]\s*\(?\s*['\"](?:iex|invoke-expression)['\"]\s*\)?",
           "Invokes Invoke-Expression through the call operator (name hidden from string matching)",
           "high", "T1059.001", "T1027"),
        # A signed proxy-execution binary pointed at a user-writable directory.
        _r(r"\b(?:rundll32|regsvr32|msbuild|installutil|mshta|wscript|cscript|regasm|regsvcs|odbcconf|cmstp|ieexec|presentationhost|msxsl|cdb|dnx|rcsi|csi|vbc|csc|jsc|bginfo|verclsid|infdefaultinstall|pcalua|forfiles|conhost)"
           r"(?:\.exe)?\b[^|&;]*?" + _DROP_FILE,
           "Signed Windows binary executing content from a user-writable staging directory",
           "high", "T1218", precision=0.9),
        _r(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^|&;]*?-f(?:ile)?\s+[\"']?\S*?" + _DROP_DIR + r"[^\\\s\"']+\.ps1\b",
           "Runs a PowerShell script file out of a temp/staging directory", "high", "T1059.001",
           precision=0.9),
        _r(r"(?:\bStart-Process\b|\bsaps\b|\bInvoke-Item\b|\bstart\b(?:\s+/\w+)*|\bcmd(?:\.exe)?\s+/c|&|\bcall\b|\bexplorer(?:\.exe)?)\s+(?:-FilePath\s+)?[\"']?\S*?"
           + _DROP_DIR + r"[^\\\s\"']+\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|scr|com|lnk|pif)\b"
           r"|(?:^|[;&|]\s*)[\"']?(?:[A-Za-z]:)?\S*?" + _DROP_DIR + r"[^\\\s\"']+\.(?:exe|bat|cmd|scr|com|pif)\b"
           # Linux: a file sitting directly in /tmp, or anything hidden under it.
           r"|(?:^|[;&|]\s*)(?:nohup\s+|sudo\s+)?(?:/tmp/|/dev/shm/|/var/tmp/)(?:[^/\s]+|\S*/\.\S+|\.\S+)(?:\s|$)",
           "Runs a program directly out of a temp/staging directory", "high", "T1204.002",
           precision=0.7),
        _r(r"\binstallutil(?:\.exe)?\b.*?(?:/u\b|/logfile=\s|/logtoconsole=false)",
           "Runs a .NET assembly's uninstaller via InstallUtil (application-control bypass)",
           "high", "T1218.004"),
        _r(r"\brundll32(?:\.exe)?\b.*?\b(?:url(?:\.dll)?,\s*(?:OpenURL|FileProtocolHandler)|ieframe(?:\.dll)?,\s*OpenURL"
           r"|shdocvw(?:\.dll)?,\s*OpenURL|pcwutl(?:\.dll)?,\s*LaunchApplication|zipfldr(?:\.dll)?,\s*RouteTheCall"
           r"|advpack(?:\.dll)?,\s*(?:LaunchINFSection|RegisterOCX)|ieadvpack(?:\.dll)?,\s*(?:LaunchINFSection|RegisterOCX)"
           r"|syssetup(?:\.dll)?,\s*SetupInfObjectInstallAction|setupapi(?:\.dll)?,\s*InstallHinfSection"
           r"|mshtml(?:\.dll)?,\s*(?:PrintHTML|RunHTMLApplication)|dfshim(?:\.dll)?,\s*ShOpenVerbApplication"
           r"|shell32(?:\.dll)?,\s*(?:ShellExec_RunDLL|Control_RunDLL\s+\S*[\\/]))",
           "Proxy-executes a payload through a rundll32 export known for abuse", "high", "T1218.011"),
        _r(r"\brundll32(?:\.exe)?\b[^|&;]*?[,\s]#\+?\d+\b",
           "Calls a DLL export by ordinal via rundll32 (hides the function name)", "medium", "T1218.011"),
        _r(fr"\bwmic(?:\.exe)?\b.*?/format:\s*[\"']?(?:{_URL}|\S+\.xsl\b)",
           "Executes a remote/attacker XSL stylesheet via wmic /format (Squiblytwo)", "high", "T1220"),
        _r(r"\bwmic(?:\.exe)?\b.*?process\s+call\s+create\b"
           r"|\bInvoke-(?:Wmi|Cim)Method\b.*?Win32_Process.*?\bCreate\b|\[wmiclass\].*?Win32_Process.*?\.Create\s*\(",
           "Spawns a process through WMI (breaks the parent-child process chain)", "medium", "T1047"),
        _r(r"\bbase64\s+-(?:d|D|-decode)\b[^|]*\|\s*(?:sudo\s+)?(?:" + _SHELLS + r"|python3?|perl)\b",
           "Decodes base64 and pipes the result straight into an interpreter", "high", "T1027", "T1059.004"),
        _r(r"\beval\s+[\"']?\$\(\s*(?:curl|wget|echo\b[^)]*\|\s*base64|base64)\b",
           "Evaluates downloaded or decoded content in the current shell", "high", "T1059.004", "T1027"),
        _r(r"python\S*\s+-c\s+.*exec\s*\(.*(?:b64decode|decompress|fromhex|urlopen|requests\.get)",
           "Python one-liner executing decoded or downloaded code", "high", "T1059.006", "T1027"),
        _r(r"\bmshta(?:\.exe)?\b.*?vbscript:",
           "Executes inline VBScript payload via mshta", "high", "T1218.005"),
        _r(r"\b(?:msxsl|ieexec|presentationhost|squirrel|update)(?:\.exe)?\b.*?" + _URL,
           "Signed binary fetching and executing remote content (LOLBin)", "high", "T1218", precision=0.8),
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
           "Decodes file using certutil", "medium", "T1140"),
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
        _r(r"\bbash\.exe\b.*?-c\b",
           "bash.exe -c on Windows: indirect command execution via WSL binary (LOLBin)", "medium", "T1202"),
        _r(r"\bwsl\b.*?(-e|--exec|bash|-u)",
           "Windows Subsystem for Linux used for indirect command execution", "medium", "T1202"),
        _r(r"\bpwsh\b",
           "PowerShell Core execution via pwsh (may bypass policies targeting powershell.exe)", "low", "T1059.001"),
        # Fileless .NET loaders — the canonical Cobalt Strike / Empire / Sliver
        # pattern of pushing assembly bytes into the current process and
        # invoking a method, never touching disk.
        _r(r"\[(?:System\.)?Reflection\.Assembly\]::Load\s*\(",
           "Loads .NET assembly via Reflection.Assembly.Load (fileless loader)", "high", "T1620", "T1059.001"),
        _r(r"\[(?:System\.)?AppDomain\]::CurrentDomain\.Load\s*\(",
           "Loads .NET assembly into the current AppDomain (fileless loader)", "high", "T1620"),
        # Inline C# compilation — used to drop shellcode runners (e.g.
        # P/Invoke wrappers calling VirtualAlloc/CreateRemoteThread).
        _r(r"\bAdd-Type\s+(?:-TypeDefinition|-Path|-LiteralPath|@'|@\")",
           "Compiles inline .NET source via Add-Type (commonly a shellcode runner)", "high", "T1059.001"),
        # Call operator invoking a constructed function name — defeats simple
        # string-match detection of IEX/Invoke-Expression by splitting the name.
        _r(r"&\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*['\"]",
           "Call operator invoking a concatenated function name (string-split execution)", "medium", "T1027"),
        # Additional LOLBins
        _r(r"\bmavinject(?:\.exe)?\b",
           "Injects DLL into a running process via mavinject.exe (LOLBin)", "high", "T1055.001"),
        _r(r"\bhh(?:\.exe)?\b.*\.chm\b",
           "Opens CHM help file for code execution via hh.exe (LOLBin)", "high", "T1218.001"),
        # `control ncpa.cpl` opens a built-in applet; only a .cpl given by path
        # (i.e. not one of the system's own) is the T1218.002 abuse pattern.
        _r(r"\bcontrol(?:\.exe)?\s+\"?\S*[\\/]\S*\.cpl\b",
           "Loads a Control Panel applet (.cpl) from an explicit path via control.exe (LOLBin)",
           "high", "T1218.002", precision=0.8),
        _r(r"\bxwizard(?:\.exe)?\b",
           "Proxy-executes arbitrary code via xwizard.exe (LOLBin)", "medium", "T1218"),
        _r(r"\bappcmd(?:\.exe)?\b",
           "Abuses IIS appcmd.exe for config manipulation or code execution (LOLBin)", "medium", "T1218"),
    ]),

    # ── C2 / Persistence ──────────────────────────────────────────────────────
    _ClassDef("c2_persistence", "C2 / Persistence", [
        _r(r"schtasks\s+/create",
           "Creates scheduled task for persistence", "medium", "T1053.005"),
        # Command position only — "meet at 10:30" is not a scheduled job.
        _r(r"(?:^|[;&|(]\s*|\bcmd(?:\.exe)?\s+/c\s+\"?)at(?:\.exe)?\s+(?:\\\\\S+\s+)?\d{1,2}:\d{2}",
           "Uses legacy at.exe job scheduler to execute commands on a schedule (T1053.002)", "high", "T1053.002"),
        _r(r"schtasks\b.*?/create\b.*?(?:/ru\s+\"?(?:SYSTEM|NT AUTHORITY)|" + _STAGING
           + r"|\b(?:powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)\b|\bcmd(?:\.exe)?\s+/c\b|" + _URL + r")",
           "Creates a scheduled task that runs as SYSTEM, from a staging path, or launches an interpreter",
           "high", "T1053.005"),
        # ── Reverse shells / interactive C2 ─────────────────────────────────
        _r(r"/dev/(?:tcp|udp)/[^/\s]+/\d+",
           "Opens a network socket through bash /dev/tcp (reverse shell / C2 channel)", "high", "T1059.004", "T1095"),
        _r(r"\b(?:nc|ncat|netcat)(?:\.exe)?\b[^|;&]*?\s(?:-\w*[ec]\b|--exec\b|--sh-exec\b)\s*\S*(?:sh|cmd(?:\.exe)?|powershell(?:\.exe)?)\b",
           "Netcat bound to a shell (reverse or bind shell)", "high", "T1059", "T1095"),
        _r(r"\b(?:mkfifo|mknod)\b.*?\b(?:nc|ncat|netcat|telnet|openssl)\b|\b(?:nc|ncat|netcat)\b[^|;&]*\|\s*(?:/bin/)?" + _SHELLS + r"\b",
           "Named-pipe (mkfifo) reverse shell", "high", "T1059.004", "T1095"),
        _r(r"\bsocat\b.*?\bexec:|\bopenssl\s+s_client\b.*?\|\s*(?:/bin/)?" + _SHELLS + r"\b",
           "Shell bound to a socat / openssl network stream", "high", "T1059.004", "T1573"),
        _r(r"\bpython\S*\s+-c\s+.*socket.*(?:\.connect|dup2|pty\.spawn|subprocess)"
           r"|\bperl\b.*?-e\b.*?(?:socket|IO::Socket).*?(?:exec|/bin/(?:ba)?sh|STDIN)"
           r"|\bruby\b.*?-rsocket\b|\bphp\b.*?-r\b.*?fsockopen|\blua\b.*?socket\.tcp|\bawk\b.*?/inet/tcp/",
           "Scripting-language reverse shell one-liner", "high", "T1059", "T1095"),
        _r(r"\bpty\.spawn\s*\(|\bscript\s+(?:-qc|/dev/null\s+-c)\s+(?:/bin/)?" + _SHELLS + r"\b|\bstty\s+raw\s+-echo\b",
           "Upgrades a dumb shell to an interactive TTY (post-exploitation)", "medium", "T1059.004"),
        # ── Account creation / manipulation ─────────────────────────────────
        _r(r"\bnet1?(?:\.exe)?\s+user\s+(?!/)\S+(?:\s+\S+)?\s+.*?/add\b",
           "Creates a local or domain user account", "high", "T1136.001", precision=0.7),
        _r(r"\bnet1?(?:\.exe)?\s+user\s+(?:administrator|guest|defaultaccount)\b.*?/active:yes\b",
           "Re-enables a built-in account (Administrator / Guest)", "high", "T1078.003", precision=0.7),
        _r(r"\bnet1?(?:\.exe)?\s+(?:localgroup|group)\s+\"?(?:administrators|remote desktop users|domain admins|enterprise admins|backup operators)\"?\s+.*?/add\b",
           "Adds an account to a privileged group", "high", "T1098"),
        _r(r"\bNew-LocalUser\b",
           "Creates a local user account via PowerShell", "high", "T1136.001", precision=0.7),
        _r(r"\bAdd-LocalGroupMember\b.*?Administrators|\bAdd-ADGroupMember\b.*?(?:Domain|Enterprise)\s+Admins",
           "Grants an account administrator membership via PowerShell", "high", "T1098"),
        _r(r"\buseradd\b.*?(?:-o\b.*?-u\s*0\b|-u\s*0\b|-g\s*0\b)|:0:0:[^>]*>>\s*/etc/passwd",
           "Creates a Linux account with UID 0 (a second root)", "high", "T1136.001", "T1098"),
        _r(r"\b(?:useradd|usermod)\b.*?-a?G\s*\S*(?:sudo|wheel|root)\b",
           "Adds a Linux account to the sudo/wheel group", "medium", "T1098"),
        # ── Linux / macOS persistence ───────────────────────────────────────
        _r(r"\|\s*crontab\s+-(?:\s|$)|>>?\s*/etc/cron\S*|>>?\s*/var/spool/cron\S*|\bcrontab\s+(?!-[lr]\b)\S+\.\S+",
           "Installs a cron job (scheduled persistence)", "medium", "T1053.003"),
        _r(r"(?=.*(?:\|\s*crontab\s+-(?:\s|$)|>>?\s*/etc/cron|>>?\s*/var/spool/cron))"
           r"(?=.*(?:\b(?:curl|wget|base64|nc|ncat)\b|/tmp/|/dev/shm/|/var/tmp/|/dev/tcp/|\s/\S*/\.\w))",
           "Installs a cron job that downloads content or runs from a temp/hidden path", "high", "T1053.003"),
        _r(r">>?\s*\S*\.ssh/authorized_keys\b",
           "Appends a key to authorized_keys (SSH backdoor access)", "high", "T1098.004", precision=0.7),
        _r(r">>?\s*\S*(?:\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|/etc/profile(?:\.d/\S+)?|/etc/rc\.local|/etc/bash\.bashrc)\b",
           "Writes to a shell startup file (logon persistence)", "medium", "T1546.004"),
        _r(r">\s*/(?:etc|lib|usr/lib)/systemd/system/\S+\.(?:service|timer)\b|>\s*\S*/Library/Launch(?:Agents|Daemons)/\S+\.plist\b|\blaunchctl\s+load\b",
           "Creates a systemd unit or launchd job (service persistence)", "medium", "T1543.002", "T1543.001"),
        _r(r">>?\s*/etc/ld\.so\.preload\b",
           "Writes /etc/ld.so.preload (injects a library into every process)", "high", "T1574.006"),
        # ── Windows persistence beyond Run keys ─────────────────────────────
        _r(r"reg\s+add.*Image File Execution Options.*(?:Debugger|GlobalFlag)|reg\s+add.*SilentProcessExit",
           "Sets an Image File Execution Options debugger (accessibility-feature / IFEO backdoor)", "high", "T1546.012"),
        _r(r"(?:\b(?:copy|move|xcopy|Copy-Item|Move-Item|Out-File)\b|>).*\\Start Menu\\Programs\\Startup\\",
           "Places a file in the Startup folder", "medium", "T1547.001"),
        _r(r"\bbitsadmin\b.*?/SetNotifyCmdLine\b",
           "Sets a BITS job notify command (runs a program when the transfer completes)", "high", "T1197"),
        _r(r"\b(?:copy|move|xcopy|Copy-Item|Move-Item|takeown|ren|rename)\b.*\\(?:sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe\b",
           "Replaces an accessibility binary (sticky-keys style logon backdoor)", "high", "T1546.008"),
        _r(r"(?:Set|New)-ItemProperty\b.*Winlogon.*(?:Userinit|Shell|Notify)\b",
           "Modifies Winlogon Userinit/Shell via PowerShell for logon persistence", "high", "T1547.004"),
        _r(r"New-ItemProperty\b.*CurrentVersion\\(?:Run|RunOnce)\b",
           "Adds Run key via PowerShell New-ItemProperty", "high", "T1547.001"),
        _r(r"reg\s+add.*\\(?:Lsa)\\?.*(?:Security Packages|Notification Packages|Authentication Packages)"
           r"|reg\s+add.*\\AppInit_DLLs|reg\s+add.*\\AppCertDlls|reg\s+add.*\\Print\\Monitors\\",
           "Registers a DLL in an auto-load registry location (LSA / AppInit / port monitor)", "high", "T1547"),
        # ── Remote-access software dropped quietly ──────────────────────────
        _r(r"\b(?:anydesk|screenconnect|connectwise\w*|atera\w*|splashtop\w*|teamviewer\w*|rustdesk|meshagent|tacticalrmm|netsupport|client32|supremo|action1\w*|simplehelp|fleetdeck|level\w*agent)(?:\.(?:exe|msi))?\b"
           r".*?(?:--silent|/silent|/verysilent|\s/s\b|/qn\b|/quiet\b|--install\b|--start-with-win|--set-password|-fullinstall)",
           "Silently installs remote-access software (frequent hands-on-keyboard intrusion tool)",
           "high", "T1219", precision=0.6),
        _r(r"reg\s+add.*\\(Run|RunOnce)\b",
           "Adds startup Run key for persistence", "high", "T1547.001"),
        _r(r"New-ScheduledTask",
           "Creates scheduled task via PowerShell", "high", "T1053.005"),
        _r(r"Set-ItemProperty.*CurrentVersion.*(Run|RunOnce)",
           "Adds Run key via PowerShell", "high", "T1547.001"),
        _r(r"sc\s+(?:\\\\\S+\s+)?(create|config)\s+\S+.*binpath",
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
        # Named pipe — used by Cobalt Strike, Meterpreter, and other C2 frameworks
        # for inter-process communication. Alone it is suggestive (IPC has benign
        # uses); needs corroboration from another C2 signal to be conclusive.
        _r(r"NamedPipeClient(?:Stream)?|NamedPipeServer(?:Stream)?|\.OpenNamedPipe\b",
           "Uses named pipes for IPC (common C2 channel pattern)", "medium", "T1559.001",
           corroborate=True, precision=0.7),
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
        _r(r"comsvcs\b.*(?:MiniDump|#\+?0*24\b)",
           "Dumps process memory via comsvcs.dll MiniDump", "high", "T1003.001"),
        _r(r"\blsass\b.*\.dmp\b|\.dmp\b.*\blsass\b|\bMiniDumpWriteDump\b|\bOut-Minidump\b",
           "Writes an LSASS / process memory dump", "high", "T1003.001"),
        _r(r"\b(?:nanodump|dumpert|handlekatz|safetykatz|sharpkatz|pypykatz|lsassy|lazagne|sharpdpapi|donpapi|sharpchrome|sharpweb|mimipenguin|laZagne)\b",
           "Known credential-dumping tool", "high", "T1003"),
        _r(r"\bntds\.dit\b",
           "Touches ntds.dit, the Active Directory credential database", "high", "T1003.003"),
        _r(r"HarddiskVolumeShadowCopy\d*\\+.*?(?:\\config\\(?:SAM|SYSTEM|SECURITY)|ntds)\b",
           "Copies credential stores out of a volume shadow copy", "high", "T1003.002", "T1003.003"),
        _r(r"\besentutl(?:\.exe)?\b.*?(?:/vss\b|\\config\\sam\b)",
           "Copies a locked credential store with esentutl", "high", "T1003.003"),
        _r(r"\b(?:impacket-)?(?:secretsdump|GetUserSPNs|GetNPUsers|ntlmrelayx|ticketer|getTGT|getST|dpapi|samrdump)(?:\.py)?\b",
           "Impacket credential-access script", "high", "T1003", "T1558"),
        _r(r"\b(?:nxc|netexec|crackmapexec|cme)\b.*?(?:--sam\b|--lsa\b|--ntds\b|--dpapi\b|--laps\b|-M\s+(?:lsassy|nanodump|handlekatz|mimikatz))",
           "NetExec / CrackMapExec credential dumping", "high", "T1003"),
        _r(r"(?:^|\s)-H\s+['\"]?(?:[a-f0-9]{32}:)?[a-f0-9]{32}\b|\s-hashes\s+\S*:[a-f0-9]{32}\b|/pth:[a-f0-9]{32}\b",
           "Authenticates with an NTLM hash instead of a password (pass-the-hash)", "high", "T1550.002"),
        _r(r"\b(?:cat|less|more|head|tail|cp|scp|tar|base64|xxd|strings|grep|awk|sed|unshadow|vi|vim|nano|curl|nc)\b[^|;&]*\s/etc/(?:shadow|gshadow|security/opasswd|master\.passwd)\b",
           "Reads the local password-hash file (/etc/shadow)", "high", "T1003.008"),
        _r(r"\b(?:cat|cp|scp|tar|zip|curl|base64|type|copy|Get-Content|gc)\b[^|;&]*"
           r"(?:\.ssh[\\/]id_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.aws[\\/]credentials\b|\.kube[\\/]config\b|\.docker[\\/]config\.json\b|\.git-credentials\b|\.netrc\b|\.azure[\\/]accessTokens)",
           "Reads private keys or cloud credential files", "medium", "T1552.004", "T1552.001"),
        _r(r"\bosascript\b.*display\s+dialog\b.*(?:password|hidden\s+answer)",
           "Fake macOS password prompt via osascript (credential phishing)", "high", "T1056.002"),
        _r(r"\bsecurity\s+(?:dump-keychain\b|find-(?:generic|internet)-password\b.*\s-\w*[gw])|\bchainbreaker\b",
           "Dumps passwords from the macOS keychain", "high", "T1555.001"),
        _r(r"/(?:var/)?run/secrets/kubernetes\.io/serviceaccount/token\b",
           "Reads the Kubernetes service-account token", "medium", "T1552.007"),
        _r(r"\b(?:Get-ChildItem|gci|dir|ls)\b.*-Recurse\b.*-Include\b.*(?:\.kdbx|\.pfx|id_rsa|\.ppk|\.pem\b|\.ovpn|\.rdp\b|wallet|passw)"
           r"|\bfind\b[^|;&]*-i?name\s+[\"']?\S*(?:id_rsa|\.kdbx|\.ppk|\.pfx|wallet\.dat|\.ovpn|credentials)",
           "Hunts the filesystem for key files, password vaults, or wallets", "medium", "T1552.004", "T1552.001"),
        _r(r"169\.254\.169\.254/(?:latest/meta-data/iam|metadata/identity|computeMetadata/v1/instance/service-accounts)",
           "Requests cloud instance-metadata credentials", "high", "T1552.005"),
        _r(r"\b(?:copy|cp|xcopy|robocopy|Copy-Item|type|cat|Get-Content)\b.*(?:\\Login Data\b|\blogins\.json\b|\bkey4\.db\b|\\Local State\b|\\Network\\Cookies\b)",
           "Copies browser credential or cookie stores", "high", "T1555.003", precision=0.8),
        _r(r"reg\s+add.*WDigest.*UseLogonCredential.*\b1\b",
           "Re-enables WDigest so plaintext passwords are kept in LSASS", "high", "T1112", "T1003.001"),
        _r(r"\bfindstr\b.*?/s\w*\b.*?\b(?:password|cpassword|passwd)\b|\bdir\b.*?/s\b.*?\*pass\*|\bGet-ChildItem\b.*?-Recurse\b.*?\*pass",
           "Searches the filesystem for stored passwords", "medium", "T1552.001"),
        _r(r"\bgrep\s+(?:-\S+\s+)*-\w*[rR]\w*\b.*\b(?:password|passwd|secret|api[_-]?key|aws_secret)\b",
           "Recursively greps files for passwords or secrets", "medium", "T1552.001", precision=0.6),
        _r(r"\bvaultcmd\b.*/listcreds|\bcmdkey\b\s+/list\b|\breg\s+query\b.*(?:DefaultPassword|PuTTY\\Sessions|RealVNC|TightVNC)",
           "Enumerates stored credentials (Credential Manager / registry)", "medium", "T1555.004", "T1552.002"),
        _r(r"\b(?:certify|certipy)(?:\.exe|\.py)?\b.*?\b(?:find|request|req|auth|shadow|forge)\b",
           "AD Certificate Services abuse tool (Certify / Certipy)", "high", "T1649"),
        _r(r"\bkerbrute\b|\bhydra\b.*?-[lLpP]\b|\bmedusa\b.*?-[hH]\b|\bInvoke-DomainPasswordSpray\b|\bDomainPasswordSpray\b|\bspray\w*\.(?:ps1|py)\b",
           "Password spraying / brute-force tool", "high", "T1110.003"),
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
        _r(r"kerberos::ptt|/ptt\b|kerberos.*import|rubeus.*asktgt|rubeus.*s4u",
           "Kerberos pass-the-ticket or delegation abuse (lateral movement)", "high", "T1550.003"),
        _r(r"\b(?:impacket-)?(?:wmiexec|smbexec|atexec|dcomexec|psexec)\.py\b|\bimpacket-(?:wmiexec|smbexec|atexec|dcomexec|psexec)\b",
           "Impacket remote-execution script", "high", "T1021.002", "T1047"),
        _r(r"\b(?:nxc|netexec|crackmapexec|cme)\s+(?:smb|winrm|ldap|mssql|ssh|rdp|wmi|ftp|vnc)\b",
           "NetExec / CrackMapExec sweep against remote hosts", "high", "T1021"),
        _r(r"\bevil-winrm\b|\bInvoke-(?:SMBExec|WMIExec|PsExec|TheHash|DCOM|SSHCommand)\b|\bSharpRDP\b|\bSharpWMI\b|\bSCShell\b",
           "Remote-execution offensive tool", "high", "T1021"),
        _r(r"\bInvoke-(?:Wmi|Cim)Method\b.*?-ComputerName\b|\bNew-CimSession\b.*?-ComputerName\b.*?Invoke-CimMethod",
           "Executes a process on a remote host through WMI", "high", "T1047"),
        _r(r"\bschtasks\b.*?/create\b.*?\s/s\s+\S+",
           "Creates a scheduled task on a remote host", "high", "T1053.005"),
        _r(r"\b(?:copy|xcopy|robocopy|move|Copy-Item)\b.*?\\\\[^\\\s]+\\(?:admin|c|ipc)\$",
           "Copies a file to a remote administrative share (tool transfer)", "high", "T1570", "T1021.002"),
        _r(r"reg\s+add.*fDenyTSConnections.*\b0\b|reg\s+add.*LocalAccountTokenFilterPolicy.*\b1\b|reg\s+add.*DisableRestrictedAdmin.*\b0\b"
           r"|netsh\s+advfirewall\s+firewall\s+(?:add|set)\s+rule.*(?:remote desktop|3389)",
           "Enables remote logon paths (RDP / remote-UAC / restricted-admin) via registry or firewall", "medium", "T1021.001", "T1112"),
    ]),

    # ── Defense Evasion ───────────────────────────────────────────────────────
    _ClassDef("defense_evasion", "Defense Evasion", [
        _r(r"\[Ref\].*AMSIUtils|amsi.*bypass|AmsiScanBuffer",
           "Patches AMSI in memory to bypass antivirus scanning", "high", "T1562.001"),
        _r(r"Set-MpPreference\b.*-Disable\w+\s+(?:\$true|1|true)\b|Set-MpPreference\b.*-Enable\w+\s+(?:\$false|0|false)\b|Set-MpPreference\b.*-(?:MAPSReporting|SubmitSamplesConsent)\s+(?:0|2|Disabled|NeverSend)\b"
           r"|\bMpCmdRun(?:\.exe)?\b.*-RemoveDefinitions",
           "Disables Windows Defender real-time protection or another Defender feature", "high", "T1562.001"),
        _r(r"reg\s+add.*Windows Defender.*(?:DisableAntiSpyware|DisableAntiVirus|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableOnAccessProtection|DisableScanOnRealtimeEnable|DisableIOAVProtection|SpynetReporting|SubmitSamplesConsent)"
           r"|(?:Set|New)-ItemProperty\b.*Windows Defender.*Disable\w+",
           "Disables Windows Defender through policy registry keys", "high", "T1562.001"),
        _r(r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|netsh\s+firewall\s+set\s+opmode\s+(?:mode=)?disable|Set-NetFirewallProfile\b.*-Enabled\s+(?:False|\$false|0)",
           "Turns the Windows Firewall off", "high", "T1562.004"),
        _r(r"\bconhost(?:\.exe)?\s+--headless\b",
           "Launches a hidden process through conhost --headless (no visible window)", "high", "T1564.003",
           precision=0.9),
        _r(r"\.ClearLog\s*\(|EventLogSession\]::GlobalSession|\bClear-WinEvent\b|\b(?:del|rm|Remove-Item|erase)\b.*\\winevt\\Logs\\",
           "Clears Windows event logs through the .NET API or by deleting the log files", "high", "T1070.001"),
        _r(_DROP_DIR + r"(?:svchost|lsass|csrss|winlogon|services|smss|explorer|spoolsv|taskhostw?|dllhost|conhost|RuntimeBroker|wininit|lsm|ctfmon|sihost|fontdrvhost|dwm|SearchIndexer|msedge|chrome|OneDrive)\.exe\b",
           "Windows system process name running from a user-writable directory (masquerading)", "high", "T1036.005"),
        _r(r"\bfsutil(?:\.exe)?\s+usn\s+deletejournal\b",
           "Deletes the NTFS change journal (anti-forensics)", "high", "T1070"),
        _r(r"\bauditpol\b.*?(?:/clear\b|/remove\b|/set\b.*?(?:disable|/success:disable|/failure:disable))",
           "Clears or disables Windows audit policy", "high", "T1562.002"),
        _r(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHIST(?:FILE)?SIZE=0\b|\bset\s+\+o\s+history\b"
           r"|\b(?:rm|shred)\b[^|;&]*\.(?:bash|zsh)_history\b|>\s*~?/?\S*\.(?:bash|zsh)_history\b|\bln\s+-s\w*\s+/dev/null\s+\S*history\b"
           r"|\b(?:Remove-Item|del|rm|erase|Clear-Content)\b.*(?:HistorySavePath|ConsoleHost_history)|-HistorySaveStyle\s+SaveNothing",
           "Clears or disables shell command history", "high", "T1070.003"),
        # Authentication / audit logs, wildcard deletes and truncation are
        # anti-forensics; removing one rotated app log is housekeeping.
        _r(r"\b(?:rm|shred|truncate)\b[^|;&]*\s/var/log/(?:\*|auth|secure|wtmp|btmp|lastlog|audit|syslog|messages|faillog)\S*"
           r"|>\s*/var/log/\S+|\brm\s+-\w*r\w*\s+/var/log/?(?:\s|$)|\bjournalctl\b.*--vacuum|\bauditctl\s+-(?:D|e\s*0)\b",
           "Deletes or truncates system logs", "high", "T1070.002"),
        _r(r"\b(?:rm|shred|truncate)\b[^|;&]*\s/var/log/",
           "Removes a file under /var/log", "medium", "T1070.002"),
        _r(r"\bxattr\s+-\w*d\w*\s+com\.apple\.quarantine\b|\bxattr\s+-c\w*\s+\S|\bspctl\s+--master-disable\b",
           "Strips the macOS quarantine flag or disables Gatekeeper", "medium", "T1553.001"),
        _r(r"\b(?:systemctl\s+(?:stop|disable|mask)|service)\s+(?:--now\s+)?(?:auditd|firewalld|ufw|apparmor|rsyslog|syslog|falcon-sensor|cbdaemon|sentinelone|mdatp|osqueryd|wazuh-agent|clamav\S*|crowdstrike\S*)\b"
           r"|\bservice\s+(?:auditd|firewalld|ufw|apparmor|rsyslog|falcon-sensor)\s+stop\b|\bpkill\b.*\b(?:falcon|auditd|osquery|wazuh)\S*",
           "Stops a Linux security or logging service", "high", "T1562.001"),
        _r(r"\bsetenforce\s+0\b|\bufw\s+disable\b|\biptables\s+-(?:F|-flush)\b|\bnft\s+flush\s+ruleset\b|SELINUX=disabled",
           "Disables SELinux or host firewall rules", "medium", "T1562.001", "T1562.004"),
        _r(r"\bchattr\s+\+i\b",
           "Makes a file immutable with chattr +i (protects an implant from removal)", "medium", "T1222.002"),
        _r(r"\bicacls\b.*?/grant\s+\"?(?:Everyone|\*S-1-1-0):?\(?F|\btakeown\b.*?/f\b.*?(?:/r\b|system32)",
           "Grants Everyone full control or seizes ownership of files", "medium", "T1222.001"),
        _r(r"\bcertutil\b.*-(?:encode|decodehex|encodehex)\b",
           "Encodes or decodes a file with certutil", "medium", "T1140", "T1027"),
        _r(r"Add-MpPreference.*Exclusion(Path|Process|Extension)",
           "Adds Windows Defender exclusion", "high", "T1562.001"),
        _r(r"netsh\s+advfirewall.*disable",
           "Disables Windows Firewall via netsh", "high", "T1562.004"),
        # bcdedit safe-boot modification — handles bcdedit.exe via \b.*?
        _r(r"bcdedit\b.*?/set\b.*safeboot",
           "Modifies boot configuration for safe-mode execution (ransomware precursor)", "high", "T1490"),
        # Both -ExecutionPolicy and its common abbreviation -ep
        _r(r"(?:ExecutionPolicy|-[Ee][Pp]|-[Ee]xec?\w*)\s+(Bypass|Unrestricted)",
           "Bypasses PowerShell execution policy", "medium", "T1059.001", installer_ok=True),
        _r(r"-[Ww]indow[Ss]tyle\s+[Hh]idden|-[Ww](?:in\w*)?\s+(?:[Hh](?:id(?:den)?)?|1)\b",
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
        _r(r"Start-Process\b.*-Verb\s+RunAs\b",
           "Launches process with elevated privileges via Start-Process -Verb RunAs (UAC elevation)", "medium", "T1548.002"),
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
           "Decodes base64 payload via .NET Convert class (common in fileless PS loaders)", "medium", "T1027.010"),
        # ${var}${var}${var} chains — heavy variable-name interpolation is an
        # invoke-obfuscation tell. Single ${PATH} usage or two-var templates
        # like ${user}${val} are fine; three or more in a row is deliberate.
        _r(r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}){3,}",
           "Heavy variable-name interpolation (Invoke-Obfuscation token-split pattern)", "medium", "T1027"),
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
           "Queries domain trust information via nltest", "high", "T1482"),
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
        _r(r"\badfind(?:\.exe)?\b",
           "AdFind Active Directory enumeration (a staple of ransomware intrusions)", "high", "T1087.002", "T1018"),
        _r(r"\b(dsquery|adexplorer|ldapsearch)\b",
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
        # Modern PowerShell-native equivalents of `wmic.exe` — same process /
        # service / user enumeration, no .exe.
        _r(r"\b(?:Get-WmiObject|Get-CimInstance|gwmi|gcim)\b\s+(?:[^|;]*?-(?:Class|Query|Namespace)|\s*Win32_)",
           "Enumerates system state via WMI/CIM cmdlets (modern wmic equivalent)", "low", "T1047"),
        _r(r"\b(?:sharphound|bloodhound(?:-python)?|Invoke-BloodHound|azurehound|adrecon|pingcastle|snaffler|ldapdomaindump|rusthound)\b",
           "Active Directory attack-path mapping tool", "high", "T1087.002", "T1482"),
        _r(r"\b(?:Get-Domain(?:User|Computer|Group|Controller|Trust|GPO)|Get-Net(?:User|Computer|Group|Domain|Session|LoggedOn)|Invoke-ShareFinder|Find-LocalAdminAccess|Invoke-UserHunter|Find-DomainShare|Get-DomainSPNTicket)\b",
           "PowerView domain enumeration cmdlet", "high", "T1087.002", "T1069.002"),
        _r(r"\b(?:linpeas|winpeas\w*|linenum|linux-exploit-suggester\S*|lse\.sh|pspy\d*|PowerUp|Invoke-AllChecks|SharpUp|Seatbelt|PrivescCheck|Invoke-PrivescCheck|watson|beRoot)\b",
           "Privilege-escalation enumeration script", "high", "T1082", "T1083"),
        _r(r"\bnet1?\s+group\s+\"?(?:domain admins|enterprise admins|domain controllers|schema admins)\"?(?:\s+/domain)?\s*$|\bnet1?\s+group\s+\"?(?:domain admins|enterprise admins)\"?\s+/domain\b",
           "Lists members of a privileged domain group", "medium", "T1069.002"),
        _r(r"SecurityCenter2\b.*AntiVirusProduct|\bGet-MpComputerStatus\b.*\|\s*(?:iex|Out-File)|\bwmic\b.*\bAntiVirusProduct\b",
           "Enumerates installed security products", "medium", "T1518.001"),
        _r(r"\bfind\s+/\S*\s.*-perm\s+(?:-u=s|-4000|/4000|-2000|/6000|-6000|/u=s)\b|\bgetcap\s+-r\s+/",
           "Hunts for SUID binaries or file capabilities (privilege-escalation recon)", "medium", "T1083", "T1548.001"),
        _r(r"\b(?:quser|qwinsta|query\s+user|query\s+session)\b|\bnet\s+(?:accounts|sessions?|config\s+workstation)\b|\bwhoami\s+/(?:all|priv|groups)\b",
           "Enumerates sessions, account policy, or token privileges", "low", "T1033", "T1201"),
        _r(r"\b(?:cat|less|head)\s+/etc/(?:passwd|group|hosts|os-release|issue|sudoers)\b|\buname\s+-a\b|\bsudo\s+-l\b|\bid\s*(?:;|&&|$)",
           "Basic Linux host and account discovery", "low", "T1082", "T1087.001"),
    ]),

    # ── Privilege Escalation ──────────────────────────────────────────────────
    _ClassDef("privilege_escalation", "Privilege Escalation", [
        _r(r">>?\s*/etc/sudoers(?:\.d/\S+)?\b|NOPASSWD:\s*ALL\b.*(?:>>?|tee)\s|\btee\b[^|;&]*/etc/sudoers",
           "Grants passwordless sudo by editing sudoers", "high", "T1548.003"),
        _r(r"\bchmod\s+(?:u\+s|g\+s|\+s|[2467][0-7]{3})\s+\S|\bsetcap\s+\S*cap_(?:setuid|setgid|sys_admin|dac_override)",
           "Sets the SUID bit or a privileged capability on a binary", "high", "T1548.001"),
        _r(r"\bdocker\s+run\b.*?(?:-v\s+/:/|--volume\s+/:/|--pid[= ]host\b)"
           r"|\bnsenter\b.*?(?:-t\s*1\b|--target\s+1\b)|\bkubectl\s+(?:run|exec)\b.*?(?:hostPID|nsenter)",
           "Container breakout: mounts the host filesystem or joins host namespaces", "high", "T1611"),
        _r(r"\bdocker\s+run\b.*?(?:--privileged\b|-v\s+/var/run/docker\.sock|--cap-add[= ](?:SYS_ADMIN|ALL))",
           "Runs a privileged container or hands it the Docker socket", "medium", "T1611"),
        _r(r"\bsudo\s+-u\s*#?(?:-1|4294967295)\b",
           "sudo runas-ALL bypass (CVE-2019-14287)", "high", "T1068"),
        _r(r"\b(?:JuicyPotato\w*|PrintSpoofer\w*|RoguePotato|GodPotato\w*|SweetPotato|RottenPotato\w*|BadPotato|EfsPotato|SharpEfsPotato|RemotePotato0|Invoke-TokenManipulation|Tokenvator|incognito)\b",
           "Windows token-impersonation privilege-escalation tool", "high", "T1134.001"),
        _r(r"\b(?:pwnkit|dirtypipe|dirty_?cow|dirtycred|polkit-?exploit|CVE-20\d\d-\d{4,6}\S*\.(?:py|sh|c|exe))\b|\bpkexec\b.*?(?:/bin/(?:ba)?sh|GCONV_PATH)",
           "Local privilege-escalation exploit", "high", "T1068"),
        _r(r"\bsudo\s+(?:-\w+\s+)*(?:vim?|find|awk|gawk|nmap|less|more|man|python\S*|perl|ruby|lua|env|tar|zip|git|ftp|ed|expect|gdb|nano|socat|tclsh|php)\b"
           r".*?(?:!/bin/(?:ba)?sh|!(?:ba)?sh\b|-exec\s+/bin/(?:ba)?sh|system\s*\(|exec\s+[\"']?/bin/(?:ba)?sh|os\.(?:system|exec\w*)|pty\.spawn|--interactive|:!\s*(?:ba)?sh|/bin/(?:ba)?sh\b)",
           "Escapes to a root shell through a sudo-permitted binary (GTFOBins technique)", "high", "T1548.003"),
        _r(r"\bLD_PRELOAD=\S+\.so\b",
           "Preloads a shared object into a process via LD_PRELOAD", "medium", "T1574.006", precision=0.7),
        _r(r"\bsc\s+(?:\\\\\S+\s+)?config\s+\S+\s+binpath=.*?(?:net\s+user|cmd(?:\.exe)?\s+/c|powershell)",
           "Rewrites a service binary path to run an attacker command as SYSTEM", "high", "T1574.011"),
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
        # sdelete -z / cipher /w are also routine disk hygiene — weak alone.
        _r(r"\bsdelete\b",
           "Secure file deletion via Sysinternals SDelete (data destruction)", "medium", "T1485",
           precision=0.6),
        _r(r"\bcipher(?:\.exe)?\s+/w:",
           "Overwrites free disk space with cipher /w (destroys recoverable deleted data)", "medium", "T1485",
           precision=0.8),
        _r(r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--no-preserve-root\s+)?/(?:\*|\s|$)|\bmkfs\.\w+\s+/dev/\w+"
           r"|\bdd\s+if=/dev/(?:zero|urandom|random)\s+of=/dev/(?:sd|hd|nvme|vd|xvd|mmcblk)",
           "Destroys a filesystem or raw disk", "high", "T1485", "T1561.001"),
        _r(r"\bopenssl\s+enc\s+-(?:aes|chacha|des|camellia)\S*\b.*-in\b.*(?:;|&&)\s*(?:shred|rm|srm)\b|\bfind\b.*-exec\s+(?:openssl\s+enc|gpg\s+(?:-c|--symmetric))\b"
           r"|\bgpg\s+(?:--batch\s+)?(?:-c|--symmetric)\b.*(?:;|&&)\s*(?:shred|rm)\b",
           "Encrypts files and deletes the originals (ransomware behaviour)", "high", "T1486", precision=0.8),
        _r(r"Win32_ShadowCopy\b.*(?:\.Delete\s*\(|Remove-WmiObject|Remove-CimInstance|Delete)",
           "Deletes shadow copies via PowerShell WMI", "high", "T1490"),
        _r(r"\b(?:xmrig\w*|minerd|cpuminer\S*|nbminer|t-rex|lolminer|phoenixminer|ethminer|kdevtmpfsi|kinsing)\b|stratum\+(?:tcp|ssl)://|--donate-level\b|\bpool\.(?:minexmr|supportxmr|hashvault)\.",
           "Cryptocurrency miner (resource hijacking)", "high", "T1496"),
        # MBR/boot record destruction
        _r(r"dd\s+if=/dev/zero\s+of=/dev/(sd|hd)|bootrec\s+/fixmbr",
           "Overwrites MBR or boot record (potential disk wipe)", "high", "T1561.002"),
        # Disk/partition wipe
        _r(r"\bdiskpart\b.*(?:clean|format)",
           "Formats or wipes disk partitions via diskpart", "high", "T1561.002"),
        # Stopping security / backup services — the universal ransomware
        # pre-encryption step. Matches `net stop`, `sc stop`, and
        # `taskkill /im` against well-known AV / EDR / DB / backup services.
        _r(r"(?:net1?\s+stop|sc\s+(?:stop|delete|config)|taskkill\b[^|&;]*?/im|Stop-Service\s+(?:-Name\s+)?|Stop-Process\s+(?:-Name\s+)?|pkill\s+(?:-\w+\s+)*|killall\s+(?:-\w+\s+)*)\s*[\"']?\b("
           r"MsMpEng|MsSense|SenseIR|NisSrv|WdNisSvc|Sysmon\w*|elastic-agent|"
           r"WinDefend|MsSecFlt|Sense|SecurityHealthService|WSearch|"
           r"MSSQL\w*|SQLAgent\w*|SQLBrowser|SQLWriter|"
           r"Veeam\w*|BackupExec\w*|Acronis\w*|VMTools|VBoxService|"
           r"Sophos\w*|SAVService|SophosAgent|"
           r"CrowdStrike|CSFalconService|CSAgent|"
           r"SentinelAgent|SentinelOne\w*|MBAMService|McShield|mfe\w+|ekrn|AVP|klnagent|TmCCSF|ntrtscan|"
           r"vss|swprv|wbengine|sppsvc|"
           r"Carbon\w*|cbsensor|cbdefense"
           r")\b",
           "Stops a known security / EDR / backup / database service (ransomware kill-chain precursor)", "high", "T1489"),
    ]),

    # ── Data Staging / Exfiltration ───────────────────────────────────────────
    _ClassDef("data_staging", "Data Staging / Exfiltration", [
        # Archive creation (staging collected data for exfil)
        _r(r"\b(7z|7za|7zip)(?:\.exe)?\s+a\b",
           "Compresses files with 7-Zip (data staging for exfiltration)", "medium", "T1560", "T1560.001"),
        _r(r"\brar(?:\.exe)?\s+a\b",
           "Compresses files with WinRAR (data staging for exfiltration)", "medium", "T1560", "T1560.001"),
        _r(r"\b(?:7z|7za|7zr|rar|winrar)(?:\.exe)?\s+a\b.*\s-(?:p|hp)\S+",
           "Creates a password-protected archive (staging data so it cannot be inspected in transit)",
           "high", "T1560.001", precision=0.7),
        _r(r"Compress-Archive\b",
           "Creates zip archive via PowerShell (data staging)", "low", "T1560"),
        _r(r"tar\s+.*-[czjJ]*f\b.*\.(tar|tgz|gz|bz2|xz)",
           "Creates compressed tar archive (data staging)", "low", "T1560"),
        # HTTP POST exfiltration
        # Uploading a *local file* to a URL (curl -F name=@path / -T / --upload-file
        # / --data-binary @file / IWR -InFile) is a strong standalone exfil tell.
        _r(r"(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b.*?(?:-F\s+\S*=@|-T\s|--upload-file\b|--data-binary\s+@|-InFile\b)",
           "Uploads a local file over HTTP (data exfiltration)", "medium", "T1048", "T1041"),
        _r(r"(?:-F\s+\S*=@|-T\s|--upload-file\b|--data-binary\s+@|-InFile\b)[^|;&]*(?:h(?:xx|tt)ps?|ftp)://(?:\d{1,3}\.){3}\d{1,3}"
           r"|(?:h(?:xx|tt)ps?|ftp)://(?:\d{1,3}\.){3}\d{1,3}\S*[^|;&]*(?:-F\s+\S*=@|-T\s|--upload-file\b|--data-binary\s+@|-InFile\b)",
           "Uploads a local file to a bare IP address", "high", "T1048"),
        # A bare POST (`-d '{...}'`, `-Method POST`) is the everyday way to call
        # an API — only an exfil signal alongside a stronger staging hit.
        _r(r"(Invoke-WebRequest|curl|wget)\b.*?(-Method\s+POST|--post-data|-d\s)",
           "Sends data via HTTP POST request (potential exfiltration)", "medium", "T1048", "T1041",
           corroborate=True),
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
        # -R exposes a local service to the remote side (reverse tunnel out of
        # the network); -L is the everyday "reach the database" developer forward.
        _r(r"ssh\b.*-R\s*(?:\S+:)?\d+:",
           "SSH reverse port forward (tunnels an internal service out to a remote host)", "high", "T1572", "T1021.004"),
        _r(r"ssh\b.*-[LD]\s*(?:\S+:)?\d+",
           "SSH local/dynamic port forward", "medium", "T1572", precision=0.8),
        _r(r"\bsocat\b",
           "socat network relay tool (reverse shell or tunneling)", "high", "T1095", "T1572"),
        _r(r"\b(?:chisel|ligolo(?:-ng)?|frpc|frps|revsocks|rsockstun|gost)(?:\.exe)?\s+\S|\bcloudflared(?:\.exe)?\s+tunnel\b|\bplink\b.*-R\s+\d+",
           "Tunnelling / pivoting tool exposing an internal network", "high", "T1572", "T1090", precision=0.8),
        _r(r"\brclone(?:\.exe)?\s+(?:copy|sync|move|copyto)\b",
           "rclone bulk transfer to remote storage (the standard ransomware exfiltration tool)",
           "high", "T1567.002", precision=0.8),
        _r(r"\b(?:megacmd|mega-(?:put|login|sync)|megatools|megasync|megacopy)\b|\bwinscp(?:\.com|\.exe)?\b.*?/(?:command|script)\b|\bpscp\b.*?\S+@\S+:",
           "Scripted file transfer to external storage (MEGA / WinSCP / pscp)", "medium", "T1567.002", "T1048"),
        _r(r"(?:transfer\.sh|file\.io|0x0\.st|anonfiles\.com|gofile\.io|catbox\.moe|temp\.sh|bashupload\.com|oshi\.at|paste\.ee|pastebin\.com/api"
           r"|discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|webhook\.site|requestbin|pipedream\.net|burpcollaborator\.net|oastify\.com|interact\.sh)",
           "Sends data to an anonymous file-drop, webhook, or out-of-band collector", "high", "T1567", "T1102",
           precision=0.8),
        _r(r"\btar\b[^|]*\|\s*(?:nc|ncat|curl|ssh|openssl)\b|\bzip\b[^|]*\|\s*(?:nc|ncat|curl)\b|<\s*/dev/tcp/|>\s*/dev/tcp/",
           "Streams an archive or file straight to a network socket", "high", "T1048", "T1560"),
        _r(r"\b(?:nslookup|dig|host)\b[^|;&]*(?:\$\(|`|\$\{?\w+\}?\.)\S*\.\w+",
           "Embeds command output in a DNS lookup (DNS exfiltration)", "medium", "T1048.003"),
        _r(r"\bbitsadmin\b.*?/upload\b|Start-BitsTransfer\b.*?-TransferType\s+Upload",
           "Uploads a file with BITS", "medium", "T1048", "T1197"),
    ]),
]

# Exact URLs of installer one-liners that are documented, widely used, and
# shaped exactly like a dropper (`curl … | sh`, `iex (DownloadString(…))`).
# Matching is on the full https URL, so a look-alike host or path gets no pass.
_KNOWN_INSTALLER_URLS = re.compile(
    r"https://(?:"
    r"(?:community\.)?chocolatey\.org/install\.ps1"
    r"|sh\.rustup\.rs/?"
    r"|get\.scoop\.sh/?"
    r"|raw\.githubusercontent\.com/Homebrew/install/HEAD/(?:un)?install\.sh"
    r"|get\.docker\.com/?"
    r"|bun\.sh/install(?:\.ps1)?"
    r"|deno\.land/install\.(?:sh|ps1)"
    r"|install\.python-poetry\.org/?"
    r"|astral\.sh/uv/install\.(?:sh|ps1)"
    r"|raw\.githubusercontent\.com/nvm-sh/nvm/v[\d.]+/install\.sh"
    r"|get\.pnpm\.io/install\.(?:sh|ps1)"
    r"|aka\.ms/install-powershell\.(?:sh|ps1)"
    r"|raw\.githubusercontent\.com/ohmyzsh/ohmyzsh/master/tools/install\.sh"
    r"|raw\.githubusercontent\.com/helm/helm/main/scripts/get-helm-3"
    r"|tailscale\.com/install\.sh"
    r"|ollama\.com/install\.sh"
    r"|claude\.ai/install\.(?:sh|ps1)"
    r"|get\.k3s\.io/?"
    r"|nixos\.org/nix/install"
    r"|install\.determinate\.systems/nix"
    r"|pyenv\.run/?"
    r"|get\.sdkman\.io/?"
    r"|fnm\.vercel\.app/install"
    r"|starship\.rs/install\.sh"
    r"|raw\.githubusercontent\.com/pyenv/pyenv-installer/master/bin/pyenv-installer"
    r")",
    re.IGNORECASE,
)
_ANY_URL = re.compile(r"h(?:xx|tt)ps?://[^\s'\"<>)|;,]+", re.IGNORECASE)


def known_installer(command: str, decoded_layers: list[dict[str, Any]]) -> str | None:
    """Return the installer URL if the command is a recognised installer one-liner.

    Deliberately narrow: plain text only (any real decode layer disqualifies),
    and *every* URL in the command must be an exact known-installer URL.
    scoring.compute_verdict() further requires that nothing but
    download-and-run rules fired, so appending a second stage voids the pass.
    """
    for layer in decoded_layers:
        if layer.get("encoding") not in ("env-variable-substitution", "cmd-variable-substitution"):
            return None
    urls = _ANY_URL.findall(command)
    if not urls:
        return None
    for url in urls:
        if not _KNOWN_INSTALLER_URLS.fullmatch(url.rstrip(".")):
            return None
    return urls[0]

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
    # High-confidence evasion (AMSI patch, Defender disable, log wiping) is
    # near-certain malicious; weighted so a lone high-conf hit reaches malicious.
    "defense_evasion": 1.5,
    "privilege_escalation": 1.5,
    "recon": 0.6,             # noisy, low-severity on its own
}
for _c in _CLASSES:
    _c.weight = _CLASS_WEIGHTS.get(_c.name, 1.0)

# Per-segment scan cap. Regex patterns here use nested `.*?` under DOTALL; on
# adversarial multi-KB input that causes linear-blowup backtracking.
# Python's `re` has no timeout, so we bound what each pattern sees.
# 20 000 chars is ≈ 20 KB — more than enough for any real command line or
# decoded layer. Attack indicators appear near the beginning of payloads;
# burying a signal past 20 KB of junk would defeat the detection anyway.
_MAX_SCAN_CHARS = 20_000

# A pure help/version query (`ipconfig --help`, `curl -V`) shouldn't look
# suspicious. But a bare substring check is trivially bypassed by appending
# `--help` after a real payload, so we also require the absence of anything
# that makes a command *do* something: chaining/operators, a URL, or a long
# base64-ish blob. Suppression is still limited to low recon/defense_evasion.
# `\b` only on the word-ending forms; `/?` has no word boundary after `?`
# (a global trailing `\b` silently never matched `cmd /?`-style queries).
_BENIGN_FLAGS = re.compile(r"\s(?:--help|-h|--version|-V|/\?|/help|-\?)\s*$")
# `-H` is a hash/header flag on half of all offensive tooling, so the match is
# case-sensitive, anchored to the end, and limited to short invocations.
_HELP_MAX_TOKENS = 5
_ACTIVE_TOKENS = re.compile(
    r"[;&|`\n]|\$\(|&&|\|\||://|[A-Za-z0-9+/]{40,}",
)
# Classes where any-confidence hits are suppressed when the command is clearly
# a help/version query (no active tokens, URL, or chaining operators).
# _is_help_query() is strict enough that suppressing high-confidence hits here
# is safe — a real attack won't pass the active-token check.
# Covers: `nltest /?` (recon), `psexec /?` / `rubeus /?` (lateral/cred theft),
#         `powershell -ep bypass --help` (defense_evasion).
_BENIGN_SUPPRESSIBLE = frozenset({"recon", "defense_evasion"})  # kept for compatibility
_BENIGN_SUPPRESSIBLE_ALLCONF = frozenset({
    "recon", "lateral_movement", "credential_theft"
    # defense_evasion intentionally excluded: high-confidence AMSI patches and
    # Defender disables must not be suppressed even when --help is appended —
    # a malicious actor could trivially bypass detection by appending a help flag.
})


# `"C:\path\tool.exe" args` / `tool.exe args` -> `tool args`. Only an .exe that
# is followed by whitespace or end-of-text is an invocation; `http://x/p.exe'`
# and `lsass.exe` as an argument are left for the rules that look for them.
_EXE_INVOCATION = re.compile(
    r"[\"']?(?:[A-Za-z]:\\|%\w+%\\|\\\\)?(?:[^\\\s\"'|&;]+\\)*([A-Za-z0-9_\-]+)\.exe[\"']?(?=\s)",
    re.IGNORECASE,
)

# Distinct discovery commands chained in one paste: individually trivial,
# together the signature of hands-on-keyboard situational awareness.
_RECON_BURST = 4


def _is_help_query(command: str) -> bool:
    return (
        bool(_BENIGN_FLAGS.search(command))
        and not _ACTIVE_TOKENS.search(command)
        and len(command.split()) <= _HELP_MAX_TOKENS
    )


def classify(command: str, decoded_layers: list[dict[str, Any]]) -> list[ThreatClass]:
    """Return detected threat classes for a command and its decoded layers.

    Rules are matched per-segment (the command at depth 0, then each decoded
    layer at its own depth) rather than against one flattened blob. This stops
    a regex from spanning unrelated content across layers and lets us record
    the obfuscation depth at which each class first appears.
    """
    segments: list[tuple[int, str]] = [(0, command[:_MAX_SCAN_CHARS])]
    for layer in decoded_layers:
        if layer.get("encoding") == "limit-reached":
            continue
        depth = int(layer.get("layer", 1) or 1)
        segments.append((depth, str(layer.get("value", ""))[:_MAX_SCAN_CHARS]))
    # Rules are written against the bare tool name (`wevtutil cl`, `reg add`).
    # Add a variant of each segment with the path and `.exe` of the invoked
    # binary removed so `C:\Windows\System32\wevtutil.exe cl` matches too.
    for depth, text in list(segments):
        bare = _EXE_INVOCATION.sub(r"\1", text)
        if bare != text:
            segments.append((depth, bare))

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
        installer_only = True

        for rule in cls.rules:
            hit_depth: int | None = None
            for depth, text in segments:
                if rule.pattern.search(text):
                    hit_depth = depth if hit_depth is None else min(hit_depth, depth)
            if hit_depth is None:
                continue
            if not rule.installer_ok:
                installer_only = False

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

        if cls.name == "recon" and len(core_signals) >= _RECON_BURST and best_conf != "high":
            best_conf = "high"
            class_precision = 1.0
            matched_signals.insert(
                0, f"Discovery burst: {len(core_signals)} separate enumeration commands chained together"
            )

        # Suppress low-confidence informational hits when the command looks
        # like a help or version query (e.g. `ipconfig --help`, `curl -V`).
        if is_help_query and best_conf in ("low", "medium") and cls.name in _BENIGN_SUPPRESSIBLE:
            continue
        # For high-stakes tool-name classes, also suppress at any confidence when
        # the command is purely a help invocation with no active payload tokens.
        if is_help_query and cls.name in _BENIGN_SUPPRESSIBLE_ALLCONF:
            continue
        results.append(ThreatClass(
            name=cls.name,
            label=cls.label,
            confidence=best_conf,
            signals=matched_signals,
            techniques=mitre.enrich(matched_technique_ids),
            max_depth=max_depth,
            precision=class_precision,
            installer_only=installer_only,
        ))

    return results
