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
    "rubeus":     "Rubeus (Kerberos attack toolkit)",
    "regasm":    "RegAsm (the .NET assembly registration utility)",
    "regsvcs":   "RegSvcs (the .NET component services registrar)",
    "wsl":       "WSL (Windows Subsystem for Linux)",
    "msdt":      "msdt.exe (the Microsoft Support Diagnostic Tool)",
    "mavinject": "mavinject.exe (the process-injection utility)",
    "hh":        "hh.exe (the HTML Help host)",
    "control":   "control.exe (the Control Panel host)",
    "dotnet":    "the .NET CLI",
    "7z":        "7-Zip",
    "7za":       "7-Zip (standalone)",
    # ── Standard Windows commands ────────────────────────────────────────────
    "cmd":        "the Windows Command Prompt",
    "cscript":    "the Windows Script Host (cscript)",
    "wscript":    "the Windows Script Host (wscript)",
    "ping":       "the network ping utility",
    "ipconfig":   "the IP configuration utility",
    "netstat":    "the network statistics utility",
    "arp":        "the ARP cache utility",
    "route":      "the routing-table utility",
    "tracert":    "the Windows traceroute utility",
    "nslookup":   "the DNS lookup utility",
    "whoami":     "the current-user identity tool",
    "hostname":   "the hostname query utility",
    "systeminfo": "the system information utility",
    "wusa":       "the Windows Update Standalone Installer",
    "mstsc":      "the Remote Desktop client (mstsc)",
    "runas":      "runas (run-as-another-user utility)",
    "ftp":        "the command-line FTP client",
    "tftp":       "the TFTP file-transfer client",
    "xcopy":      "xcopy (the extended file-copy utility)",
    "robocopy":   "robocopy (the robust file-copy utility)",
    "esentutl":   "esentutl (the Extensible Storage Engine utility)",
    "makecab":    "makecab (the cabinet-file creator)",
    "expand":     "the cabinet-file expansion utility",
    "winrm":      "WinRM (the Windows Remote Management utility)",
    "winrs":      "WinRS (the Windows Remote Shell)",
    "odbcconf":   "odbcconf (the ODBC configuration utility)",
    "msbuild":    "MSBuild (the .NET build engine)",
    "installutil": "InstallUtil (the .NET installer utility)",
    "nltest":     "nltest (the Netlogon test utility)",
    "wevtutil":   "wevtutil (the Windows event-log utility)",
    "gpupdate":   "the Group Policy update utility",
    "gpresult":   "the Group Policy result tool",
    "dsquery":    "dsquery (the Active Directory query tool)",
    "auditpol":   "the audit-policy configuration utility",
    "fsutil":     "fsutil (the file-system utility)",
    "dism":       "DISM (the Deployment Image Servicing tool)",
    "dnscmd":     "dnscmd (the DNS server management tool)",
    "takeown":    "the file-ownership transfer utility",
    "compact":    "the NTFS file-compression utility",
    "cipher":     "the EFS encryption utility",
    "cmstp":      "CMSTP (the Connection Manager Profile Installer)",
    "xwizard":    "xwizard (the Extensible Wizard host)",
    "pcalua":     "pcalua (the Program Compatibility Assistant)",
    "secedit":    "secedit (the security-template utility)",
    "at":         "the at task scheduler",
    "forfiles":   "forfiles (the batch file processor)",
    # ── Shells and interpreters ──────────────────────────────────────────────
    "sh":         "the POSIX shell",
    "zsh":        "the Z shell (Zsh)",
    "fish":       "the Fish shell",
    "python":     "the Python interpreter",
    "python3":    "the Python 3 interpreter",
    "python2":    "the Python 2 interpreter",
    "perl":       "the Perl interpreter",
    "ruby":       "the Ruby interpreter",
    "php":        "the PHP interpreter",
    "node":       "the Node.js runtime",
    # ── Networking tools ─────────────────────────────────────────────────────
    "nc":         "netcat",
    "ncat":       "ncat (Nmap's netcat)",
    "nmap":       "nmap (the network mapper)",
    "socat":      "socat (the bidirectional socket relay)",
    "tcpdump":    "tcpdump (the packet-capture utility)",
    "iptables":   "iptables (the Linux netfilter firewall)",
    "ip6tables":  "ip6tables (the Linux IPv6 firewall)",
    "nft":        "nft (the nftables firewall utility)",
    "ufw":        "ufw (the uncomplicated firewall)",
    "dig":        "dig (the DNS lookup utility)",
    "host":       "the host DNS-lookup utility",
    "whois":      "the whois domain-lookup tool",
    "traceroute": "the traceroute utility",
    "ss":         "ss (the socket statistics utility)",
    "sftp":       "the SFTP file-transfer client",
    "rsync":      "rsync (the remote file synchronization utility)",
    # ── Crypto / encoding ────────────────────────────────────────────────────
    "openssl":    "the OpenSSL cryptographic utility",
    "gpg":        "GPG (GNU Privacy Guard)",
    "base64":     "the base64 encoder/decoder",
    "xxd":        "xxd (the hex dump utility)",
    "hexdump":    "hexdump (the hex dump utility)",
    "strings":    "the strings binary-content extractor",
    # ── File/permission/user management ─────────────────────────────────────
    "chmod":      "chmod (the file-permission editor)",
    "chown":      "chown (the file-ownership editor)",
    "chattr":     "chattr (the extended file-attribute editor)",
    "sudo":       "sudo (the privilege-escalation utility)",
    "su":         "su (switch-user)",
    "useradd":    "the user-creation utility",
    "userdel":    "the user-deletion utility",
    "usermod":    "the user-modification utility",
    "adduser":    "adduser (the user-creation utility)",
    "passwd":     "the password-change utility",
    "groupadd":   "the group-creation utility",
    "groupdel":   "the group-deletion utility",
    "id":         "the user identity utility",
    "ln":         "the filesystem-link utility",
    "stat":       "the file-status utility",
    "file":       "the file-type identifier",
    "touch":      "the file timestamp utility",
    "mkdir":      "the directory-creation utility",
    "rmdir":      "the directory-removal utility",
    "mv":         "the file move/rename utility",
    "cp":         "the file-copy utility",
    "rm":         "the file-removal utility",
    "ls":         "the directory-listing utility",
    # ── Service / scheduling ─────────────────────────────────────────────────
    "systemctl":  "the systemd service manager",
    "service":    "the SysV service manager",
    "crontab":    "the cron job manager",
    # ── Archive / compression ────────────────────────────────────────────────
    "tar":        "the tar archive utility",
    "gzip":       "the gzip compression utility",
    "gunzip":     "the gzip decompression utility",
    "zip":        "the zip archive utility",
    "unzip":      "the unzip utility",
    # ── Process / system inspection ──────────────────────────────────────────
    "dd":         "dd (the block-level data copier)",
    "mount":      "the filesystem mount utility",
    "umount":     "the filesystem unmount utility",
    "ps":         "the process status utility",
    "kill":       "the process-kill utility",
    "killall":    "the kill-by-name utility",
    "pkill":      "the pattern-based process killer",
    "lsof":       "lsof (the open-files lister)",
    "strace":     "strace (the system-call tracer)",
    "ltrace":     "ltrace (the library-call tracer)",
    "ldd":        "ldd (the shared-library dependency lister)",
    "objdump":    "objdump (the binary disassembly utility)",
    "readelf":    "readelf (the ELF binary analyzer)",
    "uname":      "the kernel/system information utility",
    "uptime":     "the system uptime utility",
    "df":         "the disk-usage utility",
    "du":         "the directory-size utility",
    "free":       "the memory-usage utility",
    # ── Text processing ──────────────────────────────────────────────────────
    "find":       "the filesystem search utility",
    "grep":       "grep (the text-pattern search utility)",
    "awk":        "awk (the text-processing utility)",
    "sed":        "sed (the stream editor)",
    "xargs":      "xargs (the argument builder)",
    "tee":        "tee (the output-splitting utility)",
    "cat":        "cat (the file concatenator)",
    "echo":       "the echo command",
    "printf":     "the printf command",
    "eval":       "the shell eval command",
    "exec":       "the shell exec command",
    "env":        "the environment utility",
    "tr":         "tr (the character-translation utility)",
    "cut":        "the field-extraction utility",
    "sort":       "the sort utility",
    "uniq":       "the duplicate-line filter",
    "wc":         "the word/line counter",
    "head":       "the head utility",
    "tail":       "the tail utility",
    # ── Containers / cloud ───────────────────────────────────────────────────
    "docker":     "the Docker container runtime",
    "podman":     "Podman (the container runtime)",
    "kubectl":    "kubectl (the Kubernetes CLI)",
    # ── Package managers ─────────────────────────────────────────────────────
    "pip":        "pip (the Python package manager)",
    "pip3":       "pip3 (the Python 3 package manager)",
    "npm":        "npm (the Node.js package manager)",
    "apt":        "the APT package manager",
    "apt-get":    "the APT package manager",
    "yum":        "the YUM package manager",
    "dnf":        "the DNF package manager",
    "pacman":     "the Pacman package manager",
    "apk":        "the Alpine APK package manager",
    # ── Version control ──────────────────────────────────────────────────────
    "git":        "git (the version control system)",
    # ── Terminal multiplexers ────────────────────────────────────────────────
    "screen":     "screen (the terminal multiplexer)",
    "tmux":       "tmux (the terminal multiplexer)",
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
        (r"\bsnapshot\b",                    "create a VSS snapshot of Active Directory (NTDS.dit extraction prep)"),
        (r"activate\s+instance\s+ntds\b",    "activate the NTDS instance for direct database access"),
        (r"\bifm\b|install\s+from\s+media",  "create an Install-From-Media set (contains NTDS.dit and SYSTEM hive)"),
        (r"\bcreate\s+full\b",               "export a full Active Directory database backup"),
        (r"",                                "access the Active Directory database (often used for NTDS.dit extraction)"),
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
    "rubeus": [
        (r"\basktgt\b",        "request a Kerberos TGT for the specified account"),
        (r"\bdump\b",          "extract Kerberos tickets from LSASS memory"),
        (r"\bkerberoast\b",    "perform Kerberoasting (extract service ticket hashes for offline cracking)"),
        (r"\basreproast\b",    "perform AS-REP roasting (extract hashes from accounts without pre-auth)"),
        (r"\bgolden\b",        "forge a Kerberos Golden Ticket"),
        (r"\bsilver\b",        "forge a Kerberos Silver Ticket"),
        (r"\bptt\b",           "inject a Kerberos ticket (pass-the-ticket)"),
        (r"\bs4u\b",           "abuse S4U Kerberos delegation"),
        (r"\brenew\b",         "renew a Kerberos ticket"),
        (r"",                  "perform Kerberos-based attacks"),
    ],
    "regasm": [
        (r"/u\b",              "unregister a .NET assembly COM object"),
        (r"",                  "register a .NET assembly (LOLBin: executes code via COM registration)"),
    ],
    "regsvcs": [
        (r"",                  "register a .NET component service (LOLBin: executes code via COM registration)"),
    ],
    "wsl": [
        (r"-u\s+root\b",       "run a command as root inside the Windows Subsystem for Linux"),
        (r"-e\b|--exec\b",     "execute a Linux binary via the Windows Subsystem for Linux"),
        (r"",                  "launch a Linux shell via the Windows Subsystem for Linux"),
    ],
    "msdt": [
        (r"",                  "invoke the Microsoft Support Diagnostic Tool (Follina / CVE-2022-30190 execution vector)"),
    ],
    "mavinject": [
        (r"/injectrunning\b",  "inject a DLL into a running process"),
        (r"",                  "inject code into a process via the Windows process injection utility"),
    ],
    "hh": [
        (r"",                  "open an HTML Help file (LOLBin: can execute scripts embedded in .chm files)"),
    ],
    "control": [
        (r"\.cpl\b",           "execute a Control Panel applet (.cpl file, LOLBin execution vector)"),
        (r"",                  "invoke the Windows Control Panel"),
    ],
    "dotnet": [
        (r"build\b",           "build a .NET project (can execute arbitrary code via MSBuild tasks)"),
        (r"run\b",             "run a .NET application"),
        (r"",                  "run the .NET CLI"),
    ],
    "7z": [
        (r"a\b",               "create a compressed archive"),
        (r"e\b|x\b",           "extract files from an archive"),
        (r"-p\S+",             "extract a password-protected archive"),
        (r"",                  "manage an archive with 7-Zip"),
    ],
    "7za": [
        (r"a\b",               "create a compressed archive"),
        (r"e\b|x\b",           "extract files from a password-protected archive"),
        (r"",                  "manage an archive with 7-Zip"),
    ],
    # ── Standard Windows commands ────────────────────────────────────────────
    "cmd": [
        (r"/c\b", "execute an inline Windows command"),
        (r"/k\b", "run a command and keep the prompt open"),
    ],
    "cscript": [
        (r"\.vbs\b", "execute a VBScript file"),
        (r"\.js\b",  "execute a JScript file"),
        (r"\.wsf\b", "execute a Windows Script File"),
    ],
    "wscript": [
        (r"\.vbs\b", "execute a VBScript file"),
        (r"\.js\b",  "execute a JScript file"),
        (r"\.wsf\b", "execute a Windows Script File"),
    ],
    "ping": [
        (r"-t\b",             "continuously ping a host"),
        (r"-n\s+(\d+)\b",     "ping a host {1} times"),
        (r"-c\s+(\d+)\b",     "ping a host {1} times"),
        (r"",                 "send ICMP echo requests to a host"),
    ],
    "netstat": [
        (r"-b\b",             "list active connections with their owning processes"),
        (r"-an?\b|-a\b",      "list all active network connections and listeners"),
        (r"-r\b",             "display the routing table"),
        (r"-s\b",             "display per-protocol statistics"),
        (r"",                 "display network connection information"),
    ],
    "whoami": [
        (r"/all\b",           "list the current user, groups, and privileges"),
        (r"/groups\b",        "list current user's group memberships"),
        (r"/priv\b",          "list current user's privilege tokens"),
        (r"-a\b",             "list user identity and all group memberships"),
        (r"",                 "display the current user account name"),
    ],
    "runas": [
        (r"/savecred\b",      "run a command as another user using saved credentials (credential bypass)"),
        (r"/user:\S+",        "execute a command as a different user"),
    ],
    "wevtutil": [
        (r"\bcl\b",           "clear an event log (anti-forensics)"),
        (r"\bqe\b",           "query events from an event log"),
        (r"\bgl\b",           "read event log configuration"),
        (r"\bel\b",           "enumerate available event logs"),
    ],
    "esentutl": [
        (r"/y\b",             "copy a locked or in-use file (bypass VSS restrictions)"),
        (r"/d\b",             "defragment or compact an ESE database"),
        (r"/p\b",             "repair an ESE database"),
    ],
    "fsutil": [
        (r"hardlink\b",       "create a hard link to a file"),
        (r"usn\b.*deletejournal\b", "delete the USN change journal (anti-forensics)"),
        (r"behavior\b.*set\b", "modify file-system behavior settings"),
    ],
    "nltest": [
        (r"/domain_trusts\b", "enumerate Active Directory domain trust relationships"),
        (r"/dclist\b",        "enumerate domain controllers in the domain"),
        (r"/user\b",          "query Active Directory user details"),
    ],
    "dsquery": [
        (r"\buser\b",         "query Active Directory for user accounts"),
        (r"\bcomputer\b",     "query Active Directory for computer accounts"),
        (r"\bgroup\b",        "query Active Directory for group objects"),
        (r"\btrustedDomain\b","enumerate Active Directory domain trusts"),
        (r"",                 "query Active Directory"),
    ],
    "gpupdate": [
        (r"/force\b",         "force an immediate Group Policy refresh on this machine"),
        (r"",                 "refresh Group Policy settings"),
    ],
    "cipher": [
        (r"/w\b",             "overwrite free disk space to destroy deleted file data"),
        (r"/e\b",             "encrypt files using EFS"),
        (r"/d\b",             "decrypt EFS-encrypted files"),
    ],
    "compact": [
        (r"/u\b",             "decompress files"),
        (r"",                 "compress files using NTFS compression"),
    ],
    "secedit": [
        (r"/export\b",        "export the local security policy to a file"),
        (r"/configure\b",     "apply a security configuration to the system"),
    ],
    "winrm": [
        (r"quickconfig\b",    "enable WinRM for remote administration (lateral movement enabler)"),
        (r"set\b.*service\b", "configure the WinRM service"),
    ],
    "winrs": [
        (r"",                 "execute a command on a remote host via WinRM"),
    ],
    "msbuild": [
        (r"",                 "build a .NET project file (can execute arbitrary code via inline tasks)"),
    ],
    "installutil": [
        (r"",                 "install a .NET assembly (can execute code via custom installer class)"),
    ],
    "cmstp": [
        (r"",                 "load a Connection Manager profile (can execute code or bypass AppLocker)"),
    ],
    "wusa": [
        (r"/quiet\b",         "silently install a Windows Update package"),
        (r"",                 "install a Windows Update package"),
    ],
    "tftp": [
        (r"-i\b",             "download a file via TFTP in binary mode"),
        (r"",                 "transfer a file using TFTP"),
    ],
    "ftp": [
        (r"-s:\S+",           "execute FTP commands from a script file (automated download)"),
        (r"",                 "connect to an FTP server"),
    ],
    "xcopy": [
        (r"/[eEs]\b",         "recursively copy a directory tree including empty folders"),
        (r"",                 "copy files and directories"),
    ],
    "robocopy": [
        (r"/mov\b",           "move files to a new location (copy then delete)"),
        (r"/[eE]\b",          "recursively mirror a directory tree"),
        (r"",                 "robustly copy files between locations"),
    ],
    "takeown": [
        (r"/r\b",             "recursively take ownership of a directory tree"),
        (r"/f\b",             "take ownership of a specific file"),
    ],
    "makecab": [
        (r"",                 "create a compressed cabinet (.cab) archive"),
    ],
    "expand": [
        (r"",                 "expand files from a cabinet (.cab) archive"),
    ],
    "forfiles": [
        (r"/c\b",             "execute a command against each matched file in a batch"),
        (r"",                 "process files in batch using a filter"),
    ],
    "at": [
        (r"",                 "schedule a one-time task for later execution"),
    ],
    # ── Shells and interpreters ──────────────────────────────────────────────
    "sh": [
        (r"-c\b",             "run an inline shell command"),
        (r"-s\b",             "read commands from standard input"),
        (r"-i\b",             "start an interactive shell (common in reverse-shell payloads)"),
    ],
    "zsh": [
        (r"-c\b",             "run an inline shell command"),
        (r"-i\b",             "start an interactive Zsh shell"),
    ],
    "python": [
        (r"-c\b",             "execute inline Python code"),
        (r"-m\s+(\S+)",       "run the {1} Python module"),
        (r"",                 "run a Python script"),
    ],
    "python3": [
        (r"-c\b",             "execute inline Python code"),
        (r"-m\s+(\S+)",       "run the {1} Python module"),
        (r"",                 "run a Python 3 script"),
    ],
    "python2": [
        (r"-c\b",             "execute inline Python code"),
        (r"",                 "run a Python 2 script"),
    ],
    "perl": [
        (r"-e\b",             "execute inline Perl code"),
        (r"-i\b",             "edit files in-place"),
    ],
    "ruby": [
        (r"-e\b",             "execute inline Ruby code"),
    ],
    "php": [
        (r"-r\b",             "execute inline PHP code"),
        (r"-f\b",             "run a PHP script file"),
    ],
    "node": [
        (r"-e\b|--eval\b",    "execute inline JavaScript"),
        (r"",                 "run a Node.js script"),
    ],
    # ── Networking tools ─────────────────────────────────────────────────────
    "nc": [
        (r"-e\s+(?:/bin/(?:sh|bash)|cmd(?:\.exe)?|powershell)", "open a reverse shell"),
        (r"-c\s+",            "execute a command on connect (reverse shell)"),
        (r"-l\b.*-k\b|-k\b.*-l\b", "listen persistently for incoming connections"),
        (r"-l\b",             "listen for an incoming TCP connection"),
        (r"-z\b",             "scan ports in zero-I/O mode (port scanning)"),
        (r"-u\b",             "send or receive UDP data"),
        (r"",                 "open a TCP/UDP network connection"),
    ],
    "ncat": [
        (r"--exec\b|--sh-exec\b", "execute a command on connect (reverse shell)"),
        (r"-e\s+",            "open a reverse shell"),
        (r"--keep-open\b",    "listen persistently for connections"),
        (r"-l\b",             "listen for an incoming connection"),
    ],
    "nmap": [
        (r"-sV\b",            "scan hosts for open ports and service version banners"),
        (r"-O\b",             "fingerprint the remote operating system"),
        (r"-A\b",             "run an aggressive scan (OS, versions, scripts, traceroute)"),
        (r"-sS\b",            "perform a stealthy TCP SYN port scan"),
        (r"--script\b",       "run Nmap scripts against a target"),
        (r"-p\s+\S+",         "scan specific port(s) on the target"),
        (r"",                 "scan network hosts for open ports"),
    ],
    "socat": [
        (r"exec:(?:/bin/(?:bash|sh)|cmd\.exe)", "create a reverse shell"),
        (r"TCP(?:4|6)?-LISTEN\b", "open a TCP listener"),
        (r"PTY\b",            "spawn a fully interactive TTY (common in shell upgrades)"),
        (r"",                 "relay data between two network endpoints"),
    ],
    "tcpdump": [
        (r"-w\b",             "capture live network traffic to a file"),
        (r"-r\b",             "read and analyze a saved packet-capture file"),
        (r"-i\s+\S+",         "capture traffic on a specific network interface"),
        (r"",                 "capture and inspect live network traffic"),
    ],
    "iptables": [
        (r"-F\b|--flush\b",   "flush all firewall rules (disables the firewall)"),
        (r"-P\s+\w+\s+DROP",  "set a default-deny firewall policy"),
        (r"-A\b.*-j\s+ACCEPT","add a firewall allow rule"),
        (r"-A\b.*-j\s+DROP",  "add a firewall drop rule"),
        (r"-D\b",             "delete a firewall rule"),
        (r"",                 "modify Linux firewall rules"),
    ],
    "dig": [
        (r"\bAXFR\b",         "attempt a DNS zone transfer"),
        (r"\bTXT\b",          "look up DNS TXT records"),
        (r"@\S+",             "query a specific DNS server"),
        (r"",                 "perform a DNS lookup"),
    ],
    "rsync": [
        (r"-e\s+ssh\b",       "sync files over an SSH tunnel"),
        (r"--delete\b",       "sync files and remove any extras at the destination"),
        (r"",                 "synchronize files between two locations"),
    ],
    # ── Crypto / encoding ────────────────────────────────────────────────────
    "openssl": [
        (r"s_client\b",       "connect to a TLS endpoint (also used as a reverse-shell transport)"),
        (r"enc\s+-d\b",       "decrypt data using a symmetric cipher"),
        (r"enc\b",            "encrypt data using a symmetric cipher"),
        (r"req\b.*-x509\b",   "generate a self-signed X.509 certificate"),
        (r"base64\s+-d\b",    "decode base64-encoded data via OpenSSL"),
        (r"base64\b",         "encode data as base64 via OpenSSL"),
        (r"genrsa\b",         "generate an RSA private key"),
        (r"dgst\b",           "compute a cryptographic hash digest"),
    ],
    "base64": [
        (r"-d\b|--decode\b",  "decode base64-encoded data"),
        (r"",                 "encode data as base64"),
    ],
    # ── File / permission / user management ──────────────────────────────────
    "chmod": [
        (r"u\+s\b|4[0-7]{3}\b", "set the SUID bit (file runs as its owner)"),
        (r"g\+s\b|2[0-7]{3}\b", "set the SGID bit"),
        (r"\+x\b|a\+x\b|u\+x\b", "make a file executable"),
        (r"777\b",            "grant world read/write/execute permissions"),
        (r"000\b",            "remove all permissions from a file"),
        (r"-R\b",             "recursively change file permissions"),
        (r"",                 "change file permissions"),
    ],
    "chown": [
        (r"root\b",           "transfer file ownership to root"),
        (r"-R\b",             "recursively change file ownership"),
        (r"",                 "change file ownership"),
    ],
    "chattr": [
        (r"\+i\b",            "make a file immutable (cannot be modified or deleted)"),
        (r"-i\b",             "remove the immutability attribute from a file"),
        (r"\+a\b",            "make a file append-only"),
    ],
    "sudo": [
        (r"-s\b",             "open a root shell"),
        (r"-i\b",             "open a login shell as root"),
        (r"-u\s+(\S+)",       "run a command as {1}"),
        (r"",                 "run a command with elevated privileges"),
    ],
    "su": [
        (r"-\s*$|-\s+root\b", "switch to a root login shell"),
        (r"-c\b",             "run a command as another user"),
        (r"",                 "switch to another user account"),
    ],
    "useradd": [
        (r"-G\s+(?:sudo|wheel|admin|root)\b", "create a user and add them to a privileged group"),
        (r"-s\s+/bin/(?:bash|sh)\b", "create a user with shell access"),
        (r"",                 "create a new user account"),
    ],
    "passwd": [
        (r"-d\b",             "remove a user's password (enables passwordless login)"),
        (r"\broot\b",         "change the root account password"),
        (r"",                 "change a user's password"),
    ],
    "ln": [
        (r"-sf?\b",           "create or overwrite a symbolic link"),
        (r"-s\b",             "create a symbolic link"),
        (r"",                 "create a hard link"),
    ],
    "rm": [
        (r"-rf?\b|-fr?\b",    "forcibly and recursively delete files and directories"),
        (r"-f\b",             "forcibly delete files without prompting"),
        (r"-r\b",             "recursively delete a directory"),
        (r"",                 "delete files"),
    ],
    "cp": [
        (r"-r\b",             "recursively copy a directory"),
        (r"",                 "copy files"),
    ],
    "mv": [
        (r"",                 "move or rename files"),
    ],
    # ── Service / scheduling ─────────────────────────────────────────────────
    "systemctl": [
        (r"\benable\b",       "configure a service to start automatically at boot (persistence)"),
        (r"\bdisable\b",      "prevent a service from starting at boot"),
        (r"\bmask\b",         "permanently block a service from being started (defense evasion)"),
        (r"\bstart\b",        "start a service"),
        (r"\bstop\b",         "stop a service"),
        (r"\brestart\b",      "restart a service"),
        (r"\bdaemon-reload\b","reload systemd unit-file configuration"),
        (r"\bstatus\b",       "check service status"),
    ],
    "service": [
        (r"\bstart\b",        "start a service"),
        (r"\bstop\b",         "stop a service"),
        (r"\brestart\b",      "restart a service"),
        (r"\bstatus\b",       "check service status"),
    ],
    "crontab": [
        (r"-e\b",             "edit the current user's cron jobs (common persistence mechanism)"),
        (r"-l\b",             "list the current user's scheduled cron jobs"),
        (r"-r\b",             "delete all of the current user's cron jobs"),
        (r"-u\s+(\S+)",       "manage cron jobs for user {1}"),
    ],
    # ── Archive / compression ────────────────────────────────────────────────
    "tar": [
        (r"[xX].*[fF]\s+https?://", "download and extract a remote archive"),
        (r"[xX].*[fF]",       "extract files from an archive"),
        (r"[cC].*[fF]",       "create an archive"),
    ],
    # ── Process / system ─────────────────────────────────────────────────────
    "dd": [
        (r"if=/dev/(?:mem|kmem)\b",    "dump raw system memory (credential/key extraction)"),
        (r"if=/dev/(?:sd|nvme|vd|hd)", "dump a raw disk image"),
        (r"if=/dev/(?:urandom|random)\b", "generate cryptographic random data"),
        (r"",                          "copy or convert raw block-level data"),
    ],
    "mount": [
        (r"--bind\b",         "bind-mount a directory at a second path"),
        (r"-t\s+(?:nfs|cifs|smbfs)", "mount a remote network file share"),
        (r"-t\s+tmpfs\b",     "mount an in-memory temporary filesystem"),
        (r"",                 "mount a filesystem"),
    ],
    "kill": [
        (r"-9\b|-SIGKILL\b",  "forcibly kill a process"),
        (r"-(?:15|SIGTERM)\b", "request a process to terminate gracefully"),
        (r"",                 "send a signal to a process"),
    ],
    "strace": [
        (r"-p\s+\d+",         "trace system calls of a running process"),
        (r"",                 "trace the system calls made by a program"),
    ],
    # ── Text processing ──────────────────────────────────────────────────────
    "find": [
        (r"-exec\b.*\bchmod\b",  "find files and change their permissions"),
        (r"-exec\b.*\bchown\b",  "find files and change their ownership"),
        (r"-exec\b.*\brm\b",     "find and delete matching files"),
        (r"-exec\b",             "find files and execute a command on each match"),
        (r"-name\b.*\.\(key\|pem\|pfx\|p12\|cer\)", "search for cryptographic key files"),
        (r"-name\b.*(?:passwd|shadow|\.env|\.conf)\b", "search for credential or config files"),
        (r"-perm\b.*\+[0-9]*s",  "search for files with SUID/SGID bit set"),
        (r"-newer\b",            "find files modified more recently than a reference file"),
        (r"",                    "search the filesystem for files matching criteria"),
    ],
    "grep": [
        (r"-r[iIlL]?\b.*(?:password|passwd|secret|token|api.?key|credential)", "recursively search files for credential-related strings"),
        (r"-r\b",             "recursively search files for a pattern"),
        (r"-P\b",             "search using Perl-compatible regular expressions"),
        (r"",                 "search for a text pattern in files or input"),
    ],
    "awk": [
        (r"-F\b",             "process delimited text fields"),
        (r"\{.*print\b",      "extract and print fields from text"),
        (r"",                 "process and transform text data"),
    ],
    "sed": [
        (r"-i\b",             "edit a file in-place (modifies the file directly)"),
        (r"s/",               "find and replace text"),
        (r"/d\b",             "delete lines matching a pattern"),
        (r"",                 "transform text using stream editing"),
    ],
    "eval": [
        (r"",                 "execute a dynamically constructed shell command"),
    ],
    "exec": [
        (r"",                 "replace the current shell process with a new command"),
    ],
    "tail": [
        (r"-f\b|--follow\b",  "continuously monitor a file for new lines (log following)"),
        (r"",                 "read the last N lines of a file"),
    ],
    # ── Containers / cloud ───────────────────────────────────────────────────
    "docker": [
        (r"run\b.*--privileged\b",         "run a container with full host privileges (privilege escalation risk)"),
        (r"run\b.*-v\s+/(?::|$|-v\s+/):",  "run a container with the host filesystem mounted"),
        (r"run\b",                         "start and run a container"),
        (r"exec\b",                        "execute a command inside a running container"),
        (r"pull\b",                        "download a container image"),
        (r"build\b",                       "build a container image from a Dockerfile"),
    ],
    "kubectl": [
        (r"exec\b",           "execute a command inside a running Kubernetes pod"),
        (r"apply\b",          "apply a Kubernetes resource manifest"),
        (r"create\b",         "create a new Kubernetes resource"),
        (r"delete\b",         "delete a Kubernetes resource"),
        (r"get\b",            "retrieve Kubernetes resource information"),
    ],
    # ── Package managers ─────────────────────────────────────────────────────
    "pip": [
        (r"install\b.*-i\s+https?://", "install a Python package from a custom index (potentially malicious)"),
        (r"install\b",        "install a Python package"),
        (r"download\b",       "download a Python package without installing it"),
    ],
    "pip3": [
        (r"install\b.*-i\s+https?://", "install a Python 3 package from a custom index (potentially malicious)"),
        (r"install\b",        "install a Python 3 package"),
    ],
    "npm": [
        (r"install\b.*(?:-g\b|--global\b)", "install a Node.js package globally"),
        (r"install\b",        "install a Node.js package"),
        (r"run\b",            "run a script defined in package.json"),
    ],
    "apt": [
        (r"install\b",        "install a system package"),
        (r"remove\b|purge\b", "remove a system package"),
        (r"update\b",         "update the package index"),
        (r"upgrade\b",        "upgrade all installed packages"),
    ],
    "apt-get": [
        (r"install\b",        "install a system package"),
        (r"remove\b|purge\b", "remove a system package"),
        (r"update\b",         "update the package index"),
    ],
    "yum": [
        (r"install\b",        "install a system package via YUM"),
        (r"remove\b",         "remove a system package"),
        (r"update\b",         "update all installed packages"),
    ],
    "dnf": [
        (r"install\b",        "install a system package via DNF"),
        (r"remove\b",         "remove a system package"),
    ],
    # ── Version control ──────────────────────────────────────────────────────
    "git": [
        (r"clone\b",          "clone a remote repository"),
        (r"push\b",           "push commits to a remote repository"),
        (r"pull\b",           "pull changes from a remote repository"),
        (r"commit\b",         "record staged changes to the repository"),
    ],
    # ── Terminal multiplexers ────────────────────────────────────────────────
    "screen": [
        (r"-dm\b",            "start a detached screen session (can be used for persistence)"),
        (r"-x\b",             "attach to an existing screen session"),
        (r"",                 "manage a terminal multiplexer session"),
    ],
    "tmux": [
        (r"new(?:-session)?\b|-s\b", "start a new named session (can be used for persistence)"),
        (r"detach\b|-d\b",    "detach from a tmux session"),
        (r"",                 "manage a terminal multiplexer session"),
    ],
}

# Plain extensionless name → key in the tables above (so curl.exe and curl
# both resolve, and `iex` / `Invoke-Expression` map to the same entry).
_BINARY_ALIASES: dict[str, str] = {
    "invoke-expression":   "iex",
    "invoke-webrequest":   "curl",   # PS download cradle → same verb table
    "invoke-restmethod":   "curl",
    "nodejs":              "node",
    "python3.9":           "python3",
    "python3.10":          "python3",
    "python3.11":          "python3",
    "python3.12":          "python3",
    "python.exe":          "python",
    "sh.exe":              "sh",
    "zsh.exe":             "zsh",
    "perl.exe":            "perl",
    "ruby.exe":            "ruby",
    "php.exe":             "php",
    "ncat.exe":            "ncat",
    "nc.exe":              "nc",
    "nmap.exe":            "nmap",
    "apt-get":             "apt-get",  # kept distinct — see separate verb table
    "netcat":              "nc",
    "ip6tables":           "iptables",  # share the same verb table
    "regasm.exe":          "regasm",
    "regsvcs.exe":         "regsvcs",
    "wsl.exe":             "wsl",
    "msdt.exe":            "msdt",
    "mavinject.exe":       "mavinject",
    "hh.exe":              "hh",
    "control.exe":         "control",
    "7za.exe":             "7za",
    "7z.exe":              "7z",
    "dotnet.exe":          "dotnet",
    "traceroute":          "traceroute",
    "ping6":               "ping",
    "wget2":               "wget",
    "curl.exe":            "curl",
    "wget.exe":            "wget",
    "ssh.exe":             "ssh",
    "scp.exe":             "scp",
    "git.exe":             "git",
    "docker.exe":          "docker",
}

_CHAIN_LABEL = {"&": "then", "&&": "and, if that succeeds,", ";": "then", "||": "or, if that fails,"}

# Patterns matched against the *content* of a PowerShell -c / -Command argument.
# All matching patterns contribute action strings; order matters — most specific first.
_PS_INLINE_ACTIONS: list[tuple[str, str]] = [
    # Defense evasion (name these explicitly so they lead the sentence)
    (r"AmsiUtils|amsiInitFailed|amsiContext|amsiSession|AmsiScanBuffer",
     "disable AMSI (the antimalware scan interface)"),
    (r"EtwEventWrite|EtwpCreateEtwThread|\bPatchEtw\b",
     "patch ETW (Event Tracing for Windows) to suppress logging"),
    (r"Set-MpPreference\b|Add-MpPreference\b|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection",
     "disable Windows Defender real-time protection"),
    # Download cradles
    (r"DownloadString\s*\(|DownloadFile\s*\(|DownloadData\s*\(|OpenRead\s*\(",
     "download content from a remote URL"),
    (r"\bInvoke-WebRequest\b|\biwr\b",
     "download content from a remote URL"),
    # Decode / decompress — must precede iex so the sequence reads decode → execute
    (r"\[(?:System\.)?Convert\]::FromBase64String",
     "decode a base64-encoded payload"),
    (r"\bGZipStream\b|\bDeflateStream\b",
     "decompress a gzip/deflate payload"),
    # Reflective / in-memory execution
    (r"\[(?:System\.)?Reflection\.Assembly\]::Load",
     "load a .NET assembly reflectively (fileless execution)"),
    # Execution — always the terminal step; must come after decode/download entries
    (r"\biex\b|\bInvoke-Expression\b",
     "execute the payload as PowerShell code"),
    # Persistence
    (r"\bRegister-ScheduledTask\b|\bNew-ScheduledTask\b",
     "create a scheduled task (persistence)"),
    (r"CurrentVersion\\Run\b|CurrentVersion/Run\b",
     "write a startup registry key (persistence)"),
    (r"\bNew-Service\b",
     "create a Windows service (persistence)"),
    # Credential access
    (r"\bsekurlsa\b|\blsass\b",
     "access LSASS for credential extraction"),
    (r"\bConvertFrom-SecureString\b",
     "extract a plaintext credential from a SecureString"),
    # Code injection primitives
    (r"\bVirtualAlloc(?:Ex)?\b",
     "allocate executable memory (shellcode injection)"),
    (r"\bWriteProcessMemory\b",
     "write into another process's memory (code injection)"),
    (r"\bCreate(?:Remote)?Thread\b|\bNtCreateThread\b",
     "create a remote thread (code injection)"),
    # Privilege escalation / UAC bypass
    (r"\bImpersonateLoggedOnUser\b|\bAdjustTokenPrivileges\b",
     "manipulate process tokens (privilege escalation)"),
    (r"\beventvwr(?:\.exe)?\b|\bfodhelper(?:\.exe)?\b|\bsdclt(?:\.exe)?\b",
     "attempt a UAC bypass"),
    # Lateral movement
    (r"\bInvoke-Command\b.*-ComputerName\b|\bEnter-PSSession\b",
     "execute commands on a remote host"),
    (r"\bWin32_Process\b.*\bCreate\b|\bInvoke-WmiMethod\b",
     "spawn a process via WMI"),
    # C2 / networking
    (r"\bTcpClient\b|\bUdpClient\b|\bNet\.Sockets\b",
     "open a raw network socket (C2 channel)"),
    (r"\bNamedPipeClientStream\b|\bNamedPipeServerStream\b",
     "communicate via a named pipe"),
    # File drops
    (r"\[(?:System\.)?IO\.File\]::WriteAllBytes\b",
     "write a binary payload to disk"),
    (r"\bOut-File\b|\bSet-Content\b|\bAdd-Content\b|\[System\.IO\.File\]::WriteAllText\b",
     "write content to disk"),
    # C# compilation / runtime code loading
    (r"\bAdd-Type\b",
     "compile and load C# code at runtime (shellcode injection / API access)"),
    # BITS download
    (r"\bStart-BitsTransfer\b",
     "download a file via BITS (Background Intelligent Transfer Service)"),
    # TLS configuration (often a precursor to download cradles)
    (r"\[Net\.ServicePointManager\]::SecurityProtocol|ServicePointManager",
     "configure TLS settings (often to force an older protocol or bypass validation)"),
    # PowerSploit / common offensive toolkit invocations
    (r"\bInvoke-Mimikatz\b",
     "invoke Mimikatz for credential theft"),
    (r"\bInvoke-Kerberoast\b",
     "perform Kerberoasting (extract service ticket hashes for offline cracking)"),
    (r"\bInvoke-ReflectivePEInjection\b|\bInvoke-Shellcode\b|\bInvoke-DllInjection\b",
     "inject a PE or shellcode into a running process"),
    (r"\bGet-GPPPassword\b|\bGet-CachedGPPPassword\b",
     "extract credentials from Group Policy Preferences"),
    # Archive operations
    (r"\bExpand-Archive\b",
     "extract a ZIP archive"),
    (r"\bCompress-Archive\b",
     "create a ZIP archive (potential staging/exfiltration)"),
    # WMI recon
    (r"\bGet-WmiObject\b|\bGet-CimInstance\b",
     "query system information via WMI"),
]


def _analyze_powershell_inline(inline: str) -> list[str]:
    """Return plain-language action strings for the security-notable things
    found inside a PowerShell inline command. Empty list if nothing matches."""
    actions: list[str] = []
    seen: set[str] = set()
    for pattern, label in _PS_INLINE_ACTIONS:
        if re.search(pattern, inline, re.IGNORECASE) and label not in seen:
            actions.append(label)
            seen.add(label)
    return actions


_URL_RE = re.compile(r"h(?:tt|xx)ps?://([^\s'\"<>;|&\\)]+)", re.IGNORECASE)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s'\"<>|&]+\.(?:exe|dll|bat|cmd|ps1|vbs|hta|js)\b", re.IGNORECASE)


def _normalize_binary(name: str) -> str:
    base = name.lower().split("\\")[-1].split("/")[-1].removesuffix(".exe")
    return _BINARY_ALIASES.get(base, base)


# Separators that can surround a binary token in a command string.
_TOKEN_SEP = r"(?:^|[\s/\\|&;,\"'`(])"
_TOKEN_END = r"(?:\.exe)?(?:$|[\s/\\|&;,\"'`)])"


def _binary_in_segment(norm: str, segment_lower: str) -> bool:
    """Return True if *norm* appears as a standalone token in *segment_lower*.

    Uses word-boundary anchors so short names like 'sc', 'at', 'id' don't
    false-positive against substrings inside longer tokens (schtasks, attrib…).
    """
    return bool(re.search(_TOKEN_SEP + re.escape(norm) + _TOKEN_END, segment_lower))


_REMOTE_VERB_RE = re.compile(
    r"\b(?:connect|relay|reverse.?shell|tunnel|open a (?:TCP|UDP|raw)|remote)\b",
    re.IGNORECASE,
)


def _describe_segment(segment: str, binary_names: list[str]) -> str | None:
    """Build one sentence describing what *segment* does, using the first
    binary in *binary_names* that we have a verb table for. Returns None when
    we can't say anything useful — caller decides whether to fall back."""
    seg = segment.strip()
    if not seg:
        return None
    seg_lower = seg.lower()

    # Pick the first binary in this segment that we have rules for.
    # Use word-boundary matching so 'sc' doesn't claim 'schtasks', 'at' claim 'attrib', etc.
    chosen: str | None = None
    for raw_name in binary_names:
        n = _normalize_binary(raw_name)
        if (n in _BINARY_VERBS or n in _BINARY_PURPOSE) and _binary_in_segment(n, seg_lower):
            chosen = n
            break
    if chosen is None:
        # No known binary — try any binary in the list as a last resort (covers
        # the first segment where we may not have a clean token match).
        for raw_name in binary_names:
            n = _normalize_binary(raw_name)
            if n in _BINARY_VERBS or n in _BINARY_PURPOSE:
                chosen = n
                break
    if chosen is None:
        if binary_names:
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

    purpose = _BINARY_PURPOSE.get(chosen, f"`{chosen}`")

    if verb_phrase is None:
        # Binary is known but no flag pattern matched — describe the tool only.
        return f"Uses {purpose}."

    # ── Modifiers ─────────────────────────────────────────────────────────────
    # Silent flag: prefix the verb ("silently download" not "download … silently").
    if re.search(r"(?:^|\s)/(?:quiet|silent|q)\b", seg, re.IGNORECASE) and "silently" not in verb_phrase:
        verb_phrase = "silently " + verb_phrase

    url_match = _URL_RE.search(seg)
    path_match = _WIN_PATH_RE.search(seg)
    modifiers: list[str] = []

    if url_match:
        host = url_match.group(1).split("/")[0].replace("[.]", ".")
        if "from" not in verb_phrase and "download" in verb_phrase.lower():
            modifiers.append(f"from `{host}`")
        elif "to" not in verb_phrase and _REMOTE_VERB_RE.search(verb_phrase):
            modifiers.append(f"targeting `{host}`")

    if path_match and "download" in verb_phrase.lower() and " to " not in verb_phrase:
        modifiers.append(f"to `{path_match.group(0)}`")

    sentence = f"Uses {purpose} to {verb_phrase}"
    if modifiers:
        sentence += " " + " ".join(modifiers)
    return sentence.rstrip(".") + "."


def _split_chain(command: str) -> list[tuple[str, str]]:
    """Split *command* on top-level &&, ||, ;, & — respecting quoted strings.

    A lone | is intentionally NOT a split point: it keeps pipelines like
    "curl … | bash …" as a single segment so the pipe-aware verb rules fire.
    Returns [(segment, leading_operator), …]; the first item's operator is "".
    """
    out: list[tuple[str, str]] = []
    seg_start = 0
    pending_op = ""
    quote: str | None = None
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        # Track quote state — ignore operators inside matching paired quotes.
        if quote is None and ch in ('"', "'", "`"):
            quote = ch
            i += 1
        elif quote and ch == quote:
            quote = None
            i += 1
        elif quote:
            i += 1
        else:
            two = command[i : i + 2]
            if two in ("&&", "||"):
                out.append((command[seg_start:i].strip(), pending_op))
                pending_op = two
                i += 2
                seg_start = i
            elif ch == ";" or (ch == "&" and two != "&&"):
                out.append((command[seg_start:i].strip(), pending_op))
                pending_op = ch
                i += 1
                seg_start = i
            else:
                i += 1

    out.append((command[seg_start:].strip(), pending_op))
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

    # Split first — the quote-aware splitter preserves semicolons inside a
    # quoted -c "amsi; iex" argument as a single segment, so multi-statement
    # PS payloads are still analysed together. Splitting before the PS inline
    # check means chained commands after && or ; (e.g. certutil after the PS
    # segment) are excluded from the inline content, fixing the prior
    # greedy-capture bug where `(.*)` consumed the entire tail of the command.
    segments = _split_chain(command)

    # ── PowerShell / pwsh inline analysis (segment-bounded) ──────────────────
    ps_inline_result: str | None = None
    for raw_name in binaries:
        norm = _normalize_binary(raw_name)
        if norm not in ("powershell", "pwsh"):
            continue  # scan forward until we find a PS binary
        # Find the first segment that contains this PS binary.
        for seg_text, _ in segments:
            if not _binary_in_segment(norm, seg_text.lower()):
                continue
            if not re.search(r"-(?:c|command)\b", seg_text, re.IGNORECASE):
                break  # PS binary found but no -c flag — fall through
            inline_m = re.search(
                r"-(?:c|command)\b\s+(.*)", seg_text, re.IGNORECASE | re.DOTALL
            )
            if not inline_m:
                break
            raw_inline = inline_m.group(1).strip()
            # Strip an outer matched quote pair.
            if len(raw_inline) >= 2 and raw_inline[0] in ('"', "'") and raw_inline[-1] == raw_inline[0]:
                inline_content = raw_inline[1:-1]
            else:
                inline_content = raw_inline
            actions = _analyze_powershell_inline(inline_content)
            if actions:
                # Fall back to the full command for URL extraction — the URL may
                # sit in a different segment (e.g. certutil fetches, PS executes).
                url_m = _URL_RE.search(inline_content) or _URL_RE.search(command)
                if url_m:
                    host = url_m.group(1).split("/")[0].replace("[.]", ".")
                    actions = [
                        a.replace("from a remote URL", f"from `{host}`")
                        for a in actions
                    ]
                purpose = _BINARY_PURPOSE.get(norm, "PowerShell")
                out = f"Uses {purpose} to {_join(actions)}."
                layers = [
                    l for l in (result.get("decoded_layers") or [])
                    if l.get("encoding") not in ("limit-reached", "env-variable-substitution")
                ]
                if layers:
                    out += (
                        f" The payload is obfuscated"
                        f" ({len(layers)} decode layer{'s' if len(layers) != 1 else ''});"
                        f" see the decoded content below."
                    )
                ps_inline_result = out
            break  # found the PS segment — stop scanning segments
        if ps_inline_result is not None:
            return ps_inline_result
        break  # stop after the first PS/pwsh binary
    sentences: list[str] = []
    for idx, (segment, op) in enumerate(segments):
        seg_lower = segment.lower()
        seg_binaries = [
            b for b in binaries
            if _binary_in_segment(_normalize_binary(b), seg_lower)
        ]
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


def _compress_encoding_chain(encodings: list[str]) -> str:
    """Collapse adjacent identical labels: ['base64','base64','gzip'] → 'base64 (×2) → gzip'."""
    if not encodings:
        return "unknown"
    parts: list[str] = []
    i = 0
    while i < len(encodings):
        label = encodings[i]
        count = 1
        while i + count < len(encodings) and encodings[i + count] == label:
            count += 1
        parts.append(f"{label} (×{count})" if count > 1 else label)
        i += count
    return " → ".join(parts)


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
        # Strip non-obfuscation markers from the display chain — matches the same
        # set excluded from encoding_depth in main.py so the depth number and the
        # chain label are always computed over the same set of layers.
        _DISPLAY_SKIP = {"limit-reached", "env-variable-substitution", "format-op", "dot-replace"}
        display_encodings = [e for e in encodings if e not in _DISPLAY_SKIP]
        chain = _compress_encoding_chain(display_encodings)
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
            "No malicious patterns were matched. Review this command in the context of "
            "the broader incident timeline before drawing conclusions."
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
