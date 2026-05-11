"""Parent-process plausibility scoring for command analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Suspicion = Literal["high", "medium", "low", "benign"]


@dataclass
class ParentVerdict:
    parent: str
    child: str
    suspicion: Suspicion
    explanation: str


# Known-suspicious (parent, child) pairs
_PAIRS: dict[tuple[str, str], tuple[Suspicion, str]] = {
    # Office apps spawning shells — macros / phishing
    ("winword.exe", "powershell.exe"): ("high", "Word spawning PowerShell is a strong indicator of a malicious macro."),
    ("winword.exe", "cmd.exe"): ("high", "Word spawning cmd.exe is a classic macro execution pattern."),
    ("winword.exe", "wscript.exe"): ("high", "Office apps rarely launch script interpreters legitimately."),
    ("winword.exe", "cscript.exe"): ("high", "Office apps rarely launch script interpreters legitimately."),
    ("winword.exe", "mshta.exe"): ("high", "mshta.exe is commonly abused to execute HTA payloads from Office macros."),
    ("winword.exe", "regsvr32.exe"): ("high", "Word spawning regsvr32.exe is associated with COM scriptlet execution."),
    ("excel.exe", "powershell.exe"): ("high", "Excel spawning PowerShell is a strong indicator of a malicious macro."),
    ("excel.exe", "cmd.exe"): ("high", "Excel spawning cmd.exe is a classic macro execution pattern."),
    ("excel.exe", "wscript.exe"): ("high", "Office apps rarely launch script interpreters legitimately."),
    ("excel.exe", "mshta.exe"): ("high", "mshta.exe is commonly abused in Excel macro attacks."),
    ("excel.exe", "regsvr32.exe"): ("high", "Excel spawning regsvr32.exe is associated with COM scriptlet execution."),
    ("outlook.exe", "powershell.exe"): ("high", "Email client spawning PowerShell is characteristic of phishing payload execution."),
    ("outlook.exe", "cmd.exe"): ("high", "Email client spawning a shell is a strong IOC."),
    ("outlook.exe", "wscript.exe"): ("high", "Email client spawning script interpreters suggests malicious attachment."),
    ("outlook.exe", "mshta.exe"): ("high", "mshta.exe spawned from email is a strong indicator of HTA-based phishing."),
    ("powerpnt.exe", "powershell.exe"): ("high", "PowerPoint spawning PowerShell indicates a malicious presentation."),
    ("powerpnt.exe", "cmd.exe"): ("high", "PowerPoint spawning cmd.exe is a macro execution pattern."),
    ("onenote.exe", "cmd.exe"): ("high", "OneNote spawning cmd.exe is associated with embedded attachment attacks."),
    ("onenote.exe", "powershell.exe"): ("high", "OneNote spawning PowerShell is associated with embedded attachment attacks."),
    ("onenote.exe", "wscript.exe"): ("high", "OneNote spawning wscript.exe is a known attachment delivery vector."),
    # Browsers spawning shells — ClickFix / drive-by
    ("chrome.exe", "powershell.exe"): ("high", "Browser spawning PowerShell is characteristic of ClickFix or drive-by attacks."),
    ("chrome.exe", "cmd.exe"): ("high", "Browser spawning cmd.exe is associated with ClickFix social engineering."),
    ("chrome.exe", "mshta.exe"): ("high", "Browser spawning mshta.exe suggests a drive-by HTA attack."),
    ("msedge.exe", "powershell.exe"): ("high", "Browser spawning PowerShell is characteristic of ClickFix or drive-by attacks."),
    ("msedge.exe", "cmd.exe"): ("high", "Browser spawning cmd.exe is associated with ClickFix social engineering."),
    ("firefox.exe", "powershell.exe"): ("high", "Browser spawning PowerShell is characteristic of ClickFix or drive-by attacks."),
    ("iexplore.exe", "powershell.exe"): ("high", "IE spawning PowerShell is commonly seen in drive-by exploitation."),
    ("iexplore.exe", "mshta.exe"): ("high", "IE spawning mshta.exe is a known drive-by delivery vector."),
    # svchost spawning suspicious children
    ("svchost.exe", "mshta.exe"): ("high", "svchost spawning mshta.exe is highly suspicious and warrants immediate investigation."),
    ("svchost.exe", "wscript.exe"): ("medium", "svchost spawning script interpreters is unusual — verify the hosting service."),
    ("svchost.exe", "powershell.exe"): ("medium", "svchost spawning PowerShell is unusual outside of specific management scenarios."),
    ("svchost.exe", "cmd.exe"): ("low", "svchost spawning cmd.exe can be legitimate (Group Policy scripts) but review context."),
    # Error reporting / task hosts
    ("werfault.exe", "powershell.exe"): ("high", "Error reporting spawning PowerShell is associated with process injection."),
    ("taskhost.exe", "powershell.exe"): ("medium", "Scheduled task host spawning PowerShell — verify the task is legitimate."),
    ("taskhostw.exe", "powershell.exe"): ("medium", "Scheduled task host spawning PowerShell — verify the task is legitimate."),
    # Normal / benign pairs
    ("cmd.exe", "powershell.exe"): ("low", "cmd.exe spawning PowerShell is common and often benign — review the full command for suspicious flags."),
    ("powershell.exe", "cmd.exe"): ("low", "PowerShell spawning cmd.exe is common in scripts and automation."),
    ("powershell.exe", "powershell.exe"): ("low", "Child PowerShell process — check for encoded commands or suspicious flags."),
    ("explorer.exe", "powershell.exe"): ("low", "User-launched PowerShell — likely interactive, but review for suspicious parameters."),
    ("explorer.exe", "cmd.exe"): ("benign", "User-launched cmd.exe from Explorer."),
    ("cmd.exe", "cmd.exe"): ("benign", "Nested cmd.exe is common in batch scripts."),
    ("services.exe", "svchost.exe"): ("benign", "Normal Windows service hosting pattern."),
}

# Process categories for fallback rules
_OFFICE_APPS = frozenset({
    "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
    "onenote.exe", "access.exe", "msaccess.exe", "publisher.exe",
})
_BROWSERS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "vivaldi.exe",
})
_SHELLS = frozenset({
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "wmic.exe", "regsvr32.exe", "rundll32.exe",
})


def _normalize(name: str) -> str:
    name = name.strip().lower().split("\\")[-1].split("/")[-1]
    if "." not in name:
        name += ".exe"
    return name


def score_parent(parent_process: str, command: str) -> ParentVerdict | None:
    """Return a parent-process suspicion verdict, or None if no rule applies."""
    from .parser import extract_binaries

    parent = _normalize(parent_process)

    binaries = extract_binaries(command)
    if not binaries:
        return None
    child = _normalize(binaries[0])

    # Exact pair lookup
    if (parent, child) in _PAIRS:
        suspicion, explanation = _PAIRS[(parent, child)]
        return ParentVerdict(parent=parent, child=child, suspicion=suspicion, explanation=explanation)

    # Category fallbacks
    if parent in _OFFICE_APPS and child in _SHELLS:
        return ParentVerdict(
            parent=parent,
            child=child,
            suspicion="high",
            explanation=f"Office applications rarely spawn {child} legitimately. Strong indicator of malicious macro or exploit.",
        )
    if parent in _BROWSERS and child in _SHELLS:
        return ParentVerdict(
            parent=parent,
            child=child,
            suspicion="high",
            explanation=f"Browsers rarely spawn {child} directly. Characteristic of ClickFix social engineering or drive-by exploitation.",
        )

    # No specific intelligence for this pair
    return None
