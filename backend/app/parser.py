"""Wrap bashlex to produce a JSON-serialisable AST and extract binary names."""

from __future__ import annotations

import re
from typing import Any

import bashlex


def _node_to_dict(node: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"kind": node.kind, "pos": list(node.pos)}
    for part in getattr(node, "parts", []):
        d.setdefault("parts", []).append(_node_to_dict(part))
    for attr in ("word", "op", "heredoc"):
        val = getattr(node, attr, None)
        if val is not None:
            d[attr] = val
    return d


def parse_command(command: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Return (ast_list, error_message). ast_list is None on parse failure."""
    try:
        parts = bashlex.parse(command)
        return [_node_to_dict(p) for p in parts], None
    except Exception as exc:  # bashlex.errors.ParsingError and others
        return None, str(exc)


# Patterns to pull the leading binary name out of a command string
_WIN_BINARY_RE = re.compile(
    r"""
    (?:
        # Quoted path: "C:\Windows\System32\foo.exe"
        "([^"]+\.(?:exe|bat|cmd|ps1|vbs|mshta|wscript|cscript|hta))"
        |
        # Unquoted path segment: C:\foo\bar.exe or just bar.exe
        (?:^|[;&|`\s])
        (?:[A-Za-z]:\\[^\s;|&`"]*\\)?
        ([A-Za-z0-9_\-]+\.(?:exe|bat|cmd|ps1|vbs|mshta|wscript|cscript|hta))
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_UNIX_BINARY_RE = re.compile(r"(?:^|[;&|`\s])(/usr/bin/|/bin/|/sbin/)?([a-z][a-z0-9_\-]+)")

# Known Windows system binaries commonly invoked without a .exe extension in command chains.
# This supplements _WIN_BINARY_RE which requires an explicit extension.
_WIN_EXTENSIONLESS_BINARIES = frozenset({
    "wbadmin", "net", "net1", "sc", "reg", "netsh", "bcdedit", "vssadmin",
    "wmic", "schtasks", "taskkill", "tasklist", "whoami", "systeminfo",
    "ipconfig", "arp", "route", "nslookup", "nltest", "dsquery",
    "icacls", "attrib", "at", "forfiles",
    # Common shells/interpreters also invoked without extension
    "cmd", "powershell", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
    # Network tools built into Windows 10+ (curl.exe) or commonly present
    "curl", "wget",
})

# Tokens that are NOT binaries and must never appear in the binaries list.
# PowerShell built-in aliases and cmdlet verbs are commonly present in decoded
# payloads; URL scheme prefixes (http, https, ftp) appear at the start of URLs.
_NON_BINARY_TOKENS = frozenset({
    # PowerShell aliases
    "iex", "icm", "gci", "gps", "gwmi", "sal", "saps", "sls", "sv", "gv",
    "rv", "gi", "si", "ni", "ri", "ii", "gc", "sc", "ac", "clc", "clv",
    "compare", "diff", "measure", "select", "sort", "group", "where", "foreach",
    "ft", "fl", "fw", "out", "tee", "write", "echo", "read", "get", "set",
    "new", "remove", "invoke", "start", "stop", "wait", "test", "add", "clear",
    "copy", "move", "rename", "split", "join", "format", "export", "import",
    "convertto", "convertfrom", "register", "unregister", "enable", "disable",
    "suspend", "resume", "restart", "reset", "use", "enter", "exit",
    # URL scheme prefixes — appear at token position 0 of bare URLs
    "http", "https", "ftp", "ftps", "file",
})


def extract_binaries(command: str) -> list[str]:
    """Return candidate binary names (without path, lowercase) from a command string."""
    found: list[str] = []
    for m in _WIN_BINARY_RE.finditer(command):
        name = (m.group(1) or m.group(2) or "").split("\\")[-1].lower()
        # A name with spaces is a quoted argument string, not a binary path.
        # This happens when a command like `"sekurlsa::pth ... /run:cmd.exe"` is
        # matched by the quoted-path alternative — the greedy [^"]+ consumes the
        # whole argument body because it ends in .exe.
        if name and " " not in name and name not in found:
            found.append(name)

    # Also pick up known Windows system binaries used without .exe extension
    found_bases = {f.removesuffix(".exe") for f in found}
    for token in re.split(r'[\s;&|`"]+', command):
        base = token.lower().split("\\")[-1].split("/")[-1]
        if base in _WIN_EXTENSIONLESS_BINARIES and base not in found_bases:
            found.append(base + ".exe")
            found_bases.add(base)

    if not found:
        for m in _UNIX_BINARY_RE.finditer(command):
            name = m.group(2).lower()
            # Reject PS aliases, URL schemes, and implausibly long tokens
            # (base64 blobs and PS code fragments match [a-z0-9_-]+ but are not binaries)
            if name and name not in found and name not in _NON_BINARY_TOKENS and len(name) <= 40:
                found.append(name)

    return found
