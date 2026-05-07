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


def extract_binaries(command: str) -> list[str]:
    """Return candidate binary names (without path, lowercase) from a command string."""
    found: list[str] = []
    for m in _WIN_BINARY_RE.finditer(command):
        name = (m.group(1) or m.group(2) or "").split("\\")[-1].lower()
        if name and name not in found:
            found.append(name)

    if not found:
        for m in _UNIX_BINARY_RE.finditer(command):
            name = m.group(2).lower()
            if name and name not in found:
                found.append(name)

    # Fallback: first whitespace-delimited token
    if not found:
        first = command.strip().split()[0] if command.strip() else ""
        if first:
            found.append(first.lower().split("\\")[-1].split("/")[-1])

    return found
