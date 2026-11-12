"""Evasion mutations for the benchmark corpus.

An attacker who knows a rule exists does not rewrite the attack, they restyle
it: wrap it in another shell, change case, add a path, encode it, tack a
`--help` on the end. Each mutation here rewrites an attack case in a way that
still runs (or still plausibly appears in telemetry) and must not lower the
verdict below the case's minimum tier.
"""
from __future__ import annotations

import base64
import re
from collections.abc import Callable, Iterator

from tests.benchmark_corpus import Case

_WINDOWS_HINT = re.compile(
    r"\\|\.exe\b|\bpowershell\b|\bcmd\b|\breg\s|\bnet1?\s|\bwmic\b|\bschtasks\b|\bcertutil\b|\bmshta\b"
    r"|\brundll32\b|\bregsvr32\b|\bbitsadmin\b|\bvssadmin\b|\bwevtutil\b|\bbcdedit\b|\bnetsh\b|\bsc\s"
    r"|Invoke-|Get-|Set-|New-|Add-|\bnltest\b|\btaskkill\b|\bicacls\b|\bwbadmin\b|\bmsiexec\b|%\w+%",
    re.IGNORECASE,
)
_HAS_B64 = re.compile(r"[A-Za-z0-9+/]{24,}")
_FIRST_WORD = re.compile(r"^([A-Za-z][A-Za-z0-9]{2,})(?=\s)")
_SYSTEM32_TOOLS = frozenset({
    "certutil", "bitsadmin", "regsvr32", "rundll32", "mshta", "wmic", "schtasks", "vssadmin",
    "wevtutil", "bcdedit", "netsh", "reg", "net", "sc", "wbadmin", "cmstp", "odbcconf", "forfiles",
    "msiexec", "cscript", "wscript", "taskkill", "icacls", "nltest", "esentutl", "ntdsutil",
})


def is_windows(command: str) -> bool:
    return bool(_WINDOWS_HINT.search(command))


def _ps_enc(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode()


# name -> (applies, transform)
Mutation = tuple[Callable[[str], bool], Callable[[str], str]]

MUTATIONS: dict[str, Mutation] = {
    # Wrappers
    "cmd-wrap": (is_windows, lambda c: f'cmd.exe /c "{c}"'),
    "benign-prefix": (lambda c: True, lambda c: f"echo starting && {c}"),
    "ps-enc-wrap": (
        lambda c: is_windows(c) and len(c) < 1500,
        lambda c: f"powershell.exe -NoP -W Hidden -Enc {_ps_enc(c)}",
    ),
    "b64-bash-wrap": (
        lambda c: not is_windows(c),
        lambda c: f"echo {base64.b64encode(c.encode()).decode()} | base64 -d | bash",
    ),
    # Restyling
    "uppercase": (
        lambda c: is_windows(c) and not _HAS_B64.search(c) and "/dev/" not in c,
        lambda c: c.upper(),
    ),
    "double-space": (lambda c: not _HAS_B64.search(c), lambda c: c.replace(" ", "  ")),
    "tabs": (lambda c: is_windows(c) and not _HAS_B64.search(c), lambda c: c.replace(" ", "\t")),
    "system32-path": (
        lambda c: bool((m := _FIRST_WORD.match(c)) and m.group(1).lower() in _SYSTEM32_TOOLS),
        lambda c: _FIRST_WORD.sub(lambda m: rf"C:\Windows\System32\{m.group(1)}.exe", c, count=1),
    ),
    "quoted-path": (
        lambda c: bool((m := _FIRST_WORD.match(c)) and m.group(1).lower() in _SYSTEM32_TOOLS),
        lambda c: _FIRST_WORD.sub(lambda m: rf'"C:\Windows\System32\{m.group(1)}.exe"', c, count=1),
    ),
    "caret-first-token": (
        lambda c: bool((m := _FIRST_WORD.match(c)) and m.group(1).lower() in _SYSTEM32_TOOLS),
        lambda c: _FIRST_WORD.sub(lambda m: "^".join(m.group(1)), c, count=1),
    ),
    "unicode-dash": (
        # PowerShell accepts en dash / em dash / horizontal bar as the parameter prefix.
        lambda c: c.lower().startswith("powershell"),
        lambda c: re.sub(r"(?<=\s)-(?=[A-Za-z])", "\u2013", c),
    ),
    "newline-chain": (
        lambda c: " & " in c or " && " in c or "; " in c,
        lambda c: c.replace(" && ", "\n").replace(" & ", "\n").replace("; ", "\n"),
    ),
    # Suppression / allow-list abuse
    "help-suffix": (lambda c: True, lambda c: f"{c} --help"),
    "slash-help-suffix": (is_windows, lambda c: f"{c} /?"),
    "installer-decoy": (lambda c: True, lambda c: f"{c} ; curl -sSf https://sh.rustup.rs"),
    "trailing-comment": (lambda c: True, lambda c: f"{c} # routine maintenance, approved"),
}


def mutate(cases: list[Case]) -> Iterator[tuple[str, Case]]:
    """Yield (mutation name, mutated case) for every applicable pair."""
    for case in cases:
        for name, (applies, transform) in MUTATIONS.items():
            if applies(case.command):
                yield name, Case(f"{case.id}+{name}", transform(case.command), case.tier, case.source)
