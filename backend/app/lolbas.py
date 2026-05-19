"""Load and query the LOLBAS catalog from the vendored git submodule."""

from __future__ import annotations

import difflib
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from . import mitre

logger = logging.getLogger(__name__)

# Loaded once at startup
_catalog: dict[str, dict[str, Any]] = {}

SIMILARITY_THRESHOLD = 0.7
# Argument-pattern similarity: how close the *observed arguments* are to a known
# abuse example. Lower than the name threshold because catalog examples carry
# {PLACEHOLDER} tokens and real invocations vary — 0.6 reliably separates abuse
# patterns from benign dual-use of the same binary (CLAUDE.md convention).
ARG_SIMILARITY_THRESHOLD = 0.6
LOLBAS_DIR = Path(__file__).parent.parent / "data" / "LOLBAS" / "yml"

# Catalog example placeholders: {REMOTEURL:.exe}, {PATH_ABSOLUTE}, {PAYLOAD}, …
_PLACEHOLDER = re.compile(r"\{[^}]*\}")
_WS = re.compile(r"\s+")
# Catalog examples carry these as {PLACEHOLDER}; we normalize observed
# invocations the same way so character-level SequenceMatcher isn't drowned
# by a long URL or absolute path that the example tokenized away.
_URL_LIKE = re.compile(r"\bh(?:tt|xx)ps?://\S+", re.IGNORECASE)
_WIN_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']+|\\\\[^\s\"']+")
_POSIX_PATH = re.compile(r"(?:^|\s)/[^\s\"']{2,}")
_FLAG_TOKEN = re.compile(r"(?:^|\s)([-/][A-Za-z][A-Za-z0-9_\-]*)")


def load_catalog() -> None:
    """Walk LOLBAS/yml/, parse every YAML file, index by lowercase binary name."""

    if not LOLBAS_DIR.exists():
        logger.warning("LOLBAS submodule not found at %s — LOLBAS matching disabled", LOLBAS_DIR)
        return

    count = 0
    for yml_file in LOLBAS_DIR.rglob("*.yml"):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "Name" not in data:
                continue
            name = data["Name"].lower()
            _catalog[name] = data
            count += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping %s: %s", yml_file, exc)

    logger.info("LOLBAS catalog loaded: %d entries", count)


def _extract_techniques(entry: dict[str, Any]) -> list[str]:
    """Return unique MITRE technique IDs from all Commands in a LOLBAS entry.

    MitreID in the YAML is always a plain string (e.g. "T1059.001"), never a
    list — iterating a string yields characters, which is the bug this fixes.
    """
    techniques: list[str] = []
    for cmd in entry.get("Commands", []) or []:
        mitre = cmd.get("MitreID")
        if isinstance(mitre, str) and mitre and mitre not in techniques:
            techniques.append(mitre)
        elif isinstance(mitre, list):
            for t in mitre:
                if isinstance(t, str) and t and t not in techniques:
                    techniques.append(t)
    return techniques


def _extract_functions(entry: dict[str, Any]) -> list[str]:
    """Return unique abuse categories (Execute, Download, …) from Commands."""
    seen: list[str] = []
    for cmd in entry.get("Commands", []) or []:
        cat = cmd.get("Category")
        if isinstance(cat, str) and cat and cat not in seen:
            seen.append(cat)
    return seen


def _normalize_invocation(text: str) -> str:
    """Lowercase, strip placeholders/URLs/paths, defang, collapse whitespace.

    Catalog example commands carry value-bearing tokens as {PLACEHOLDER}; we
    apply the same erasure to observed URLs and Windows/POSIX paths so a
    char-level SequenceMatcher compares argument *patterns*, not URL contents.
    """
    text = text.replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":")
    text = _PLACEHOLDER.sub(" ", text)
    text = _URL_LIKE.sub(" ", text)
    text = _WIN_PATH.sub(" ", text)
    text = _POSIX_PATH.sub(" ", text)
    return _WS.sub(" ", text).strip().lower()


def _flag_overlap(observed: str, example: str) -> float:
    """Jaccard similarity of flag/switch tokens between observed and example.
    Robust when char-level ratios are depressed by length differences (long
    URLs, paths). Jaccard (∩/∪) is used so a tiny observed flag-set doesn't get
    100% credit by being a subset of a multi-flag abuse example."""
    ex_flags = {m.group(1).lower() for m in _FLAG_TOKEN.finditer(example)}
    obs_flags = {m.group(1).lower() for m in _FLAG_TOKEN.finditer(observed)}
    union = ex_flags | obs_flags
    if not union:
        return 0.0
    return len(ex_flags & obs_flags) / len(union)


def _arg_portion(invocation: str, binary: str) -> str:
    """Everything after the leading binary token — the argument pattern."""
    inv = invocation.lstrip()
    low = inv.lower()
    for cand in (binary, binary.removesuffix(".exe"), binary + ".exe"):
        c = cand.lower()
        idx = low.find(c)
        if idx != -1:
            return inv[idx + len(c):].strip()
    # No binary token found — compare the whole thing.
    return inv


def _best_arg_similarity(command: str, entry: dict[str, Any]) -> float:
    """Best SequenceMatcher ratio between the observed argument pattern and any
    abuse-example Command in this entry. This is what makes a *renamed* LOLBIN
    or an obfuscated invocation match, and lets benign dual-use (args unlike any
    abuse example) score low — exactly what name-only matching cannot do."""
    name = str(entry.get("Name", ""))
    observed = _arg_portion(_normalize_invocation(command), name)
    observed_raw_args = _arg_portion(command.lower(), name)  # preserve flag tokens
    if not observed:
        return 0.0
    best = 0.0
    for cmd in entry.get("Commands", []) or []:
        example = cmd.get("Command")
        if not isinstance(example, str) or not example:
            continue
        example_args = _arg_portion(_normalize_invocation(example), name)
        if not example_args:
            continue
        seq = difflib.SequenceMatcher(None, observed, example_args).ratio()
        # Weighted combo: sequence ratio is the primary signal; flag-set
        # Jaccard rescues short/sparse patterns where char ratio is noisy.
        # 0.75/0.25 weighting empirically separates abuse from benign dual-use
        # better than either signal alone.
        flag = _flag_overlap(observed_raw_args, _arg_portion(example.lower(), name))
        ratio = 0.75 * seq + 0.25 * flag
        if ratio > best:
            best = ratio
    return round(best, 4)


def match(binary_name: str, command: str | None = None) -> dict[str, Any] | None:
    """Return the best-matching LOLBAS entry for *binary_name*, or None.

    When *command* is supplied, the result also carries `arg_similarity` (how
    closely the observed arguments resemble a known abuse example) and
    `arg_match` (>= ARG_SIMILARITY_THRESHOLD). Per CLAUDE.md, argument
    similarity — not the binary name alone — is what distinguishes abuse from
    benign dual-use and catches obfuscated/renamed invocations.
    """
    if not _catalog:
        return None

    needle = binary_name.lower().removesuffix(".exe")

    # Exact match first — avoids false fuzzy matches like wget→winget.
    exact = _catalog.get(needle) or _catalog.get(needle + ".exe")
    if exact is not None:
        best_entry = exact
        best_score = 1.0
    else:
        best_score = 0.0
        best_entry = None
        # Short names (≤5 chars) are too ambiguous for fuzzy matching.
        if len(needle) <= 5:
            return None
        for catalog_name, entry in _catalog.items():
            score = difflib.SequenceMatcher(None, needle, catalog_name.removesuffix(".exe")).ratio()
            if score > best_score:
                best_score = score
                best_entry = entry

    if best_entry is None or best_score < SIMILARITY_THRESHOLD:
        return None

    raw_techniques = _extract_techniques(best_entry)
    technique_details = mitre.enrich(raw_techniques)

    result: dict[str, Any] = {
        "name": best_entry.get("Name"),
        "description": best_entry.get("Description"),
        "url": best_entry.get("URL"),
        "techniques": raw_techniques,
        "technique_details": technique_details,
        "functions": _extract_functions(best_entry),
        "similarity": round(best_score, 4),
    }

    if command is not None:
        arg_sim = _best_arg_similarity(command, best_entry)
        result["arg_similarity"] = arg_sim
        result["arg_match"] = arg_sim >= ARG_SIMILARITY_THRESHOLD

    return result
