#!/usr/bin/env python3
"""Run once to regenerate the 3-layer PowerShell fixture blob printed to stdout."""

import base64
import gzip

# Layer 3 (innermost): the actual payload
layer3 = b"Write-Host 'pwned'"

# Layer 2: gzip-compress layer3, then base64
gz = gzip.compress(layer3)
layer2_b64 = base64.b64encode(gz).decode()

# Layer 1: wrap in an IEX call, encode as UTF-16LE, then base64
layer1_inner = f"IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{layer2_b64}') | % {{ Invoke-Expression (([System.IO.Compression.GZipStream]::new([System.IO.MemoryStream]::new($_), [System.IO.Compression.CompressionMode]::Decompress)).CopyTo([ref]$null)) }}))"
# Simpler: just wrap with another IEX decode
layer1_inner = f"IEX (([System.IO.Compression.GZipStream]::new([System.IO.MemoryStream]::new([System.Convert]::FromBase64String('{layer2_b64}')), [System.IO.Compression.CompressionMode]::Decompress) | % ReadToEnd))"

layer1_utf16 = layer1_inner.encode("utf-16-le")
layer1_b64 = base64.b64encode(layer1_utf16).decode()

cmd = f"powershell.exe -NonInteractive -EncodedCommand {layer1_b64}"

print("Command:")
print(cmd)
print()
print("Layer 1 b64:", layer1_b64[:40], "...")
print("Layer 2 (gzip b64):", layer2_b64[:40], "...")
