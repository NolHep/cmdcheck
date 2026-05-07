import base64, gzip

layer3_text = "Write-Host 'level3-payload'"
layer3_bytes = layer3_text.encode("utf-8")

gz2 = gzip.compress(layer3_bytes, mtime=0)
layer2_b64 = base64.b64encode(gz2).decode()

layer1_text = (
    f"IEX([System.Text.Encoding]::UTF8.GetString("
    f"[System.IO.Compression.GZipStream]::new("
    f"[System.IO.MemoryStream]::new([System.Convert]::FromBase64String(\"{layer2_b64}\")), "
    f"[System.IO.Compression.CompressionMode]::Decompress).ReadToEnd()))"
)
layer1_utf16 = layer1_text.encode("utf-16-le")
layer1_b64 = base64.b64encode(layer1_utf16).decode()

cmd = f"powershell.exe -NonInteractive -EncodedCommand {layer1_b64}"
print(cmd)
