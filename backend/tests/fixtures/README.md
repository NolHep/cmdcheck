# Test Fixtures

## lumma_clickfix.txt
Lumma Stealer ClickFix mshta payload pattern documented in:
- Huntress, "ClickFix: How to Infect Your PC in Three Easy Steps" (Oct 2024)
  https://www.huntress.com/blog/clickfix-how-to-infect-your-pc-in-three-easy-steps
- The command uses mshta.exe (LOLBAS-catalogued) to execute a JavaScript blob
  that downloads and runs Lumma Stealer. Defanged for safe storage (hxxp).

## benign.txt
Plain ls invocation; exercises happy-path parse with no LOLBAS hit.

## three_layer_ps.txt
Self-constructed 3-layer PowerShell payload:
  outer: -EncodedCommand (UTF-16LE base64)
  middle: gzip-compressed base64
  inner: plaintext PS command
Used to verify the recursive decoder handles all three layers correctly.
