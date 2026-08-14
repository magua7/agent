# SKILL: Memory Forensics — Expert Analysis Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [3. ANALYSIS METHODOLOGY](#3-analysis-methodology)
- [4. LINUX MEMORY ANALYSIS](#4-linux-memory-analysis)
- [5. MALWARE INDICATORS IN MEMORY](#5-malware-indicators-in-memory)
- [6. DECISION TREE](#6-decision-tree)
<!-- zhiyugo:toc:end -->

## 3. ANALYSIS METHODOLOGY

### Step 1: Identify OS

```bash
# Vol2
vol.py -f mem.raw imageinfo
vol.py -f mem.raw kdbgscan

# Vol3
vol -f mem.raw windows.info
vol -f mem.raw banners.Banners
```

### Step 2: Process Listing — Hidden Process Detection

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE pslist       # EPROCESS linked list
vol.py -f mem.raw --profile=PROFILE psscan       # pool tag scan (finds unlinked)
vol.py -f mem.raw --profile=PROFILE pstree       # parent-child hierarchy

# Vol3
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan
vol -f mem.raw windows.pstree
```

**Red flags**: Process in `psscan` but not `pslist` = DKOM (Direct Kernel Object Manipulation) hiding.

### Step 3: Network Connections

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE netscan      # TCP/UDP endpoints
vol.py -f mem.raw --profile=PROFILE connections   # XP/2003 only
vol.py -f mem.raw --profile=PROFILE connscan      # closed connections

# Vol3
vol -f mem.raw windows.netscan
vol -f mem.raw windows.netstat
```

### Step 4: DLL / Module Analysis

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE dlllist -p PID
vol.py -f mem.raw --profile=PROFILE ldrmodules -p PID   # find unlinked DLLs

# Vol3
vol -f mem.raw windows.dlllist --pid PID
```

**Red flags**: DLL in `dlllist` but `False` in all three `ldrmodules` columns = reflective DLL injection.

### Step 5: Code Injection Detection (Malfind)

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE malfind -p PID
vol.py -f mem.raw --profile=PROFILE malfind -D /tmp/dump/   # dump injected sections

# Vol3
vol -f mem.raw windows.malfind --pid PID
```

**What malfind detects**: Memory regions with `PAGE_EXECUTE_READWRITE` that don't map to a file on disk — classic shellcode/injection indicator.

### Step 6: Credential Extraction

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE hashdump      # SAM hashes
vol.py -f mem.raw --profile=PROFILE lsadump       # LSA secrets
vol.py -f mem.raw --profile=PROFILE cachedump     # domain cached creds
vol.py -f mem.raw --profile=PROFILE mimikatz      # (plugin) plaintext creds

# Vol3
vol -f mem.raw windows.hashdump
vol -f mem.raw windows.lsadump
vol -f mem.raw windows.cachedump
```

### Step 7: File Extraction

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE filescan | grep -i "password\|secret\|flag"
vol.py -f mem.raw --profile=PROFILE dumpfiles -Q OFFSET -D /tmp/dump/

# Vol3
vol -f mem.raw windows.filescan
vol -f mem.raw windows.dumpfiles --virtaddr OFFSET
```

### Step 8: Registry Analysis

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE hivelist
vol.py -f mem.raw --profile=PROFILE printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
vol.py -f mem.raw --profile=PROFILE userassist    # program execution evidence

# Vol3
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### Step 9: Command History

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE cmdscan       # cmd.exe history
vol.py -f mem.raw --profile=PROFILE consoles       # full console output

# Vol3
vol -f mem.raw windows.cmdline
```

### Step 10: Timeline Generation

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE timeliner --output=body --output-file=timeline.body
mactime -b timeline.body -d > timeline.csv

# Vol3
vol -f mem.raw timeliner.Timeliner
```

---

## 4. LINUX MEMORY ANALYSIS

```bash
# Vol2 (requires Linux profile)
vol.py -f mem.lime --profile=LinuxProfile linux_pslist
vol.py -f mem.lime --profile=LinuxProfile linux_pstree
vol.py -f mem.lime --profile=LinuxProfile linux_netstat
vol.py -f mem.lime --profile=LinuxProfile linux_bash        # bash history
vol.py -f mem.lime --profile=LinuxProfile linux_enumerate_files
vol.py -f mem.lime --profile=LinuxProfile linux_proc_maps -p PID
vol.py -f mem.lime --profile=LinuxProfile linux_malfind

# Vol3
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree
vol -f mem.lime linux.bash
vol -f mem.lime linux.check_afinfo     # rootkit detection
vol -f mem.lime linux.check_syscall    # syscall hooking
vol -f mem.lime linux.tty_check        # TTY hooking
```

### Building Linux Profiles (Vol2)

```bash
cd volatility/tools/linux
make
# Creates module.dwarf + System.map → zip as profile
zip LinuxProfile.zip module.dwarf /boot/System.map-$(uname -r)
# Place in volatility/plugins/overlays/linux/
```

---

## 5. MALWARE INDICATORS IN MEMORY

| Indicator | Detection Method | What It Means |
|---|---|---|
| Process in psscan but not pslist | Compare pslist vs psscan | DKOM — process hiding |
| Unexpected parent-child | pstree analysis | e.g., svchost spawned by cmd.exe |
| MZ header in non-image memory | malfind | Reflective DLL / PE injection |
| RWX memory without backing file | malfind | Shellcode injection |
| DLL unlinked from all PEB lists | ldrmodules (all False) | Stealth DLL loading |
| svchost.exe not child of services.exe | pstree | Fake svchost (malware) |
| Unusual network connections | netscan + PID correlation | C2 communication |
| Hooking in SSDT/IDT | ssdt / idt plugins | Rootkit |
| Modified kernel objects | linux_check_syscall | Linux rootkit |

### Normal Parent-Child Relationships (Windows)

```
System (4)
└── smss.exe
    └── csrss.exe
    └── wininit.exe
        └── services.exe
            └── svchost.exe (multiple)
            └── spoolsv.exe
        └── lsass.exe
    └── winlogon.exe
        └── explorer.exe
            └── user applications
```

---

## 6. DECISION TREE

```
Memory dump acquired — need to analyze
│
├── What OS?
│   ├── Windows → vol imageinfo / windows.info (§3 Step 1)
│   └── Linux → build profile or use Vol3 auto-detect (§4)
│
├── Malware investigation?
│   ├── Check processes: pslist vs psscan (hidden?) (§3 Step 2)
│   ├── Check parent-child: pstree (suspicious spawning?) (§5)
│   ├── Check injections: malfind (RWX memory?) (§3 Step 5)
│   ├── Check DLLs: ldrmodules (unlinked?) (§3 Step 4)
│   ├── Check network: netscan (C2 connections?) (§3 Step 3)
│   └── Extract suspicious files: dumpfiles (§3 Step 7)
│
├── Credential recovery?
│   ├── SAM hashes → hashdump (§3 Step 6)
│   ├── LSA secrets → lsadump (§3 Step 6)
│   ├── Cached domain creds → cachedump (§3 Step 6)
│   └── Plaintext passwords → mimikatz plugin (§3 Step 6)
│
├── Incident timeline?
│   ├── timeliner for comprehensive timeline (§3 Step 10)
│   ├── cmdscan / consoles for command history (§3 Step 9)
│   ├── userassist for program execution (§3 Step 8)
│   └── Cross-reference with PCAP timeline (→ traffic-analysis-pcap)
│
├── CTF / flag hunting?
│   ├── filescan + grep for flag patterns (§3 Step 7)
│   ├── cmdscan for typed flags/passwords (§3 Step 9)
│   ├── Clipboard: clipboard plugin
│   ├── Screenshots: screenshot plugin
│   └── Environment vars: envars plugin
│
└── Linux-specific?
    ├── linux_bash for shell history (§4)
    ├── linux_check_syscall for rootkit (§4)
    └── linux_netstat for connections (§4)
```
