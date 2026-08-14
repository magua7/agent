---
name: anti-debugging-techniques
description: >-
  Anti-debugging detection and bypass playbook. Use when reversing protected
  binaries that detect debuggers via ptrace, PEB flags, timing checks, or
  signal/exception handlers on Linux and Windows.
---

# SKILL: Anti-Debugging Techniques — Detection & Bypass Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert anti-debug techniques across Linux and Windows. Covers ptrace, PEB flags, NtQueryInformationProcess, timing attacks, signal-based detection, TLS callbacks, VEH tricks, and all corresponding bypass methods. Pay particular attention to the distinction between user-mode and kernel-mode detection and the correct patching strategy for each.

## 0. RELATED ROUTING

- `code-obfuscation-deobfuscation` when the binary also uses control flow flattening, VM protection, or string encryption
- `vm-and-bytecode-reverse` when the anti-debug sits inside a custom VM dispatcher
- `symbolic-execution-tools` when you want to symbolically skip anti-debug checks entirely

### Advanced Reference

Also inspect [ANTI_DEBUG_MATRIX.md](./ANTI_DEBUG_MATRIX.md) when you need:
- Complete cross-reference matrix of technique × OS × detection method × bypass method
- Per-technique reliability ratings and false-positive notes
- Tool compatibility chart (GDB, x64dbg, WinDbg, Frida, ScyllaHide)

### Quick bypass picks

| Detection Class | First Bypass | Backup |
|---|---|---|
| ptrace-based (Linux) | `LD_PRELOAD` hook `ptrace()` → return 0 | Kernel module to hide tracer |
| PEB.BeingDebugged (Windows) | Patch PEB byte at `fs:[0x30]+0x2` | ScyllaHide auto-patch |
| Timing check (rdtsc) | Conditional BP after rdtsc, fix registers | Frida hook `rdtsc` return |
| IsDebuggerPresent | NOP the call / hook return 0 | x64dbg built-in hide |
| INT 2D / UD2 exception | Set VEH to handle gracefully | TitanHide driver |

---

## 1. LINUX ANTI-DEBUG TECHNIQUES

### 1.1 ptrace(PTRACE_TRACEME)

The classic self-attach: a process calls `ptrace(PTRACE_TRACEME, 0, 0, 0)`. If a debugger is already attached, the call fails (returns -1).

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    exit(1); // debugger detected
}
```

**Bypass methods**:

| Method | How |
|---|---|
| `LD_PRELOAD` shim | Compile shared lib: `long ptrace(int r, ...) { return 0; }` and set `LD_PRELOAD` |
| Binary patch | NOP the `ptrace` call or patch return value check |
| GDB catch | `catch syscall ptrace` → modify `$rax` to 0 on return |
| Kernel module | Hook `sys_ptrace` to allow multiple tracers |

### 1.2 /proc/self/status — TracerPid

```c
FILE *f = fopen("/proc/self/status", "r");
// parse TracerPid: if non-zero → debugger attached
```

**External lab reference**: FUSE or `LD_PRELOAD` interposition can test this branch. ZhiyuGo cannot mount filesystems or hook functions; require supplied trace evidence.

### 1.3 Timing Checks (rdtsc / clock_gettime)

Measures elapsed time between two points; debugger single-stepping causes noticeable delay.

```asm
rdtsc
mov ebx, eax       ; save low 32 bits
; ... protected code ...
rdtsc
sub eax, ebx
cmp eax, 0x1000    ; threshold
ja  debugger_detected
```

**External lab reference**: a debugger can alter the post-`rdtsc` value, while Frida can instrument the timing function. The current runtime provides neither capability; only analyze supplied traces and patched-artifact evidence.

### 1.4 Signal-Based Detection (SIGTRAP)

```c
volatile int caught = 0;
void handler(int sig) { caught = 1; }
signal(SIGTRAP, handler);
raise(SIGTRAP);
if (!caught) exit(1); // debugger swallowed the signal
```

When a debugger is attached, `SIGTRAP` may be consumed instead of reaching the handler. **External lab reference**: GDB signal forwarding can test this hypothesis, but the current runtime cannot control a debugger; require supplied trace evidence.

### 1.5 /proc/self/maps & LD_PRELOAD Detection

Checks for injected libraries or memory regions characteristic of debuggers/instrumentation.

```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(buf, sizeof(buf), f)) {
    if (strstr(buf, "frida") || strstr(buf, "LD_PRELOAD"))
        exit(1);
}
```

**External lab reference**: API hooking or an instrumented library can test this check. ZhiyuGo cannot hook functions or alter a Frida agent; require supplied trace and patched-artifact evidence.

### 1.6 Environment Variable Checks

Some protections check for `LD_PRELOAD`, `LINES`, `COLUMNS` (set by GDB's terminal), or debugger-specific env vars.

**External lab reference**: environment normalization or `getenv()` instrumentation can test this branch. ZhiyuGo cannot alter a process environment or hook functions; require supplied trace evidence.

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 2. WINDOWS ANTI-DEBUG TECHNIQUES
- 3. ADVANCED MULTI-LAYER TECHNIQUES
- 4. COUNTERMEASURE TOOLS
- 5. SYSTEMATIC BYPASS METHODOLOGY
- 6. DECISION TREE
- 7. CTF & REAL-WORLD PATTERNS
- 8. QUICK REFERENCE — BYPASS CHEAT SHEET
