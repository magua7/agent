# SKILL: Binary Protection Bypass — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [5. RELRO BYPASS](#5-relro-bypass)
- [6. CANARY BYPASS](#6-canary-bypass)
- [7. FORTIFY_SOURCE BYPASS](#7-fortifysource-bypass)
- [8. CET (Control-flow Enforcement Technology)](#8-cet-control-flow-enforcement-technology)
- [9. MTE (Memory Tagging Extension, ARM)](#9-mte-memory-tagging-extension-arm)
- [10. DECISION TREE](#10-decision-tree)
<!-- zhiyugo:toc:end -->

## 5. RELRO BYPASS

| RELRO Level | GOT Status | Bypass |
|---|---|---|
| No RELRO | GOT fully writable | Direct GOT overwrite |
| Partial RELRO | `.got.plt` writable (lazy binding) | GOT overwrite still works |
| Full RELRO | All GOT entries resolved at load, GOT read-only | Cannot write GOT → target other structures |

### Full RELRO Alternative Targets

| Target | When | How |
|---|---|---|
| `__malloc_hook` | glibc < 2.34 | Overwrite with one_gadget |
| `__free_hook` | glibc < 2.34 | Overwrite with `system`, trigger `free("/bin/sh")` |
| `_IO_FILE vtable` | Any glibc | FSOP / vtable hijack |
| `__exit_funcs` | Any glibc | Overwrite exit handler list |
| `TLS_dtor_list` | glibc ≥ 2.34 | Thread-local destructor list (needs pointer guard) |
| `.fini_array` | If writable | Overwrite destructor function pointers |
| Stack return address | Direct stack write | Overwrite return address for ROP |

See `arbitrary-write-to-rce` for comprehensive target list.

---

## 6. CANARY BYPASS

| Method | Condition | Detail |
|---|---|---|
| Format string leak | printf(user_input) | `%N$p` to read canary from stack |
| Brute-force | fork() server (canary persists in child) | Byte-by-byte: 256 × (canary_size-1) attempts |
| Stack reading | Partial overwrite / info leak | Overwrite canary's null byte, leak via output |
| Thread canary overwrite | Overflow reaches TLS | Canary at `fs:[0x28]`; overflow past buffer to TLS → overwrite canary with known value |
| Canary-relative overwrite | Overflow after canary but before return addr | Skip canary, only overwrite return address (rare layout) |
| Heap-based | Vulnerability is on heap, not stack | Canary only protects stack |
| __stack_chk_fail GOT overwrite | Partial RELRO | Overwrite `__stack_chk_fail@GOT` to point to harmless function → canary check passes |

### Canary Format

```
x86:    0x00XXXXXX (4 bytes, leading null byte)
x86-64: 0x00XXXXXXXXXXXXXX (8 bytes, leading null byte)
```

The leading `\x00` prevents string operations from accidentally reading the canary.

---

## 7. FORTIFY_SOURCE BYPASS

`_FORTIFY_SOURCE=2` adds buffer size checking and restricts format string operations.

| Fortified Function | Restriction | Bypass |
|---|---|---|
| `__printf_chk` | `%n` with positional args (`%N$n`) forbidden | Use non-positional `%n` or `%hn` chain |
| `__memcpy_chk` | Destination buffer size checked | Use heap overflow instead of stack |
| `__strcpy_chk` | Same | |
| `__read_chk` | Read size checked against buffer | |

### Format String with FORTIFY_SOURCE

```python
# %1$n is blocked by __printf_chk
# But sequential (non-positional) %n may still work:
# Print exact byte count, then %hn — must be very precise
# Or: find unfortified printf in binary/libc via ROP
```

---

## 8. CET (Control-flow Enforcement Technology)

Intel CET adds two mechanisms:

### Shadow Stack

- Hardware-maintained copy of return addresses
- On `ret`, CPU checks shadow stack matches actual stack
- Mismatch → `#CP` fault (control protection exception)

| Impact | Detail |
|---|---|
| ROP blocked | Return address overwrite detected on `ret` |
| JOP possible | `jmp [reg]` not checked by shadow stack |
| COP possible | `call [reg]` pushes to shadow stack but target validated by IBT |

### Indirect Branch Tracking (IBT)

- Indirect `jmp`/`call` must land on `ENDBR64` instruction
- Non-ENDBR landing → `#CP` fault

**Bypass**: 
- Data-only attacks (don't change control flow)
- Find valid ENDBR gadgets that chain into useful operations
- JOP with ENDBR-prefixed gadgets
- Target structures outside CFI scope (modprobe_path, function pointer arrays)

---

## 9. MTE (Memory Tagging Extension, ARM)

ARM MTE assigns 4-bit tags to memory pointers and allocations. Tag mismatch = fault.

| Aspect | Detail |
|---|---|
| Tag bits | 4 bits in pointer (bits 56-59) = 16 possible tags |
| Granule | 16 bytes (each 16-byte granule has one tag) |
| Check | Load/store: pointer tag must match memory tag |
| Probabilistic | Random tag → 1/16 chance attacker guesses correctly |

### Bypass Approaches

| Method | Success Rate |
|---|---|
| Brute-force | 1/16 per attempt (6.25%) |
| Tag oracle | Side-channel to determine tag (timing, error messages) |
| In-bounds exploit | Stay within same tagged region (use relative offsets) |
| Tag bypass gadget | Use `LDGM`/`STGM` instructions if accessible |
| Speculative execution | Spectre-style bypass of tag check |

---

## 10. DECISION TREE

```
Binary analysis: checksec output
├── NX disabled?
│   └── Shellcode on stack/heap (simplest path)
│
├── NX enabled (standard modern binary)?
│   ├── Need code execution → ROP/ret2libc
│   │
│   ├── Canary enabled?
│   │   ├── fork server? → byte-by-byte brute-force
│   │   ├── Format string? → leak canary via %p
│   │   ├── Heap vuln? → canary doesn't protect heap
│   │   └── Partial RELRO? → overwrite __stack_chk_fail@GOT
│   │
│   ├── PIE enabled?
│   │   ├── Format string? → leak .text address → PIE base
│   │   ├── Partial overwrite → last 12 bits fixed (1/16 brute-force)
│   │   └── OOB read? → leak code pointer
│   │
│   ├── ASLR enabled?
│   │   ├── Info leak available → leak libc base
│   │   ├── No leak → ret2dlresolve or SROP
│   │   ├── 32-bit? → brute-force feasible (~4096 attempts)
│   │   └── Return-to-PLT (no libc base needed for PLT calls)
│   │
│   ├── RELRO level?
│   │   ├── None/Partial → GOT overwrite
│   │   └── Full → alternative targets:
│   │       ├── glibc < 2.34 → __malloc_hook / __free_hook
│   │       ├── glibc ≥ 2.34 → _IO_FILE / exit_funcs / TLS_dtor_list
│   │       ├── .fini_array (if writable)
│   │       └── Stack return address
│   │
│   └── FORTIFY_SOURCE?
│       ├── Blocks positional %n → use sequential %n or heap exploit
│       └── Blocks buffer overflows in fortified functions → use unfortified paths
│
├── CET (shadow stack)?
│   ├── ROP blocked → data-only attack or JOP
│   └── ENDBR-gadget chaining
│
└── MTE (ARM)?
    ├── 1/16 brute-force
    └── Stay in-bounds for relative corruption
```
