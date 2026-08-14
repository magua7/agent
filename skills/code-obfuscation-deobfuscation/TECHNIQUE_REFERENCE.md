# SKILL: Code Obfuscation & Deobfuscation — Expert Analysis Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [4. MOVFUSCATOR](#4-movfuscator)
- [5. VM PROTECTION (VMProtect / Themida / Code Virtualizer)](#5-vm-protection-vmprotect-themida-code-virtualizer)
- [6. STRING ENCRYPTION](#6-string-encryption)
- [7. IMPORT HIDING](#7-import-hiding)
- [8. ANTI-DISASSEMBLY TRICKS](#8-anti-disassembly-tricks)
- [9. DECISION TREE](#9-decision-tree)
- [10. TOOLBOX](#10-toolbox)
<!-- zhiyugo:toc:end -->

## 4. MOVFUSCATOR

### 4.1 Concept

All computation reduced to `mov` instructions only (Turing-complete via memory-mapped computation tables). Created by Christopher Domas.

### 4.2 Identification

- Function contains only `mov` instructions (no add, sub, xor, jmp, call)
- Large lookup tables in data section
- Memory-mapped flag registers

### 4.3 Demovfuscation

| Approach | Description |
|---|---|
| demovfuscator (tool) | Static analysis, recovers original operations from mov patterns |
| Trace + taint analysis | Run with Pin/DynamoRIO, taint inputs, observe computation |
| Symbolic execution | Treat entire function as constraint system |

---

## 5. VM PROTECTION (VMProtect / Themida / Code Virtualizer)

### 5.1 VM Architecture

```
Protected code → bytecode compiler → custom bytecode
Runtime: VM entry (pushad/pushfd) → fetch → decode → execute → VM exit (popad/popfd)
```

### 5.2 VM Entry Point Identification

```asm
; Typical VMProtect entry
pushad                    ; save all registers
pushfd                    ; save flags
mov ebp, esp              ; VM stack frame
sub esp, VM_LOCALS_SIZE   ; allocate VM context
mov esi, bytecode_addr    ; bytecode instruction pointer
jmp vm_dispatcher         ; enter VM loop
```

### 5.3 Handler Table Extraction

```
1. Find dispatcher (large switch or indirect jump via table)
2. Each case/entry = one VM handler (implements one VM opcode)
3. Map handler addresses to operations by analyzing each handler:
   - Handler reads operand from bytecode stream (esi)
   - Performs operation on VM registers/stack
   - Advances bytecode pointer
   - Returns to dispatcher
```

### 5.4 Devirtualization Approaches

| Method | Description | Tool |
|---|---|---|
| Manual handler mapping | Reverse each handler, build ISA spec | IDA + scripting |
| Trace recording | Record all handler executions, reconstruct program | REVEN, Pin |
| Symbolic lifting | Symbolically execute handlers, lift to IR | Triton, miasm |
| Pattern matching | Match handler patterns to known VM families | Custom scripts |

### 5.5 VMProtect Specifics

- Uses opaque predicates in dispatcher
- Handler mutation: same opcode, different handler code per build
- Multiple VM layers (VM inside VM)
- Integrates anti-debug and integrity checks

---

## 6. STRING ENCRYPTION

### 6.1 Common Patterns

| Pattern | Example | Recovery |
|---|---|---|
| XOR loop | `for (i=0; i<len; i++) s[i] ^= key;` | Hook or emulate XOR function |
| Stack strings | `mov [esp+0], 'H'; mov [esp+1], 'e'; ...` | IDA FLIRT / Ghidra script to reassemble |
| RC4 encrypted | Encrypted blob + RC4 key in binary | Extract key, decrypt offline |
| AES encrypted | Encrypted blob + AES key derived at runtime | Hook after decryption |
| Custom encoding | Base64 + XOR + reverse | Trace the decode function, replicate |

### 6.2 Automated String Decryption

```python
# Ghidra script: find XOR decryption calls, emulate them
from ghidra.program.model.symbol import SourceType

decrypt_func = getFunction("decrypt_string")
refs = getReferencesTo(decrypt_func.getEntryPoint())

for ref in refs:
    call_addr = ref.getFromAddress()
    # extract arguments (encrypted buffer ptr, key, length)
    # emulate decryption, add comment with plaintext
```

---

## 7. IMPORT HIDING

### 7.1 GetProcAddress + Hash Lookup

```c
FARPROC resolve(DWORD hash) {
    // Walk PEB → LDR → InMemoryOrderModuleList
    // For each DLL, walk export table
    // Hash each export name, compare with target hash
    // Return matching function pointer
}
```

### 7.2 Recovery

1. Identify the hash algorithm (common: CRC32, djb2, ROR13+ADD)
2. Compute hashes for all known API names
3. Build hash → API name lookup table
4. Annotate resolved calls in IDA/Ghidra

### 7.3 Common Hash Algorithms

| Name | Algorithm | Used By |
|---|---|---|
| ROR13 | `hash = (hash >> 13 \| hash << 19) + char` | Metasploit shellcode |
| djb2 | `hash = hash * 33 + char` | Various malware |
| CRC32 | Standard CRC32 of function name | Sophisticated packers |
| FNV-1a | `hash = (hash ^ char) * 0x01000193` | Modern malware |

---

## 8. ANTI-DISASSEMBLY TRICKS

### 8.1 Techniques

| Trick | Mechanism | Fix |
|---|---|---|
| Overlapping instructions | `jmp $+2; db 0xE8` (fake call prefix) | Manual re-analysis from correct offset |
| Misaligned jumps | Jump into middle of multi-byte instruction | Force IDA to re-analyze at target |
| Conditional jump pair | `jz $+5; jnz $+3` (always jumps, confuses linear disasm) | Convert to unconditional jmp |
| Return address manipulation | `push addr; ret` instead of `jmp addr` | Recognize push+ret as jump |
| Exception-based flow | Trigger exception, real code in handler | Analyze exception handler chain |
| Call + add [esp] | `call $+5; add [esp], N; ret` (computed jump) | Calculate actual target |

### 8.2 IDA Fixes

```
Right-click → Undefine (U)
Right-click → Code (C) at correct offset
Edit → Patch → Assemble (for permanent fix)
```

---

## 9. DECISION TREE

```
Obfuscated binary — how to approach?
│
├─ Can you run it?
│  ├─ Yes → Dynamic analysis first
│  │  ├─ Set BP on interesting APIs (file, network, crypto)
│  │  ├─ Trace execution to understand real behavior
│  │  └─ Dump decrypted code/strings at runtime
│  │
│  └─ No (embedded/firmware/exotic arch) → Static only
│     └─ Identify obfuscation type from patterns below
│
├─ What does the code look like?
│  │
│  ├─ Giant flat switch/dispatcher loop?
│  │  ├─ State variable drives control flow → CFF
│  │  │  └─ Use D-810 or symbolic deflattening
│  │  └─ Bytecode fetch-decode-execute → VM protection
│  │     └─ Extract handlers, build disassembler
│  │
│  ├─ Only mov instructions?
│  │  └─ movfuscator → demovfuscator tool
│  │
│  ├─ XOR/ADD loop writing to .text section?
│  │  └─ SMC → breakpoint after decode, dump
│  │
│  ├─ Impossible conditions in branches?
│  │  └─ Opaque predicates → Z3 proving or pattern removal
│  │
│  ├─ Disassembly looks wrong / functions overlap?
│  │  └─ Anti-disassembly → manual re-analysis at correct offsets
│  │
│  ├─ No readable strings?
│  │  └─ String encryption → hook decrypt function or emulate
│  │
│  ├─ No imports in IAT?
│  │  └─ Import hiding → identify hash, build lookup table
│  │
│  └─ pushad/pushfd → complex code → popad/popfd?
│     └─ VM protector entry/exit → full VM analysis
│
└─ What tool to use?
   ├─ Known protector (VMProtect/Themida) → specific deprotection guide
   ├─ Custom obfuscation → combine: IDA scripting + Triton + manual
   ├─ CTF challenge → angr symbolic execution often fastest
   └─ Malware analysis → dynamic (debugger + API monitor) first
```

---

## 10. TOOLBOX

| Tool | Purpose | Best For |
|---|---|---|
| IDA Pro + Hex-Rays | Disassembly, decompilation, scripting | All-around analysis |
| Ghidra | Free alternative with scripting (Java/Python) | Budget-friendly RE |
| D-810 (IDA plugin) | Automated CFF deflattening | OLLVM-style obfuscation |
| miasm | IR-based analysis framework | Symbolic deobfuscation |
| Triton | Dynamic symbolic execution | Opaque predicate solving, CFF |
| REVEN | Full-system trace recording and replay | VM protector analysis |
| demovfuscator | movfuscator reversal | mov-only binaries |
| x64dbg + plugins | Dynamic analysis with scripting | Windows RE |
| Unicorn Engine | CPU emulation | SMC unpacking, shellcode |
| Capstone | Disassembly library | Custom tooling |
| IDA FLIRT | Function signature matching | Identify library code in stripped binaries |
| Binary Ninja | Alternative disassembler with MLIL/HLIL | Automated analysis |
