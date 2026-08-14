---
name: vm-and-bytecode-reverse
description: >-
  Custom VM and bytecode reverse engineering playbook. Use when CTF challenges
  or protected software implement custom virtual machines with proprietary
  bytecode, dispatcher loops, or maze-style challenges.
---

# VM and Bytecode Reverse Engineering

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the host binary, bytecode blob, disassembly/decompiler output, or trace with evidence IDs and hashes.
- Record host architecture, file format, load base, dispatcher address, bytecode address/length, and observed entry/exit behavior.
- Identify the suspected VM state: program counter, stack/register file, flags, memory, input/output channels, and termination rule.
- State the goal: identify the VM, map opcodes, disassemble a region, reconstruct validation logic, solve a maze, or verify a candidate input.
- Supply known instruction traces or input/output pairs when available.

## Capability boundary

ZhiyuGo can inspect bounded scoped textual code and prior evidence through file.read/search/code.search. It has no built-in binary loader, IDA/Ghidra, debugger, emulator, tracer, symbolic solver, or script runtime. If opcode extraction, execution, or solver work cannot be performed from supplied textual evidence, return a capability gap with exact offsets, bytes/state required, and a concrete validation plan. Reference scripts are not executable tools.

## Core workflow

1. Confirm a fetch-decode-execute loop exists; distinguish a VM from a large native state machine or ordinary switch.
2. Locate bytecode, program counter updates, dispatcher, handler table, VM state, and halt/error paths.
3. Map one opcode at a time from observed state effects. Record operand width, endianness, stack delta, flags, memory effects, next-PC rule, and confidence.
4. Trace a short known bytecode sequence manually or from real tool evidence to validate the map.
5. Build a deterministic disassembly of only the relevant region. Mark unknown bytes rather than guessing instruction boundaries.
6. Recover control/data flow from input to the success predicate. Use a solver only after opcode semantics are validated.
7. Replay a candidate in the original interpreter or compare a complete state trace before claiming success.

| Pattern | Likely design | Evidence needed |
|---|---|---|
| Loop plus large switch on fetched byte | Switch dispatcher | Case value, consumed bytes, state delta, and next PC |
| Indirect jump through indexed table | Handler-table VM | Table base/index rule and resolved handler addresses |
| Dominant push/pop state changes | Stack VM | Stack direction, cell width, and per-op stack effect |
| Indexed register array | Register VM | Register width/count and operand encoding |
| Encoded handler/state transition | Protected virtualizer | Decryption/dispatch transition from exact addresses |
| Grid state with directional input | Maze/state challenge | Extracted state graph and verified transition rules |

Route commercial-control-flow transformations to code-obfuscation-deobfuscation and well-defined constraint solving to symbolic-execution-tools. These are routing recommendations only.

## Evidence bar

A supported reconstruction includes artifact hashes, address convention, bytecode bounds, dispatcher and handler locations, an opcode table with confidence, operand encoding, and at least one trace showing predicted and observed state agreement. A recovered solution must replay through the original interpreter or match an independently captured success trace. Decompiled pseudocode, mnemonic guesses, or a standalone custom emulator without parity evidence are insufficient.

## Stop conditions

Stop as successful when the requested semantics or candidate are independently replayed and satisfy the task criterion. Stop as inconclusive when instruction boundaries, state layout, self-modification, or handler decoding remain ambiguous. Stop as blocked when binary extraction, tracing, emulation, solver execution, or concrete replay requires an unavailable capability. Stop and revise on any trace divergence; never patch over it with invented semantics. Never fabricate opcodes, state values, solver output, or flags.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for disassembler/emulator patterns, VM variants, maze workflows, and external tool recipes. It is not loaded automatically.
