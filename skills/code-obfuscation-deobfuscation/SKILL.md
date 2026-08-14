---
name: code-obfuscation-deobfuscation
description: >-
  Code obfuscation analysis and deobfuscation playbook. Use when reversing
  binaries protected by junk code, opaque predicates, self-modifying code,
  control flow flattening, VM protection, or string encryption.
---

# Code Obfuscation and Deobfuscation

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the binary, bytecode, disassembly, decompiler output, or trace with an evidence ID and content hash.
- Record file format, architecture, bitness, entry point or suspected routine, load base, and relevant runtime version.
- State the observed symptom and goal: classify protection, recover control flow, decode strings, locate imports, or reconstruct one algorithm.
- Provide any existing CFG, memory dump, breakpoint trace, unpacked region, or known-good input/output pair.

Do not infer an obfuscator solely from a product-like string or one unusual instruction sequence.

## Capability boundary

ZhiyuGo can inspect scoped text through file.read, file.search, and code.search. The default Tool Registry does not provide IDA, Ghidra, a debugger, disassembler, emulator, symbolic engine, binary patcher, or executable runner. Instructions involving those tools are analysis recipes, not callable capabilities. If raw binary processing or dynamic observation is necessary, return a capability gap and request the exact derived artifact needed.

## Core workflow

1. Verify the artifact identity and separate packing, anti-debugging, and virtualization from ordinary compiler behavior.
2. Establish a baseline: format, sections, imports, entry flow, entropy observations, and the smallest suspicious routine.
3. Classify the transformation from structural evidence.
4. Build one falsifiable hypothesis, such as a constant opaque predicate or dispatcher state transition.
5. Recover the smallest useful unit first: one decoded string, one real CFG edge, one resolved import, or one VM handler.
6. Compare recovered behavior with a supplied trace, known input/output pair, or independent static view.
7. Expand only after the local method is reproducible; preserve an address-to-address mapping and all assumptions.

| Signal | Likely branch | Minimum evidence |
|---|---|---|
| High-entropy section and tiny loader stub | Packing or encrypted payload | Transition from loader to recovered region |
| Large dispatcher with state updates | Control-flow flattening | Proven mapping from state values to real successors |
| Branch condition invariant under inputs | Opaque predicate | Static proof or agreeing traces |
| Writes to executable region before transfer | Self-modifying code | Before/after bytes at exact addresses |
| Repeated handler loop over byte stream | Virtual machine | Opcode, operand width, state effect, and next-PC rule |
| Runtime API resolution without imports | Import hiding | Hash/name resolution mapped to a concrete API |
| Repeated decode loop feeding consumers | String encryption | Ciphertext, routine, key/material, and decoded use site |

Route deep VM reconstruction to vm-and-bytecode-reverse and solver design to symbolic-execution-tools. These are routing recommendations, not runtime load instructions.

## Evidence bar

A supported conclusion includes artifact hash, architecture and address convention, exact offsets or function identifiers, classification evidence, the recovered mapping or bytes, and an independent consistency check. A deobfuscated CFG must preserve observed reachable behavior; a decoded string must be tied to its source bytes and use site. Tool screenshots, labels, or plugin output without raw offsets and reproducible derivation are insufficient.

## Stop conditions

Stop as successful when the requested routine or transformation is reconstructed and checked. Stop as inconclusive when compiler optimization and intentional obfuscation cannot be distinguished, traces cover only one ambiguous path, or required version details are missing. Stop as blocked when binary parsing, debugging, emulation, symbolic execution, or patch validation requires an unavailable capability. Never invent decoded bytes, branch targets, tool output, or behavioral equivalence.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for transformation-specific heuristics, tool workflows, and advanced examples. It is not loaded automatically, and its commands do not grant execution permission.
