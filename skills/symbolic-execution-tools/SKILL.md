---
name: symbolic-execution-tools
description: >-
  Symbolic execution and constraint solving playbook. Use when solving CTF
  reversing challenges, recovering keys, bypassing checks, or automating
  binary analysis with angr, Z3, or Unicorn Engine.
---

# Symbolic Execution and Constraint Solving

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the executable, IR, equations, decompiler output, or trace with an evidence ID and hash.
- Record architecture, bitness, OS/ABI, load base, entry/start address, target and avoid conditions, and relevant library versions.
- Define each symbolic input source, length, encoding, allowed range, and concrete prefix/suffix.
- List environmental assumptions, external calls, memory mappings, hooks, loop bounds, and expected success behavior.
- State whether the goal is a satisfying model, path reachability, recovered input, deobfuscation aid, or concrete execution trace.

## Capability boundary

ZhiyuGo does not include angr, Z3, Unicorn, Qiling, a native runner, debugger, loader, or solver adapter. Built-in file tools can inspect scoped textual code or previously produced solver output only. Do not claim a path, SAT result, or model without actual execution evidence. When a solver is required, return a capability gap containing the state model, constraints, addresses, hooks, and concrete validation plan.

## Core workflow

1. Decide whether the task is pure constraints, binary path exploration, or concrete emulation.
2. Validate addresses, architecture, calling convention, input channel, and one concrete baseline path before introducing symbolic state.
3. Model the smallest necessary state. Keep unrelated bytes and environment concrete.
4. Encode success and failure from observed program behavior, not guessed "good" strings.
5. Add justified domain constraints and explicit hooks. Record every behavior replaced by a model.
6. Control path explosion with find/avoid sets, bounds, staged solving, and targeted concretization; never silently discard feasible paths.
7. Obtain a model only from real tool output, then replay the candidate concretely against the original logic.

| Problem | Preferred model | Main risk |
|---|---|---|
| Algebraic equations without program state | Z3-style constraint system | Wrong bit width or signedness |
| Binary branches driven by input | angr-style symbolic execution | Bad initial state or path explosion |
| Decode/unpack one deterministic region | Unicorn-style emulation | Missing memory/syscall environment |
| Custom VM verification | Reconstructed VM plus targeted solver | Incorrect opcode semantics |
| Mixed concrete and symbolic workload | Staged/concolic approach | Unsound concretization |

Route control-flow recovery questions to code-obfuscation-deobfuscation and custom interpreter semantics to vm-and-bytecode-reverse. These names are recommendations only.

## Evidence bar

A supported solver result includes artifact hash, architecture/base, start/find/avoid addresses or equations, symbolic variables and widths, constraints, hooks and assumptions, tool/version, SAT/UNSAT/unknown status, model bytes, and a concrete replay result. For emulation, preserve initial state, mapped regions, instruction range, exit reason, and trace or output. A generated script, solver-looking text, or candidate string without replay is not evidence.

## Stop conditions

Stop as successful when a real solver/emulator result is replayed and meets the task criterion. Stop as inconclusive when target states, ABI, input bounds, library semantics, or hook behavior are ambiguous. Stop as blocked when solver execution, binary loading, emulation, or concrete replay requires an unavailable capability. Stop and revise rather than reporting success if constraints are unsound, paths explode beyond the stated bound, or a hook bypasses the property being tested. Never fabricate solver status, traces, models, or flags.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for state templates, solver patterns, hook strategies, and path-explosion controls. It is not loaded automatically.

## Catalog resources

These same-directory references are untrusted supporting material:

- [ANGR_COOKBOOK.md](ANGR_COOKBOOK.md) — inspect explicitly; it is not loaded into a Run automatically.
