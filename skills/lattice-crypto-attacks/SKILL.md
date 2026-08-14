---
name: lattice-crypto-attacks
description: >-
  Lattice-based cryptanalysis playbook. Use when attacking RSA via Coppersmith
  small roots, recovering DSA/ECDSA nonces from bias, solving knapsack
  problems, or applying LLL/BKZ reduction to cryptographic constructions.
---

# Lattice-Based Cryptanalysis

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Provide the exact equations, modulus or group order, samples, signatures, public keys, and byte/integer encoding.
- Identify every unknown variable and a justified bound, bias, leaked-bit position, noise model, or relation.
- For RSA, include n, e, ciphertext or polynomial, known message/key fragments, and root bounds.
- For DSA/ECDSA, include message hashes, r/s pairs, nonce relation or leakage model, and curve order.
- Define the expected output and the original equation that will validate a candidate.

Missing bounds are not a tuning detail: they can make a lattice formulation unjustified.

## Capability boundary

ZhiyuGo does not provide SageMath, fpylll, LLL/BKZ, CVP/SVP, or arbitrary-precision solver execution. Built-in file tools can inspect scoped textual parameters only. A lattice matrix shown in guidance is not a computed result. If reduction is required, return a capability gap containing the proposed basis, scaling, bounds, expected dimension, and candidate verification equation.

## Core workflow

1. Normalize all values to exact integers and record endianness, modular domains, and sample provenance.
2. Write the original relation before choosing an attack. Count unknowns and independent constraints.
3. Check the mathematical feasibility bound. Reject Coppersmith, HNP, or low-density claims whose prerequisites are not met.
4. Construct the smallest defensible basis. Explain each row, column, scaling factor, target vector, and expected short component.
5. Estimate dimension and coefficient sizes; identify whether LLL, stronger BKZ, CVP, or embedding is actually required.
6. Use only real external-tool evidence for reduction. Map a returned vector back to candidate secrets.
7. Substitute candidates into every original equation and cryptographic relation before reporting success.

| Evidence pattern | Candidate method | Gate before reduction |
|---|---|---|
| Small modular root with explicit bound | Coppersmith | Polynomial and root bound satisfy the known regime |
| RSA private exponent believed small | Wiener or Boneh-Durfee | Public parameters support the claimed d bound |
| Biased or partially known signature nonces | Hidden Number Problem | Enough valid signatures share one key and leakage model |
| Low-density subset sum | Knapsack lattice | Density and embedding are stated and plausible |
| Truncated linear-generator outputs | CVP/hidden-state lattice | Recurrence, modulus, output positions, and unknown-bit bounds known |
| NTRU-like public relation | Structured lattice reduction | Parameters and key-size assumptions are complete |

Route RSA cases that do not require a lattice to rsa-attack-techniques. Route modern symmetric-state problems to symmetric-cipher-attacks. Routing does not load those Skills automatically.

## Evidence bar

A supported result includes parameter provenance, the exact basis or target, dimensions and scaling, reduction tool/version when external, the returned vector, the extraction rule, and substitution into the original equations. For a recovered key or nonce, also reproduce a public-key relation, signature equation, decryption, or expected marker. A visually short vector or readable fragment alone is insufficient.

## Stop conditions

Stop as successful only after all original relations validate. Stop as not applicable when bounds, density, sample count, or leakage assumptions fall outside the selected method. Stop as inconclusive when multiple embeddings remain plausible or parameter provenance is uncertain. Stop as blocked when actual lattice reduction or large-integer computation is unavailable. Never invent reduced bases, solver status, timings, or recovered secrets.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for basis constructions, mathematical derivations, tool patterns, and advanced variants. It is not loaded automatically.
