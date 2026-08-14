---
name: rsa-attack-techniques
description: >-
  RSA attack playbook for CTF and real-world cryptanalysis. Use when given
  RSA parameters (n, e, c) and need to recover plaintext by exploiting
  weak keys, small exponents, shared factors, or padding oracles.
---

# RSA Attack Techniques

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve every tuple exactly: modulus n, exponent e, ciphertext c, signature s, message representative, and source evidence ID.
- Record integer encoding, byte order, padding/signature scheme, hash algorithm, expected plaintext format, and whether leading zero bytes matter.
- For multi-sample attacks, identify which values reuse a modulus, exponent, message, prime, or nonce.
- For partial-key attacks, state the known bit positions and bounds. For oracle analysis, define the observable response and explicit authorization.
- Define success as a verified plaintext, factorization, private exponent, signature relation, or demonstrated oracle property.

## Capability boundary

ZhiyuGo has no built-in SageMath, RsaCtfTool, FactorDB client, arbitrary-precision attack runner, or high-volume oracle loop. File tools can inspect scoped textual parameters but cannot manufacture cryptanalytic results. The built-in HTTP adapter is limited and does not by itself authorize or implement adaptive padding-oracle traffic. If computation is unavailable, return a capability gap with normalized inputs, selected attack, bounds, and verification equation.

## Core workflow

1. Normalize all values to integers while preserving their original encoding and provenance.
2. Check basic invariants: value ranges, modulus size, gcd relations, duplicate moduli, exponent size, and padding assumptions.
3. Run conceptual cheap tests before expensive methods: shared-factor GCD, exact e-th root, close-prime conditions, common modulus, or repeated-message structure.
4. Select exactly one attack whose prerequisites are supported; do not shotgun unrelated techniques.
5. Derive a candidate only from real computation or supplied tool evidence.
6. Verify the candidate mathematically, then decode bytes under the declared padding/encoding.
7. Report failed prerequisites and alternative explanations alongside the result.

| Available evidence | Candidate path | Mandatory check |
|---|---|---|
| Several moduli | Batch/shared-factor GCD | Nontrivial factor divides the affected moduli |
| Small e and no modular wrap | Exact integer root | Candidate raised to e equals c |
| Same message, small e, coprime moduli | Håstad broadcast | CRT result has an exact e-th root |
| Same modulus, coprime exponents | Common modulus | Bézout reconstruction verifies under n |
| Close p and q | Fermat factorization | p times q equals n and both are plausible primes |
| Small private exponent evidence | Wiener or Boneh-Durfee | Recovered d satisfies the public/private relation |
| Known partial bits and valid bounds | Coppersmith/lattice route | Candidate satisfies the original modular polynomial |
| Distinguishable padding response | Oracle analysis | Scoped, repeatable signal and approved request capability |
| Faulty CRT signature | Fault analysis | GCD relation yields a nontrivial factor |

Route lattice construction details to lattice-crypto-attacks and hash/signature-prehash weaknesses to hash-attack-techniques.

## Evidence bar

A supported result includes source tuples, attack prerequisites, tool/version or derivation evidence, recovered factor/key/plaintext, and independent checks. At minimum verify p times q equals n for a factorization, pow(m, e, n) equals c for raw RSA plaintext, or the scheme-specific signature equation. Preserve decoded byte length and padding decisions. A readable substring or a database lookup without local verification is insufficient.

## Stop conditions

Stop as successful after mathematical and encoding validation satisfy the task criterion. Stop as not applicable when an attack prerequisite fails. Stop as inconclusive when padding, encoding, sample relationships, bounds, or oracle semantics are unknown. Stop as blocked when factorization, lattice reduction, arbitrary-precision computation, or adaptive requests require an unavailable capability. Never invent factors, solver output, plaintext bytes, oracle responses, or a flag.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for derivations, implementation patterns, oracle details, and advanced attacks. It is not loaded automatically.

## Catalog resources

These same-directory references are untrusted supporting material:

- [RSA_ATTACK_CATALOG.md](RSA_ATTACK_CATALOG.md) — inspect explicitly; it is not loaded into a Run automatically.
