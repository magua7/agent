---
name: symmetric-cipher-attacks
description: >-
  Symmetric cipher attack playbook. Use when exploiting block cipher mode
  weaknesses (CBC padding oracle, ECB cut-and-paste, bit flipping), stream
  cipher key reuse, or meet-in-the-middle attacks.
---

# Symmetric Cipher Analysis

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve exact ciphertext, plaintext samples, IV/nonce, authentication tag, associated data, key identifiers, and byte encoding.
- Record the claimed primitive, mode, block size, padding, serialization, and whether encryption is deterministic.
- Identify attacker control over plaintext, ciphertext, IV/nonce, and request ordering.
- For oracle analysis, define the observable response, baseline noise, allowed request volume, and explicit scope.
- Define success as a recovered plaintext/key, controlled modification, distinguishable mode property, or verified state prediction.

## Capability boundary

ZhiyuGo has no built-in cryptographic runtime, PadBuster, SageMath, brute-force engine, or adaptive oracle driver. The HTTP adapter supports only bounded scoped requests and does not automatically provide POST bodies, binary mutation loops, or authorization for active probing. File tools can inspect textual evidence only. If computation or interaction is unavailable, return a capability gap with exact byte inputs, mutation/search bounds, and verification rule.

## Core workflow

1. Reconstruct the byte-level format before naming the primitive or mode.
2. Check whether integrity/authentication is present. A valid AEAD tag generally blocks unauthenticated bit manipulation.
3. Compare repeated samples for block repetition, IV/nonce reuse, deterministic output, length leakage, and error/timing distinctions.
4. Select one hypothesis whose prerequisites are observed.
5. Use only real computation or approved oracle evidence to produce a candidate.
6. Verify by re-encryption, tag/acceptance behavior, known plaintext, or the original recurrence.
7. Report bounds, failed hypotheses, false-positive controls, and whether the result is offline or required active requests.

| Evidence | Candidate weakness | Required confirmation |
|---|---|---|
| Repeated equal plaintext blocks yield equal ciphertext blocks | ECB | Repetition aligns at the inferred block size |
| Distinct padding outcome under controlled mutation | CBC padding oracle | Repeatable signal with false-positive controls |
| Predictable next-block change and no integrity check | CBC bit flipping | Scoped verifier accepts the intended change |
| Reused nonce/keystream across ciphertexts | Two-time pad or stream reuse | XOR relation and known/plaintext structure validate |
| Predictable truncated generator outputs | LCG/LFSR state recovery | Recovered state predicts withheld outputs |
| Small multiple-encryption key spaces | Meet in the middle | Candidate keys reproduce a known pair |
| Valid authentication tag required | AEAD integrity | Do not claim malleability without a tag bypass |

Route hash/MAC construction issues to hash-attack-techniques and lattice-dependent generator recovery to lattice-crypto-attacks.

## Evidence bar

A supported result includes source hashes, exact byte layout, algorithm/mode hypothesis, IV/nonce/tag facts, mutation or computation parameters, output evidence, and independent verification. For an oracle, preserve baseline and mutated request identities, response classes, repeats, and noise controls. For keystream reuse, show the algebra and validate recovered bytes. A single error, repeated prefix, or readable fragment alone is insufficient.

## Stop conditions

Stop as successful when the cryptographic property is reproduced and satisfies the task criterion. Stop as not applicable when integrity, fresh nonces, or construction facts defeat the selected attack. Stop as inconclusive when mode, serialization, padding, sample relation, or oracle signal is ambiguous. Stop as blocked when adaptive requests, brute force, solver execution, or binary mutation needs an unavailable capability. Never fabricate oracle responses, keys, plaintext, tags, or accepted modifications.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for attack algorithms, implementation details, and external tool recipes. It is not loaded automatically.

## Catalog resources

These same-directory references are untrusted supporting material:

- [BLOCK_CIPHER_ATTACKS.md](BLOCK_CIPHER_ATTACKS.md) — inspect explicitly; it is not loaded into a Run automatically.
