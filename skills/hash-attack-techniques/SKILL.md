---
name: hash-attack-techniques
description: >-
  Hash attack playbook. Use when exploiting length extension, MD5/SHA1
  collisions, HMAC timing leaks, birthday attacks, or hash-based proof
  of work in CTF and authorized testing scenarios.
---

# Hash Attack Techniques

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Record the exact algorithm, digest encoding, message bytes, serialization, delimiter rules, salt or nonce, and construction order when known.
- State which values are attacker-controlled, which are secret, any secret-length bounds, and whether an oracle or verifier is available.
- For collision tasks, retain both source artifacts and any required prefix constraints.
- For timing analysis, retain repeated raw measurements and the collection conditions.
- Define success precisely: accepted forgery, two distinct colliding artifacts, recovered parameter, or proof-of-work threshold.

Never assume that a displayed hexadecimal value is a hash or that a keyed construction is prefix-MAC.

## Capability boundary

ZhiyuGo has no built-in Python runtime, HashPump, HashClash, hashcat, timing harness, or high-volume brute-force capability. Bounded file tools may inspect scoped text artifacts but do not execute cryptanalysis. Online oracle requests also require a separately available and approved capability. If the necessary computation is unavailable, return a capability gap with the algorithm, input encoding, search bound, and validation rule.

## Core workflow

1. Preserve byte-exact inputs and reconstruct the serialization before analyzing the primitive.
2. Classify the construction: plain digest, secret-prefix MAC, HMAC, password hash, proof of work, or signature prehash.
3. Reject inapplicable attacks from construction facts before estimating cost.
4. Select the cheapest hypothesis whose prerequisites are all present.
5. Produce a candidate only through real computation or supplied tool evidence.
6. Verify with the original acceptance rule or an independent local recomputation.
7. Report unsuccessful branches and complexity bounds; do not promote a theoretical weakness to an exploit.

| Construction or signal | Candidate analysis | Critical prerequisite |
|---|---|---|
| MD5/SHA-1/SHA-2 of secret-prefix plus message | Length extension | Full digest, exact message bytes, plausible secret length |
| HMAC or SHA-3/Keccak | Do not use length extension | Construction must be confirmed |
| Two unconstrained files may differ | Identical-prefix collision | Collision-capable algorithm and real generated pair |
| Chosen semantic prefixes must remain | Chosen-prefix collision | Dedicated computation and both verified outputs |
| Early-exit comparison with repeatable latency | Timing analysis | Sufficient samples and controlled noise |
| Truncated digest or leading-zero target | Birthday search or proof of work | Explicit bit target and feasible search bound |
| Stored password digest | Password-audit workflow, not automatic cracking | Explicit authorization and dedicated capability |

Route RSA signature/hash interactions to rsa-attack-techniques and key-derivation or MAC composition issues to symmetric-cipher-attacks.

## Evidence bar

For a forgery, preserve original and forged byte strings, old and new digests, assumed secret length, and verifier acceptance. For a collision, prove the artifacts differ byte-for-byte and independently hash to the same value. For timing, provide sample count, distribution or effect size, controls, and reproducibility. For proof of work, provide the candidate and an independent digest/threshold check. A tool banner, theoretical complexity claim, or unverified digest is not sufficient.

## Stop conditions

Stop as successful only when the requested property is independently reproduced. Stop as not applicable when the construction defeats the proposed method, such as HMAC against length extension. Stop as inconclusive when serialization, algorithm, secret-length range, timing quality, or verifier behavior is unknown. Stop as blocked when collision generation, brute force, statistical testing, or oracle access requires an unavailable capability. Never fabricate a digest, collision, accepted request, or timing result.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for algorithms, scripts, complexity notes, and attack variants. The current Run does not load it automatically.
