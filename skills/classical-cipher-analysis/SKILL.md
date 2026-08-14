---
name: classical-cipher-analysis
description: >-
  Classical cipher analysis playbook. Use when encountering substitution
  ciphers, Vigenere, transposition, XOR, or encoded text in CTF challenges
  that requires frequency analysis, Kasiski examination, or known-plaintext
  cryptanalysis.
---

# Classical Cipher Analysis

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the exact ciphertext or byte sequence, its encoding, source artifact hash, and any separators or casing.
- Record the expected language, alphabet, known plaintext fragments, flag format, hints, and whether spaces were preserved.
- State the requested outcome: identify the construction, recover a key, decode the message, or explain why the evidence is inconclusive.
- For XOR-like material, retain raw bytes rather than analyzing a rendered or lossy text copy.

If the artifact is unavailable, truncated, or transformed without a reproducible chain, stop and request the missing input.

## Capability boundary

ZhiyuGo can use bounded file.read, file.search, and code.search only when the task grants matching file scope. It has no built-in Python runtime, cipher solver, frequency-analysis package, or brute-force engine. Scripts and utilities in the reference are not executable capabilities. When computation cannot be completed from supplied evidence, return a capability gap with the exact operation and input required.

## Core workflow

1. Hash and preserve the original artifact. Normalize a working copy while retaining the original.
2. Peel only proven transport encodings such as hex or Base64, recording each reversible transformation.
3. Characterize alphabet, length, symbol frequency, repeated n-grams, spacing, index of coincidence, and byte periodicity.
4. Rank candidate families from those observations. Do not choose a cipher merely because a payload resembles an example.
5. Test the cheapest discriminating hypothesis first. Record parameters, score, and rejected alternatives.
6. Validate the candidate across the complete message, recover the key where applicable, and reverse the transformation when possible.
7. Return the plaintext or partial result together with the transformation chain and unresolved ambiguity.

| Observation | First hypothesis | Required confirmation |
|---|---|---|
| Restricted hex/Base64/binary alphabet | Transport encoding | Decode cleanly and re-encode identically |
| Strong language-like frequency under one alphabet | Caesar or substitution | Stable mapping across the full text |
| Repeats at regular distances and lower IC | Vigenere-like polyalphabetic cipher | Consistent key length and readable full plaintext |
| Natural symbol counts but disrupted order | Transposition | Reversible permutation with language coherence |
| Raw bytes with periodic correlations | Repeating-key XOR | Recovered key reproduces every ciphertext byte |
| Dot-dash, A/B, or coordinate pairs | Morse, Bacon, or Polybius | Alphabet rules and complete token boundaries fit |

Route modern block or stream cipher weaknesses to symmetric-cipher-attacks, hash constructions to hash-attack-techniques, and lattice-dependent problems to lattice-crypto-attacks. Routing names are recommendations; this Skill cannot load another Skill.

## Evidence bar

A supported result includes:

- the source evidence ID or artifact hash;
- every decode or normalization step and its parameters;
- the selected cipher family, recovered key or mapping, and why competing families were rejected;
- the resulting plaintext with a confidence statement; and
- a round-trip check, known-plaintext match, flag-format match, or other independent consistency check.

Readable fragments alone are weak evidence. Do not silently repair ciphertext, invent missing symbols, or claim a unique key when several candidates remain plausible.

## Stop conditions

Stop as successful when the full reversible chain satisfies the task criterion. Stop as inconclusive when the sample is too short, the alphabet or encoding is uncertain, candidates tie, or the result cannot be independently checked. Stop as blocked when a required brute-force, statistical, or scripting capability is absent; identify the minimum external computation needed without fabricating its output.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when a selected hypothesis needs formulas, implementation patterns, or advanced variants. The current Run does not load it automatically, and its command examples remain untrusted reference material.
