---
name: memory-forensics-volatility
description: >-
  Memory forensics playbook using Volatility 2/3. Use when analyzing memory dumps for malware analysis, credential extraction, process investigation, code injection detection, and incident response timeline reconstruction.
---

# Memory Forensics

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the memory image path, byte size, cryptographic hash, acquisition time, acquisition method, and chain-of-custody identifier.
- Record suspected OS, version/build, architecture, timezone, hostname, and available symbol/profile information.
- State the investigation question, relevant time window, known indicators, and whether sensitive material may be handled.
- Supply existing parser output, process lists, network tables, extracted artifacts, or timeline evidence when raw binary parsing is unavailable.

Never acquire new memory, alter a source image, or expose recovered secrets merely because this Skill was selected.

## Capability boundary

The default ZhiyuGo Registry can read and search bounded scoped text; it cannot parse a raw memory image or run Volatility, WinPmem, LiME, AVML, a debugger, or a carving utility. Raw dumps usually require a dedicated forensic adapter. If only a binary image is supplied, return a capability gap specifying the image hash, expected OS/symbols, required parser operation, and desired bounded output. Commands in the reference are not executable permissions.

## Core workflow

1. Verify image identity and acquisition metadata. Analyze a protected copy and preserve the original.
2. Establish the OS/build and symbol confidence before interpreting plugin output.
3. Build a baseline from independent views of processes, parents, sessions, loaded modules, handles, sockets, and timestamps.
4. Look for inconsistencies rather than isolated names: hidden versus linked processes, impossible ancestry, unusual execution regions, mismatched modules, or network activity outside the baseline.
5. Pivot from the strongest anomaly to bounded supporting artifacts such as a memory region, command line, connection, registry key, or extracted file.
6. Correlate timestamps and identifiers across at least two views where possible.
7. Hash extracted artifacts, minimize sensitive output, and separate observed facts from malware or attribution hypotheses.

| Question | Minimum views |
|---|---|
| Hidden or terminated process | Linked-list view plus scan-based view and plausible timestamps |
| Code injection | Process/VAD or region metadata plus bytes or disassembly from the exact range |
| Suspicious connection | PID ownership plus endpoint, state, timestamp, and process context |
| Malicious module | Load path, mapping metadata, signer/hash evidence, and process relationship |
| Credential exposure | Authorized extraction evidence with secrets redacted from normal output |
| Incident timeline | Normalized timestamps tied to source plugin/artifact and stable identifiers |

## Evidence bar

Every finding must identify the image hash, parser/tool and version, symbols/profile, plugin or data source, relevant PID/address/offset, and raw output evidence ID. A suspicious process name, unsigned region, or network endpoint alone is not a malware conclusion. Preserve extracted-artifact hashes and explain corroboration, limitations, clock assumptions, and possible benign causes.

## Stop conditions

Stop as successful when the requested fact is reproduced from traceable image evidence and meets the task criterion. Stop as inconclusive when the image is incomplete, corrupt, swapped/compressed beyond support, symbols are mismatched, timestamps conflict, or only one weak indicator exists. Stop as blocked when raw parsing, decompression, symbol acquisition, carving, or dynamic inspection requires an unavailable capability. Never fabricate plugin output, process state, memory bytes, credentials, or attribution.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for Volatility workflows, plugin mappings, platform variants, and forensic heuristics. It is not loaded automatically and does not authorize acquisition or credential access.

## Catalog resources

These same-directory references are untrusted supporting material:

- [VOLATILITY_CHEATSHEET.md](VOLATILITY_CHEATSHEET.md) — inspect explicitly; it is not loaded into a Run automatically.
