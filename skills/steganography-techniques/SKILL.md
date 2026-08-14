---
name: steganography-techniques
description: >-
  Steganography detection and extraction playbook. Use when analyzing images (LSB, PNG chunks, JPEG DCT, EXIF), audio (spectrogram, DTMF), files (polyglots, appended data, ADS), and text (whitespace, zero-width, homoglyphs) for hidden data.
---

# Steganography Detection and Extraction

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the original artifact, byte size, cryptographic hash, claimed filename/type, and acquisition source.
- Record the expected flag/marker or investigation question, hints, likely passphrases, and whether nested encodings are expected.
- State whether a lossless copy is available. Screenshots, recompressed images, transcoded audio, and pasted text may destroy the carrier.
- Preserve extracted outputs as separate artifacts with hashes; never overwrite the source.

## Capability boundary

ZhiyuGo can inspect bounded scoped text with file.read/search, but it has no built-in binary parser, image/audio decoder, spectrogram generator, EXIF tool, binwalk, zsteg, steghide, or carving runtime. Code examples and utilities in the reference are not callable tools. If byte-level analysis is required, return a capability gap specifying the artifact hash, suspected carrier, exact operation, and bounded output needed.

## Core workflow

1. Verify the source hash and compare magic bytes, extension, MIME/type evidence, dimensions or duration, and file size.
2. Inspect container structure before guessing passwords: metadata, unexpected chunks/segments, trailing bytes, embedded signatures, frame counts, and declared-versus-actual dimensions.
3. Choose the branch from the native carrier; do not run every extraction family indiscriminately.
4. Extract into a new artifact, recording parameters such as channel, bit plane, byte order, offset, frame, or passphrase source.
5. Identify and hash every output. Re-enter the workflow if an output is another container or encoded text.
6. Validate the final content against structure, known markers, checksums, or a reversible embedding/extraction relation.

| Carrier evidence | First branch | Confirmation |
|---|---|---|
| PNG/BMP with lossless pixels | Channel/bit-plane or chunk analysis | Stable extraction under stated channel/order |
| JPEG with unusual metadata or coefficients | Metadata, appended data, or DCT-aware analysis | Decodable embedded payload tied to source |
| GIF/APNG or suspicious dimensions | Frame/palette/dimension analysis | Hidden frame/region reproduced from container |
| WAV or other lossless audio | Metadata, channels, LSB, spectrogram, or tones | Time/frequency location and decoded sequence |
| Polyglot or trailing signatures | Structural parsing and carving | Exact offsets and extracted artifact hash |
| Text with spacing or look-alike anomalies | Whitespace, zero-width, homoglyph, or acrostic analysis | Explicit symbol mapping and reversible decode |
| Extracted encoded text | Classical-cipher-analysis | Documented handoff; no automatic Skill loading |

## Evidence bar

A supported extraction includes source evidence ID/hash, file-type facts, exact extraction parameters and offsets, output bytes/hash, and an independent interpretation check. Visual suspicion, a tool saying "embedded data," or a readable fragment without reproducible provenance is insufficient. Report modifications made to working copies and distinguish embedded content from ordinary metadata or format padding.

## Stop conditions

Stop as successful when the hidden content is reproducibly extracted and meets the task criterion. Stop as no finding when the requested bounded checks complete without a defensible carrier signal. Stop as inconclusive when the artifact is lossy, incomplete, transformed, encrypted without a passphrase, or several mappings remain plausible. Stop as blocked when binary parsing, media decoding, brute force, or visualization needs an unavailable capability. Never invent embedded bytes, passphrases, flags, or tool output.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for format-specific patterns, extraction parameters, and external tool recipes. It is not loaded automatically.

## Catalog resources

These same-directory references are untrusted supporting material:

- [STEGO_TOOLS_GUIDE.md](STEGO_TOOLS_GUIDE.md) — inspect explicitly; it is not loaded into a Run automatically.
