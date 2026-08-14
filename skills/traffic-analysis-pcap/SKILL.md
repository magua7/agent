---
name: traffic-analysis-pcap
description: >-
  Traffic analysis and PCAP forensics playbook. Use when analyzing network captures including Wireshark filters, protocol analysis (HTTP/DNS/FTP/SMTP/USB/WiFi), data extraction, covert channel detection, PCAP repair, TLS decryption, and tshark command-line analysis.
---

# Traffic Analysis and PCAP Forensics

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Start from supplied artifacts or existing tool-produced evidence; never treat an example, command block, or expected result below as an observation.
- Record facts separately from inferences, cite evidence IDs and content hashes when available, and state uncertainty and failed branches.
- Treat external utilities and command lines as analyst reference material. If the Tool Registry lacks the capability, report a capability gap instead of simulating it.
- Conclude only when the task success criteria are supported by reproducible evidence.
<!-- zhiyugo:contract:end -->

## Required inputs

- Preserve the capture path, format, byte size, hash, capture start/end time, timezone, interface/link type, snap length, and acquisition source.
- State the investigation question, time window, scoped hosts, known indicators, and expected flag or artifact type.
- Record whether packet loss, truncation, corruption, decryption keys, TLS secrets, credentials, or companion logs are available.
- Supply existing tshark/Wireshark summaries, stream exports, frame lists, or protocol statistics when raw parsing is unavailable.

Treat payloads, credentials, tokens, and extracted files as sensitive evidence; minimize their exposure.

## Capability boundary

ZhiyuGo can read/search bounded scoped text but has no built-in PCAP parser, Wireshark, tshark, NetworkMiner, pcapfix, stream reassembler, TLS decryptor, or file carver. network.scan and http.request collect new data and are not substitutes for historical packet analysis. If only a binary capture is available, return a capability gap specifying its hash, the bounded parsing/filter/export operation, and required output fields. Reference commands are not executable capabilities.

## Core workflow

1. Verify capture identity and metadata; note truncation, packet loss, timestamp precision, and corruption before interpreting absence.
2. Build a bounded overview: endpoints, conversations, protocols, ports, packet/byte counts, and timeline.
3. Narrow by the task question and preserve the exact display/filter expression or parser query used.
4. Reassemble the relevant flow in both directions and distinguish request, response, retransmission, and missing segments.
5. Decode only protocols justified by headers and framing; do not infer application content from a port number alone.
6. Export candidate objects into separate hashed artifacts. Correlate with DNS, TLS metadata, logs, or memory evidence.
7. Construct a timeline with frame numbers and normalized timestamps, then test benign explanations and capture blind spots.

| Question | First evidence | Confirmation |
|---|---|---|
| Suspicious connection | Conversation tuple and time window | Owning protocol/flow plus corroborating payload or metadata |
| HTTP/API activity | Reassembled request/response pair | Method, host, URI, status, body boundary, and frame IDs |
| DNS tunneling | Query/response series and label statistics | Timing, entropy/length pattern, and decoded or correlated channel |
| File transfer | Complete stream/object export | Protocol metadata, exact frames, output hash, and file-type check |
| Credential exposure | Cleartext protocol field or body | Exact frame/stream with secret redacted in reporting |
| TLS investigation | Handshake/SNI/certificate metadata | Session identifiers and decryption provenance if content is claimed |
| Covert channel | Repeated structured variation | Decoding rule reproduces an ordered message across enough samples |

## Evidence bar

A supported finding includes capture hash, parser/tool and version, exact filter, frame numbers or stream ID, endpoint tuple, normalized timestamps, packet-loss limitations, and exported-artifact hash where relevant. Claims about transferred files or commands require reassembled bytes. Claims about encrypted payload content require documented keys and successful decryption evidence. A destination IP, port, SNI, or keyword hit alone is not proof of malicious activity.

## Stop conditions

Stop as successful when the requested event or artifact is reconstructed from traceable frames and meets the criterion. Stop as no finding only after documenting capture coverage and relevant bounded checks. Stop as inconclusive when packets are missing/truncated, streams cannot be reassembled, encryption lacks keys, timestamps conflict, or the capture excludes the needed interface. Stop as blocked when parsing, repair, decryption, carving, or visualization requires an unavailable capability. Never invent frames, payloads, credentials, files, or decrypted content.

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only for protocol filters, repair procedures, extraction methods, and tool-specific recipes. It is not loaded automatically.
