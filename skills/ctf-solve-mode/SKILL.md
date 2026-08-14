---
name: ctf-solve-mode
description: >-
  Orchestrate evidence-backed analysis of isolated CTF web, crypto, reverse,
  pwn, forensics, and misc challenges. Use when scoped inputs define a flag or
  other exact success marker and the solution must be reproducible.
---

# CTF Evidence-Gated Solve Mode

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=orchestrator`, `risk=lab_only`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Produce an evidence-gated stage graph for the Planner; do not claim to start a sub-agent, browser, MCP server, shell, or sibling Skill. Keep every stage inside an isolated lab or CTF environment.
- Give each stage an entry condition, one work product, a supported abstract capability or explicit capability gap, and an exit criterion.
- Use canonical Skill names only as route hints resolved before a Run.
- Stop planning when scope, required input, or a supported capability is missing.
<!-- zhiyugo:contract:end -->

## Required inputs

- An isolated challenge URL, authorized local artifact root, or exact artifact
  path.
- The expected flag pattern or another measurable success criterion.
- Any challenge statement, supplied parameters, known file format, and
  constraints.

Do not treat a challenge title as evidence of its category or solution.

## Evidence-gated stages

| Stage | Entry condition | Capability | Work product | Exit criterion |
|---|---|---|---|---|
| Success contract | Expected marker and scoped inputs are supplied | no action; validate task data | Exact success criteria and allowed subjects | Every criterion is observable and remains inside the challenge scope |
| Initial inventory | Scoped URL, host/ports, root/query, or path is supplied | `http.request`, `network.scan`, `file.search`, `code.search`, or `file.read` as appropriate | First tool-produced evidence and artifact inventory | The challenge surface is described only from observed data |
| Classification | Initial evidence exists | no new action; classify evidence | One primary category, optional secondary category, and route hints | Each classification cites a discriminating signal |
| Hypothesis | Category and relevant evidence exist | no new action; reason from evidence | A testable hypothesis, prerequisites, and one next supported action | The hypothesis predicts an observable result |
| Validation | A supported action can test the hypothesis | one supported capability | Fresh evidence that confirms, rejects, or leaves the hypothesis unresolved | Outcome is tied to the predicted marker |
| Criterion assessment | Validation evidence exists | no new action | One assessment per exact success criterion with evidence IDs | No criterion is satisfied by inference alone |
| Completion | Every criterion is assessed | no new action | Reproducible evidence summary, observed flag if present, and remaining gaps | A flag is returned only when it appears in cited evidence |

Use one primary capability per action-producing plan node. A failed action is
evidence of failure, not evidence that the challenge condition is absent.

## Classification and route hints

| Observed evidence | Route hint |
|---|---|
| RSA modulus, exponent, ciphertext, shared factors, or padding behavior | `rsa-attack-techniques` |
| Ciphertext statistics, encoding layers, or classical cipher structure | `classical-cipher-analysis` |
| Packet-capture format or parsed network conversations | `traffic-analysis-pcap` |
| Custom bytecode, opcode table, or virtual-machine dispatcher | `vm-and-bytecode-reverse` |
| Symbolic constraints or path-condition evidence | `symbolic-execution-tools` |
| Web file-read or include behavior | `web-ctf-lfi` |

Route hints must be resolved before a Run and remain planning labels only.

## Capability gaps

The current registry does not provide arbitrary program execution,
compilation, debugging, disassembly, symbolic execution, packet decoding,
archive extraction, cryptographic computation, interactive sessions,
state-changing HTTP methods, browser rendering, or payload automation. When a
hypothesis depends on one of these operations, record the exact missing
capability and leave the criterion unsatisfied.

## Result record

Return structured fields:

- `challenge_type`: classification supported by evidence;
- `evidence_summary`: evidence IDs and the facts each one proves;
- `route_hints`: canonical names and triggering observations;
- `hypothesis_results`: confirmed, rejected, or unresolved;
- `success_criteria`: satisfied boolean, reason, and evidence IDs for each;
- `flag`: exact observed value, or `null`;
- `capability_gaps`: operations required but unavailable.

Do not add risk ratings or remediation unless the task explicitly requests a
separate report.
