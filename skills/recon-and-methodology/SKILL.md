---
name: recon-and-methodology
description: >-
  Orchestrate bounded reconnaissance from explicit network targets, URLs, and
  authorized local artifacts. Use when a new authorized target needs an
  evidence-backed service, HTTP, or endpoint baseline before focused testing.
---

# Reconnaissance and Methodology

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=orchestrator`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Produce an evidence-gated stage graph for the Planner; do not claim to start a sub-agent, browser, MCP server, shell, or sibling Skill.
- Give each stage an entry condition, one work product, a supported abstract capability or explicit capability gap, and an exit criterion.
- Use canonical Skill names only as route hints resolved before a Run.
- Stop planning when scope, required input, or a supported capability is missing.
<!-- zhiyugo:contract:end -->

## Required inputs

- Explicit in-scope hosts, URLs, or local roots.
- Explicit TCP ports when service discovery is requested.
- Task constraints and a measurable success criterion.

An organization or domain name by itself is not a target inventory. Preserve
unknown coverage as a gap rather than expanding scope.

## Evidence-gated stages

| Stage | Entry condition | Capability | Work product | Exit criterion |
|---|---|---|---|---|
| Scope baseline | Exact targets and constraints are supplied | no action; validate task data | Normalized inventory of scoped hosts, URLs, roots, ports, and exclusions | Every planned action has an exact scoped subject |
| Service baseline | One scoped host and an explicit bounded port list exist | `network.scan` | Open-port observations, scan engine, resolved addresses, and evidence ID | All requested ports have a successful result or an explicit tool failure |
| HTTP baseline | One exact scoped URL exists | `http.request` | Bounded GET or HEAD response with status, non-sensitive headers, content preview, and evidence ID | The response is preserved; redirects are recorded but not followed |
| Local surface inventory | Authorized root and query are supplied | `file.search` or `code.search` | Paths and matches for routes, configuration, API prefixes, framework markers, or security boundaries | Every inventory item cites a real match |
| Artifact inspection | A relevant in-scope text file is identified | `file.read` | Bounded configuration, route, schema, or client artifact evidence | Interpretation stays within content actually read |
| Correlation | At least one preceding stage produced evidence | no new action; compare evidence | Target-to-service-to-endpoint map, confidence, and unresolved gaps | No inferred asset is represented as observed |
| Route decision | A concrete behavior or artifact signal is evidenced | no new action; classify evidence | At most two canonical route hints | Each hint names the evidence that triggered it |
| Completion | Success criteria can be assessed | no new action | Criterion assessment with evidence IDs and coverage limits | Untested areas and tool failures remain explicit |

## Route decisions

| Evidence | Route hint |
|---|---|
| REST, GraphQL, OpenAPI, or mobile API surface | `api-sec` |
| Login, session, token, role, or tenant boundary | `auth-sec` |
| Reflected input, parser behavior, query sink, or template evaluation | `injection-checking` |
| Upload, download, filename, include, or import behavior | `file-access-vuln` |
| Pricing, approval, quota, sequence, or state-machine behavior | `business-logic-vuln` |
| Exposed VCS or backup artifact | `insecure-source-code-management` |

Choose the narrowest evidence-supported hints. They are planning labels only,
not execution requests.

## Capability gaps

The current registry does not provide certificate-transparency or internet
search, DNS enumeration, subdomain brute force, virtual-host discovery,
directory brute force, crawling, JavaScript execution, technology scanners,
screenshots, authenticated browsing, or arbitrary command execution. Stop any
stage that requires one of these operations and record the exact gap.

## Completion record

Return:

- exact scoped subjects tested;
- service, HTTP, and local-artifact evidence IDs;
- a correlated inventory containing observed facts only;
- route hints with their triggering evidence;
- success-criterion assessments;
- failures, capability gaps, and untested coverage.
