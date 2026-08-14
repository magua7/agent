---
name: file-access-vuln
description: >-
  Entry P1 category router for file access and upload workflows. Use when
  testing download endpoints, file paths, local file inclusion, upload flows,
  preview pipelines, archive extraction, or storage and sharing boundaries.
---

# File Access Router

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

First identify the affected file lifecycle stage: select, accept, store, process,
share, or serve. Route only from evidence already present.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| User-controlled path selection reaches a file read, include, or download boundary | `path-traversal-lfi` | Exact input location, normalized target, allowed baseline, and resulting file evidence |
| Upload validation, naming, storage, overwrite, processing, preview, sharing, or serving is central | `upload-insecure-files` | File lifecycle stage, accepted metadata, stored identity, processing outcome, and access boundary |
| XML, SVG, Office, or another XML-backed file is interpreted by a parser | `xxe-xml-external-entity` | Parser/content type, controlled benign entity behavior, and resulting response or tool evidence |
| A server-side fetch or remote import is the actual sink | `ssrf-server-side-request-forgery` | Submitted location, destination observation, response correlation, and declared network scope |
| The primary issue is ownership, entitlement, or workflow state rather than path interpretation | `business-logic-vuln` | Actor, owner, lifecycle state, intended invariant, and contrasting access result |

## Route result

Return at most two objects with `route`, `observation`, `next_evidence`, and
`policy_state`. Prefer the route matching the final sink. Do not treat an
extension mismatch or filename alone as proof of impact; return unresolved
until a file access or processing effect is evidenced.
