---
name: business-logic-vuln
description: >-
  Entry P1 category router for business logic testing. Use when workflow abuse,
  race conditions, pricing flaws, or multi-step state attacks matter more than
  parser-level input injection.
---

# Business Logic Router

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

Route from an observed workflow invariant, not from a speculative impact.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| A sequence, prerequisite, amount, quota, approval, ownership, or one-time invariant appears violated | `business-logic-vulnerabilities` | Intended state machine, actor/preconditions, ordered before/after states, and concrete effect |
| Concurrent actions appear to bypass a one-time or check-then-act invariant | `race-condition` | Timestamped parallel outcomes, a sequential control, and the durable state difference |
| The violated invariant is object- or function-level authorization | `auth-sec` | Actor roles, object ownership, operation, and paired allow/deny evidence |
| The workflow is chiefly an API contract or hidden writable-field issue | `api-sec` | Endpoint, method, accepted fields, actor state, and response/state evidence |
| The invariant occurs in upload, storage, preview, sharing, or download stages | `file-access-vuln` | File lifecycle stage, ownership, resulting access, and observable state |

## Route result

Return at most two objects with `route`, `observation`, `next_evidence`, and
`policy_state`. Choose `business-logic-vulnerabilities` for the invariant and
only add a boundary router when it explains a distinct part of the evidence.
If the intended workflow is unknown, return unresolved rather than inventing it.
