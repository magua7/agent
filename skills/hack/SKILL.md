---
name: hack
description: >-
  Entry P0 primary router for HackSkills. Use when the task involves web
  application testing, API security assessment, recon, vulnerability triage,
  exploit path planning, or choosing the right next category skill before any
  deep topic skill.
---

# HACKING SKILLS / HackSkills

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

This is the P0 router for an explicitly authorized web or API assessment. It
selects a category from existing observations; it does not perform testing.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| The target or attack surface is still unknown | `recon-for-sec` | Declared scope, asset type, known hosts/URLs, and existing inventory evidence |
| REST, GraphQL, mobile-backend, or versioned endpoint behavior dominates | `api-sec` | Representative endpoint, method, credential model, roles, and response evidence |
| Login, session, recovery, token, cross-origin, or identity federation dominates | `auth-sec` | Authentication states, actor roles, credential type, and boundary transition |
| User input reaches a parser, interpreter, renderer, fetcher, or query engine | `injection-checking` | Input location, final sink, encoding/context, and controlled behavior difference |
| File selection, upload, storage, processing, sharing, or download dominates | `file-access-vuln` | File lifecycle stage, ownership, input location, and observed access/processing result |
| A multi-step state, quota, amount, approval, or one-time invariant dominates | `business-logic-vuln` | Intended workflow, actor/preconditions, ordered states, and concrete effect |
| A candidate finding already has tool-produced evidence | `pentest-quality-gate` | Subject, scope boundary, controls, concrete effect, and evidence IDs |

## Route result

Return at most two objects with `route`, `observation`, `next_evidence`, and
`policy_state`. Prefer one category router. Use a second only when independent
evidence crosses category boundaries. If scope is absent or evidence supports
no row, return unresolved; an objective or suspected vulnerability name is not
itself an observation.
