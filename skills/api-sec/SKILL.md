---
name: api-sec
description: >-
  Entry P1 category router for API security. Use when choosing between API
  recon, authorization, token abuse, and hidden-parameter workflows before any
  deeper API topic skill.
---

# API Security Router

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

Classify observed API behavior without proposing an action. Use only canonical
catalog names and return no more than two routes.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| OpenAPI, Swagger, versioned documentation, or an endpoint inventory is visible | `api-recon-and-docs` | Documentation location, observed versions, and one representative endpoint |
| Object IDs or tenant/account identifiers cross an authorization boundary | `api-authorization-and-bola` | Paired authorized and unauthorized request/response evidence with actor, object, and operation |
| Bearer tokens, JWT claims, signing metadata, or token-bound rate limits dominate | `api-auth-and-jwt-abuse` | Redacted token structure, issuer/audience context, and contrasting accepted/rejected responses |
| GraphQL operations, batching, schema fields, or undocumented parameters dominate | `graphql-and-hidden-parameters` | Operation shape, visible fields, and a response showing the relevant trust boundary |
| Login, session, OAuth, OIDC, or SSO behavior is the primary concern | `auth-sec` | Authentication states, roles, and the exact transition under review |
| A multi-step API workflow or business invariant is central | `business-logic-vuln` | State sequence, intended invariant, and before/after observations |

## Route result

For each selected route return `route`, `observation`, `next_evidence`, and
`policy_state`. Set `policy_state` to `policy-filtered` when the catalog blocks
the exact candidate. If no row is supported by existing evidence, return an
unresolved route and name the single most useful missing observation.
