---
name: recon-for-sec
description: >-
  Entry P1 category router for reconnaissance and methodology. Use when mapping
  scope, discovering assets, fingerprinting technology, building endpoint
  inventory, and choosing the first high-value security testing path.
---

# Recon and Methodology Router

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

Route an existing inventory or observation to the next bounded methodology.
Never treat an undeclared host, URL, repository, or package as in scope.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| Scope is known but the asset/service/endpoint inventory is incomplete | `recon-and-methodology` | Declared targets, current inventory, coverage gaps, and provenance of each observation |
| Explicit ports on a declared localhost target need bounded service inventory | `local-service-discovery` | Exact scoped host, explicit port set, and prior scan evidence if any |
| API documentation, endpoint versions, or machine-readable schemas are visible | `api-recon-and-docs` | Documentation URL/source, versions, and representative endpoint evidence |
| Exposed source-control metadata or repository artifacts are already observed | `insecure-source-code-management` | Exact in-scope location, response/file evidence, and whether sensitive content is present |
| Internal package names or registry-resolution evidence is present | `dependency-confusion` | Package name, ecosystem, trusted registry configuration, and resolution provenance |
| An endpoint inventory now clearly exposes API behavior | `api-sec` | Endpoint, method, credential model, roles, and one representative response |
| Login, session, token, or authorization boundaries are visible | `auth-sec` | Actor roles, authentication states, and the transition under review |

## Route result

Return at most two objects with `route`, `observation`, `next_evidence`, and
`policy_state`. Prefer an inventory route until evidence identifies a concrete
surface. Mark active or lab-only candidates as `policy-filtered`. If declared
scope is missing, return unresolved and request it as the next evidence.
