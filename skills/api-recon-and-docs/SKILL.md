---
name: api-recon-and-docs
description: >-
  Orchestrate evidence-backed API surface discovery from scoped URLs, local
  client artifacts, schemas, and version clues. Use when an authorized API
  assessment needs a bounded endpoint inventory before topic-specific review.
---

# API Recon and Documentation

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=orchestrator`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Produce an evidence-gated stage graph for the Planner; do not claim to start a sub-agent, browser, MCP server, shell, or sibling Skill.
- Give each stage an entry condition, one work product, a supported abstract capability or explicit capability gap, and an exit criterion.
- Use canonical Skill names only as route hints resolved before a Run.
- Stop planning when scope, required input, or a supported capability is missing.
<!-- zhiyugo:contract:end -->

## Required inputs

- An exact in-scope API URL or an authorized local client/source root.
- The API style already observed, if known: REST, GraphQL, mobile backend, or
  documented schema.
- A success criterion that defines the required inventory or comparison.

Do not infer additional hosts, credentials, versions, or endpoints from the
objective alone.

## Evidence-gated stages

| Stage | Entry condition | Capability | Work product | Exit criterion |
|---|---|---|---|---|
| Baseline | Exact scoped URL is supplied | `http.request` | One bounded GET or HEAD response with status, headers, body preview, and evidence ID | The real response is preserved, including redirects as observations rather than followed navigation |
| Artifact inventory | Authorized local root and search term are supplied | `file.search` or `code.search` | Matches for API prefixes, schema names, route declarations, or version strings | Every reported path and match is traceable to evidence |
| Schema review | An OpenAPI, Swagger, GraphQL, or client schema file is identified in scope | `file.read` | Bounded schema evidence listing declared paths, methods, parameters, and versions | Inventory contains only fields actually present in the artifact |
| Surface comparison | At least two evidenced schemas, versions, or responses exist | no new action; compare existing evidence | Added, removed, deprecated, or role-sensitive surface differences | Each difference cites both sides of the comparison |
| Route decision | One or more concrete API signals are evidenced | no new action; classify existing evidence | At most two canonical route hints with reasons | Each hint is tied to an observed signal |
| Completion | The task success criterion can be assessed | no new action | Criterion-by-criterion result with evidence IDs and unresolved gaps | No unsupported enumeration is presented as completed |

## Route decisions

Use route names only as pre-Run hints:

| Evidence | Route hint |
|---|---|
| Object identifiers or cross-user/tenant boundaries | `api-authorization-and-bola` |
| JWT, bearer-token, API-key, or request-identity trust | `api-auth-and-jwt-abuse` |
| GraphQL schema, batching, or undocumented fields | `graphql-and-hidden-parameters` |
| Login, session, OAuth, OIDC, or SSO boundaries | `auth-sec` |
| A specific injection sink | `injection-checking` |

If the evidence fits several rows, retain the two narrowest hints. A route hint
does not mean that another Skill is available in the current Run.

## Capability gaps

The current registry does not provide passive internet search, DNS or
subdomain enumeration, directory brute force, JavaScript execution, browser
state, authenticated session automation, crawling, fuzzing, POST requests, or
GraphQL introspection. Record the exact missing operation and stop that branch;
do not replace it with an unevidenced result.

## Completion record

Return:

- evidenced API entry points and versions;
- schema or client-artifact evidence IDs;
- observed differences and route hints;
- every success criterion marked satisfied or unsatisfied;
- explicit capability gaps and untested surface.
