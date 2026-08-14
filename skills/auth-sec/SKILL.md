---
name: auth-sec
description: >-
  Entry P1 category router for authentication and authorization. Use when
  testing login flows, sessions, object authorization, JWT, OAuth, CORS, CSRF,
  and enterprise SSO weaknesses before any deeper auth topic skill.
---

# Authentication and Authorization Router

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=router`, `risk=passive`, `default=enabled`. Trusted `policy.json` remains authoritative.

- Return routing decisions rather than payloads: list at most two canonical Skill names, the observation supporting each route, and the next evidence needed.
- Treat sibling Skill names as catalog hints only. Do not read sibling paths or claim that another Skill was loaded during this Run.
- Report an exact candidate as policy-filtered when it is disabled or lab-only; do not reproduce its high-risk procedure in the router.
- Leave the route unresolved when the available evidence does not distinguish the candidate branches.
<!-- zhiyugo:contract:end -->

Classify the observed identity boundary before selecting a specialist. Do not
infer an authentication failure from an error message or token shape alone.

## Observation → route → next evidence

| Observation already present | Canonical route | Next evidence needed |
|---|---|---|
| Login, registration, recovery, MFA, or session establishment behaves inconsistently | `authbypass-authentication-flaws` | Contrasting accepted/rejected state transitions and the account preconditions |
| One identity can address another user's, role's, or tenant's object/function | `idor-broken-object-authorization` | Actor, object, operation, intended owner, and paired authorization responses |
| JWT validation, claims, keys, issuer, audience, or token lifetime is central | `jwt-oauth-token-attacks` | Redacted header/claims, trust configuration evidence, and acceptance outcome |
| Redirect URI, state, nonce, PKCE, account binding, or federation flow is central | `oauth-oidc-misconfiguration` | Ordered protocol messages, registered client context, and resulting identity binding |
| A browser can trigger a sensitive authenticated action cross-site | `csrf-cross-site-request-forgery` | Sensitive state change, cookie context, origin, and anti-CSRF control behavior |
| A cross-origin response exposes credentialed sensitive data | `cors-cross-origin-misconfiguration` | Request Origin, response CORS headers, credential mode, and readable sensitive fields |
| A SAML assertion, signature, audience, recipient, or ACS boundary is central | `saml-sso-assertion-attacks` | Redacted assertion metadata, service-provider expectation, and validation result |
| The issue is primarily an API-wide identity model | `api-sec` | Endpoint, actor roles, credential type, and affected operation |

## Route result

Return at most two objects with `route`, `observation`, `next_evidence`, and
`policy_state`. Prefer the route that explains the violated boundary; use a
second only when the evidence genuinely spans two protocols. Otherwise return
an unresolved route with the missing identity-state comparison.
